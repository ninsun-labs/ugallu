// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package backupverify

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// RunReconciler reconciles BackupVerifyRun CRs.
type RunReconciler struct {
	Client          client.Client
	Scheme          *runtime.Scheme
	Emitter         *emitterv1alpha1.Emitter
	ClusterIdentity securityv1alpha1.ClusterIdentity
	EtcdSnapshotDir string
}

// SetupWithManager wires the reconciler.
func (r *RunReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.BackupVerifyRun{}).
		Named("backup-verify-run").
		Complete(r)
}

// Reconcile drives the run lifecycle.
func (r *RunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var run securityv1alpha1.BackupVerifyRun
	if err := r.Client.Get(ctx, req.NamespacedName, &run); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	switch run.Status.Phase {
	case "Succeeded", "Failed":
		return ctrl.Result{}, nil
	case "Running":
		// Reconciler runs the verifier inline — Phase=Running means
		// a previous reconcile crashed mid-flight; restart from
		// scratch. The verifier is idempotent against the same
		// BackupRef.
		return r.execute(ctx, &run)
	default:
		// First touch.
		now := metav1.Now()
		run.Status.Phase = "Running"
		run.Status.StartTime = &now
		if err := r.Client.Status().Update(ctx, &run); err != nil {
			return ctrl.Result{}, err
		}
		r.emitSE(ctx, &run, securityv1alpha1.TypeBackupVerifyStarted, securityv1alpha1.SeverityInfo, nil)
		return r.execute(ctx, &run)
	}
}

// execute runs the backend verifier and writes the result.
func (r *RunReconciler) execute(ctx context.Context, run *securityv1alpha1.BackupVerifyRun) (ctrl.Result, error) {
	verifier, err := VerifierFor(&run.Spec, r.EtcdSnapshotDir)
	if err != nil {
		return r.fail(ctx, run, err.Error())
	}
	outcome, err := verifier.Verify(&run.Spec)
	if err != nil {
		return r.fail(ctx, run, err.Error())
	}

	result := &securityv1alpha1.BackupVerifyResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      run.Name + "-result",
			Namespace: run.Namespace,
		},
		Spec: securityv1alpha1.BackupVerifyResultSpec{
			DerivedFromRun:      securityv1alpha1.LocalProfileRef{Name: run.Name},
			Backend:             run.Spec.Backend,
			Mode:                run.Spec.Mode,
			Checksum:            outcome.Checksum,
			RestoredObjectCount: outcome.RestoredObjectCount,
			Findings:            outcome.Findings,
		},
	}
	worst := worstSeverity(outcome.Findings)
	result.Status.WorstSeverity = worst
	if err := r.Client.Create(ctx, result); err != nil && !apierrors.IsAlreadyExists(err) {
		return r.fail(ctx, run, fmt.Sprintf("create result: %v", err))
	}

	// If any finding has a "high" or "critical" severity, surface a
	// BackupVerifyMismatch (Detection). Otherwise just close the run
	// with BackupVerifyCompleted (Compliance).
	now := metav1.Now()
	run.Status.Phase = "Succeeded"
	run.Status.CompletionTime = &now
	run.Status.ResultRef = &securityv1alpha1.LocalProfileRef{Name: result.Name}
	if err := r.Client.Status().Update(ctx, run); err != nil {
		return ctrl.Result{}, err
	}

	if worst == securityv1alpha1.SeverityHigh || worst == securityv1alpha1.SeverityCritical {
		r.emitSE(ctx, run, securityv1alpha1.TypeBackupVerifyMismatch, worst, outcome.Findings)
	} else {
		r.emitSE(ctx, run, securityv1alpha1.TypeBackupVerifyCompleted, securityv1alpha1.SeverityInfo, outcome.Findings)
	}
	return ctrl.Result{}, nil
}

func (r *RunReconciler) fail(ctx context.Context, run *securityv1alpha1.BackupVerifyRun, reason string) (ctrl.Result, error) {
	now := metav1.Now()
	run.Status.Phase = "Failed"
	run.Status.CompletionTime = &now
	run.Status.Conditions = upsertCondition(run.Status.Conditions, &metav1.Condition{
		Type:               "Failed",
		Status:             metav1.ConditionTrue,
		Reason:             "VerifyFailed",
		Message:            reason,
		LastTransitionTime: now,
	})
	if err := r.Client.Status().Update(ctx, run); err != nil {
		return ctrl.Result{}, err
	}
	r.emitSE(ctx, run, securityv1alpha1.TypeBackupVerifyFailed, securityv1alpha1.SeverityHigh, []securityv1alpha1.BackupVerifyFinding{{
		Code: "verify-failed", Severity: securityv1alpha1.SeverityHigh, Detail: reason,
	}})
	return ctrl.Result{}, nil
}

// emitSE wraps the SDK emitter.
func (r *RunReconciler) emitSE(ctx context.Context, run *securityv1alpha1.BackupVerifyRun, seType string, severity securityv1alpha1.Severity, findings []securityv1alpha1.BackupVerifyFinding) {
	signals := map[string]string{
		"run.namespace":  run.Namespace,
		"run.name":       run.Name,
		"backup.backend": string(run.Spec.Backend),
		"backup.mode":    string(run.Spec.Mode),
		"backup.refName": run.Spec.BackupRef.Name,
	}
	if run.Spec.BackupRef.Namespace != "" {
		signals["backup.refNamespace"] = run.Spec.BackupRef.Namespace
	}
	if len(findings) > 0 {
		signals["findings.count"] = fmt.Sprintf("%d", len(findings))
		signals["findings.first.code"] = findings[0].Code
	}
	var class securityv1alpha1.Class
	switch seType {
	case securityv1alpha1.TypeBackupVerifyMismatch:
		class = securityv1alpha1.ClassDetection
	case securityv1alpha1.TypeBackupVerifyFailed:
		class = securityv1alpha1.ClassAnomaly
	default:
		class = securityv1alpha1.ClassCompliance
	}
	_, _ = r.Emitter.Emit(ctx, &emitterv1alpha1.EmitOpts{
		Class:            class,
		Type:             seType,
		Severity:         severity,
		SubjectKind:      securityv1alpha1.SubjectKind("Cluster"),
		SubjectName:      "cluster",
		SubjectNamespace: run.Namespace,
		Signals:          signals,
		ClusterIdentity:  r.ClusterIdentity,
	})
}

// worstSeverity returns the highest severity in findings (or "" if
// none). Order: critical > high > medium > low > info.
func worstSeverity(findings []securityv1alpha1.BackupVerifyFinding) securityv1alpha1.Severity {
	rank := map[securityv1alpha1.Severity]int{
		securityv1alpha1.SeverityCritical: 4,
		securityv1alpha1.SeverityHigh:     3,
		securityv1alpha1.SeverityMedium:   2,
		securityv1alpha1.SeverityLow:      1,
		securityv1alpha1.SeverityInfo:     0,
	}
	var worst securityv1alpha1.Severity
	worstRank := -1
	for i := range findings {
		if r := rank[findings[i].Severity]; r > worstRank {
			worstRank = r
			worst = findings[i].Severity
		}
	}
	return worst
}

func upsertCondition(conds []metav1.Condition, c *metav1.Condition) []metav1.Condition {
	for i := range conds {
		if conds[i].Type == c.Type {
			conds[i] = *c
			return conds
		}
	}
	return append(conds, *c)
}
