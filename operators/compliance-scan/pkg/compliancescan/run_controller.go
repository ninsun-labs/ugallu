// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package compliancescan

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

// RunReconciler reconciles ComplianceScanRun CRs.
type RunReconciler struct {
	Client          client.Client
	Scheme          *runtime.Scheme
	Emitter         *emitterv1alpha1.Emitter
	ClusterIdentity securityv1alpha1.ClusterIdentity
}

// SetupWithManager wires the reconciler.
func (r *RunReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ComplianceScanRun{}).
		Named("compliance-scan-run").
		Complete(r)
}

// Reconcile drives the scan lifecycle.
func (r *RunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var run securityv1alpha1.ComplianceScanRun
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
		return r.execute(ctx, &run)
	default:
		now := metav1.Now()
		run.Status.Phase = "Running"
		run.Status.StartTime = &now
		if err := r.Client.Status().Update(ctx, &run); err != nil {
			return ctrl.Result{}, err
		}
		r.emitSE(ctx, &run, securityv1alpha1.TypeComplianceScanStarted, securityv1alpha1.SeverityInfo, nil)
		return r.execute(ctx, &run)
	}
}

// execute dispatches to the backend scanner and writes the result.
func (r *RunReconciler) execute(ctx context.Context, run *securityv1alpha1.ComplianceScanRun) (ctrl.Result, error) {
	scanner, err := ScannerFor(&run.Spec)
	if err != nil {
		return r.fail(ctx, run, err.Error())
	}
	outcome, err := scanner.Scan(ctx, r.Client, &run.Spec)
	if err != nil {
		return r.fail(ctx, run, err.Error())
	}

	checks := decorateWithMappings(outcome.Checks, run.Spec.ControlMappings)
	worst := worstSeverity(checks)

	result := &securityv1alpha1.ComplianceScanResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      run.Name + "-result",
			Namespace: run.Namespace,
		},
		Spec: securityv1alpha1.ComplianceScanResultSpec{
			DerivedFromRun: securityv1alpha1.LocalProfileRef{Name: run.Name},
			Backend:        run.Spec.Backend,
			Profile:        run.Spec.Profile,
			Checks:         checks,
			Summary:        outcome.Summary,
		},
	}
	result.Status.WorstSeverity = worst
	if err := r.Client.Create(ctx, result); err != nil && !apierrors.IsAlreadyExists(err) {
		return r.fail(ctx, run, fmt.Sprintf("create result: %v", err))
	}

	now := metav1.Now()
	run.Status.Phase = "Succeeded"
	run.Status.CompletionTime = &now
	run.Status.ResultRef = &securityv1alpha1.LocalProfileRef{Name: result.Name}
	if err := r.Client.Status().Update(ctx, run); err != nil {
		return ctrl.Result{}, err
	}

	severity := worst
	if severity == "" {
		severity = securityv1alpha1.SeverityInfo
	}
	r.emitSE(ctx, run, securityv1alpha1.TypeComplianceScanCompleted, severity, checks)
	return ctrl.Result{}, nil
}

func (r *RunReconciler) fail(ctx context.Context, run *securityv1alpha1.ComplianceScanRun, reason string) (ctrl.Result, error) {
	now := metav1.Now()
	run.Status.Phase = "Failed"
	run.Status.CompletionTime = &now
	run.Status.Conditions = upsertCondition(run.Status.Conditions, &metav1.Condition{
		Type:               "Failed",
		Status:             metav1.ConditionTrue,
		Reason:             "ScanFailed",
		Message:            reason,
		LastTransitionTime: now,
	})
	if err := r.Client.Status().Update(ctx, run); err != nil {
		return ctrl.Result{}, err
	}
	r.emitSE(ctx, run, securityv1alpha1.TypeComplianceScanFailed, securityv1alpha1.SeverityHigh, []securityv1alpha1.ComplianceCheckResult{{
		CheckID:  "scan-failed",
		Title:    "Scan failed",
		Outcome:  "fail",
		Severity: securityv1alpha1.SeverityHigh,
		Detail:   reason,
	}})
	return ctrl.Result{}, nil
}

// emitSE wraps the SDK emitter.
func (r *RunReconciler) emitSE(ctx context.Context, run *securityv1alpha1.ComplianceScanRun, seType string, severity securityv1alpha1.Severity, checks []securityv1alpha1.ComplianceCheckResult) {
	signals := map[string]string{
		"run.namespace": run.Namespace,
		"run.name":      run.Name,
		"scan.backend":  string(run.Spec.Backend),
		"scan.profile":  run.Spec.Profile,
	}
	if len(checks) > 0 {
		signals["checks.count"] = fmt.Sprintf("%d", len(checks))
		fail := 0
		for i := range checks {
			if checks[i].Outcome == "fail" {
				fail++
			}
		}
		signals["checks.fail"] = fmt.Sprintf("%d", fail)
	}
	class := securityv1alpha1.ClassCompliance
	if seType == securityv1alpha1.TypeComplianceScanFailed {
		class = securityv1alpha1.ClassAnomaly
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

// decorateWithMappings stamps each check with the matching framework
// controls from the run's ControlMappings.
func decorateWithMappings(checks []securityv1alpha1.ComplianceCheckResult, mappings []securityv1alpha1.ControlMapping) []securityv1alpha1.ComplianceCheckResult {
	if len(mappings) == 0 {
		return checks
	}
	idx := map[string][]securityv1alpha1.FrameworkControl{}
	for i := range mappings {
		idx[mappings[i].CheckID] = mappings[i].Frameworks
	}
	out := make([]securityv1alpha1.ComplianceCheckResult, len(checks))
	for i := range checks {
		out[i] = checks[i]
		if frames, ok := idx[checks[i].CheckID]; ok {
			out[i].Frameworks = frames
		}
	}
	return out
}

func worstSeverity(checks []securityv1alpha1.ComplianceCheckResult) securityv1alpha1.Severity {
	rank := map[securityv1alpha1.Severity]int{
		securityv1alpha1.SeverityCritical: 4,
		securityv1alpha1.SeverityHigh:     3,
		securityv1alpha1.SeverityMedium:   2,
		securityv1alpha1.SeverityLow:      1,
		securityv1alpha1.SeverityInfo:     0,
	}
	var worst securityv1alpha1.Severity
	worstRank := -1
	for i := range checks {
		if r := rank[checks[i].Severity]; r > worstRank {
			worstRank = r
			worst = checks[i].Severity
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
