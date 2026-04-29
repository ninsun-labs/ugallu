// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package confidentialattestation

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

// RunReconciler reconciles ConfidentialAttestationRun CRs.
type RunReconciler struct {
	Client          client.Client
	Scheme          *runtime.Scheme
	Emitter         *emitterv1alpha1.Emitter
	ClusterIdentity securityv1alpha1.ClusterIdentity

	NodeName     string
	TPMDevice    string
	SEVSNPDevice string
	TDXDevice    string
}

// SetupWithManager wires the reconciler.
func (r *RunReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ConfidentialAttestationRun{}).
		Named("confidential-attestation-run").
		Complete(r)
}

// Reconcile drives the lifecycle.
func (r *RunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var run securityv1alpha1.ConfidentialAttestationRun
	if err := r.Client.Get(ctx, req.NamespacedName, &run); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	// Each attester DaemonSet pod only handles runs targeting its
	// node — the cluster-scope cycle is N runs in parallel, one per
	// node. Skip silently otherwise.
	if run.Spec.TargetNodeName != "" && run.Spec.TargetNodeName != r.NodeName {
		return ctrl.Result{}, nil
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
		r.emitSE(ctx, &run, securityv1alpha1.TypeAttestationStarted, securityv1alpha1.SeverityInfo)
		return r.execute(ctx, &run)
	}
}

func (r *RunReconciler) execute(ctx context.Context, run *securityv1alpha1.ConfidentialAttestationRun) (ctrl.Result, error) {
	att, err := AttesterFor(&run.Spec, r.TPMDevice, r.SEVSNPDevice, r.TDXDevice)
	if err != nil {
		return r.fail(ctx, run, err.Error())
	}
	outcome, err := att.Attest(&run.Spec)
	if err != nil {
		return r.fail(ctx, run, err.Error())
	}

	result := &securityv1alpha1.ConfidentialAttestationResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      run.Name + "-result",
			Namespace: run.Namespace,
		},
		Spec: securityv1alpha1.ConfidentialAttestationResultSpec{
			DerivedFromRun: securityv1alpha1.LocalProfileRef{Name: run.Name},
			Backend:        run.Spec.Backend,
			NodeName:       r.NodeName,
			Nonce:          run.Spec.Nonce,
			Quote:          outcome.Quote,
			Signature:      outcome.Signature,
			Measurements:   outcome.Measurements,
			Verdict:        outcome.Verdict,
			VerifierNotes:  outcome.VerifierNotes,
		},
	}
	result.Status.Trusted = outcome.Verdict == securityv1alpha1.ConfidentialAttestationVerdictVerified
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

	switch outcome.Verdict {
	case securityv1alpha1.ConfidentialAttestationVerdictVerified:
		r.emitSE(ctx, run, securityv1alpha1.TypeAttestationVerified, securityv1alpha1.SeverityInfo)
	case securityv1alpha1.ConfidentialAttestationVerdictFailed:
		r.emitSE(ctx, run, securityv1alpha1.TypeAttestationFailed, securityv1alpha1.SeverityCritical)
	default:
		// Indeterminate verdicts emit AttestationVerified with
		// info severity — the result carries the missing-device or
		// no-policy notes for human review.
		r.emitSE(ctx, run, securityv1alpha1.TypeAttestationVerified, securityv1alpha1.SeverityInfo)
	}
	return ctrl.Result{}, nil
}

func (r *RunReconciler) fail(ctx context.Context, run *securityv1alpha1.ConfidentialAttestationRun, reason string) (ctrl.Result, error) {
	now := metav1.Now()
	run.Status.Phase = "Failed"
	run.Status.CompletionTime = &now
	run.Status.Conditions = upsertCondition(run.Status.Conditions, &metav1.Condition{
		Type:               "Failed",
		Status:             metav1.ConditionTrue,
		Reason:             "AttestationFailed",
		Message:            reason,
		LastTransitionTime: now,
	})
	if err := r.Client.Status().Update(ctx, run); err != nil {
		return ctrl.Result{}, err
	}
	r.emitSE(ctx, run, securityv1alpha1.TypeAttestationFailed, securityv1alpha1.SeverityCritical)
	return ctrl.Result{}, nil
}

func (r *RunReconciler) emitSE(ctx context.Context, run *securityv1alpha1.ConfidentialAttestationRun, seType string, severity securityv1alpha1.Severity) {
	signals := map[string]string{
		"run.namespace":    run.Namespace,
		"run.name":         run.Name,
		"node.name":        r.NodeName,
		"backend":          string(run.Spec.Backend),
		"nonce.shaPresent": fmt.Sprintf("%t", run.Spec.Nonce != ""),
	}
	class := securityv1alpha1.ClassCompliance
	if seType == securityv1alpha1.TypeAttestationFailed {
		class = securityv1alpha1.ClassDetection
	}
	_, _ = r.Emitter.Emit(ctx, &emitterv1alpha1.EmitOpts{
		Class:            class,
		Type:             seType,
		Severity:         severity,
		SubjectKind:      securityv1alpha1.SubjectKind("Node"),
		SubjectName:      r.NodeName,
		SubjectNamespace: run.Namespace,
		Signals:          signals,
		ClusterIdentity:  r.ClusterIdentity,
	})
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
