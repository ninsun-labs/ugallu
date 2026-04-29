// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"context"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// IncidentAcknowledgedAnnotation marks a Forensic SE as ready for
// unfreeze. Admission policy 4 (ack-restricted) gates writes to this
// annotation by SA.
const IncidentAcknowledgedAnnotation = "ugallu.io/incident-acknowledged"

// SecurityEventReconciler watches SecurityEvents and starts the
// forensics capture pipeline when the trigger predicate matches.
type SecurityEventReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Pipeline *Pipeline
}

// Reconcile is called by controller-runtime on every SE create /
// update. The reconciler is the predicate gate: it loads the
// active ForensicsConfig, evaluates the trigger, and either starts
// the pipeline or records a skip metric.
func (r *SecurityEventReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rlog := log.FromContext(ctx).WithName("forensics-se").WithValues("name", req.Name)

	se := &securityv1alpha1.SecurityEvent{}
	if err := r.Get(ctx, req.NamespacedName, se); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	cfg := &securityv1alpha1.ForensicsConfig{}
	if err := r.Get(ctx, client.ObjectKey{Name: DefaultForensicsConfigName}, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			pipelineSkippedTotal.WithLabelValues("no_config").Inc()
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	reason := evalPredicate(se, &cfg.Spec.Trigger, cfg.Spec.WhitelistedTypes)
	if reason != "" {
		pipelineSkippedTotal.WithLabelValues(reason).Inc()
		return ctrl.Result{}, nil
	}

	incident := NewIncident(se)
	if incident == nil {
		pipelineSkippedTotal.WithLabelValues("non_pod_subject").Inc()
		return ctrl.Result{}, nil
	}

	if err := r.Pipeline.Start(ctx, incident); err != nil {
		// "max concurrent" / "already in flight" are transient — back
		// off and retry.
		pipelineQueueSize.Inc()
		rlog.Info("pipeline busy, requeueing", "err", err)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	return ctrl.Result{}, nil
}

// SetupWithManager wires the reconciler.
func (r *SecurityEventReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("forensics-se").
		For(&securityv1alpha1.SecurityEvent{}).
		Complete(r)
}

// evalPredicate returns "" when the SE matches the trigger, or a
// short skip-reason string for the metric label otherwise.
func evalPredicate(se *securityv1alpha1.SecurityEvent, t *securityv1alpha1.ForensicsTrigger, whitelist []string) string {
	if !matchClass(se.Spec.Class, t.Classes) {
		return "class_mismatch"
	}
	if !matchSeverity(se.Spec.Severity, t.MinSeverities) {
		return "severity_below_min"
	}
	if !matchType(se.Spec.Type, whitelist) {
		return "type_not_whitelisted"
	}
	if t.RequireAttested && se.Status.Phase != securityv1alpha1.SecurityEventPhaseAttested {
		return "not_attested"
	}
	if !matchNamespace(se.Spec.Subject.Namespace, t.NamespaceAllowlist) {
		return "namespace_filtered"
	}
	if se.Spec.Subject.Kind != "Pod" {
		return "non_pod_subject"
	}
	return ""
}

// matchClass returns true when allowed contains class. Empty
// allowed = match-all (the CRD default fills in
// {Detection, Anomaly} via kubebuilder, but defense-in-depth).
func matchClass(class securityv1alpha1.Class, allowed []securityv1alpha1.Class) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, c := range allowed {
		if c == class {
			return true
		}
	}
	return false
}

// matchSeverity returns true when sev meets the minimum from the
// allowed list. The allowed list itself is the discrete set of
// severities, not a numeric threshold — set membership is enough.
func matchSeverity(sev securityv1alpha1.Severity, allowed []securityv1alpha1.Severity) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, s := range allowed {
		if s == sev {
			return true
		}
	}
	return false
}

// matchType returns true when t is in the whitelist. Empty
// whitelist = nothing matches (explicit opt-in default).
func matchType(t string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return false
	}
	for _, w := range whitelist {
		if w == t {
			return true
		}
	}
	return false
}

// matchNamespace returns true when ns is in the allowlist. Empty
// allowlist = match-all namespaces.
func matchNamespace(ns string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == ns {
			return true
		}
	}
	return false
}

// UnfreezeReconciler watches Forensic SE annotations and reverses
// the freeze when an authorized SA stamps
// `ugallu.io/incident-acknowledged=true`. Admission policy 4
// already gates the annotation write by SA; this reconciler only
// reacts to legitimate acknowledgements.
type UnfreezeReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Freezer    *Freezer
	StepRunner *StepRunner
}

// Reconcile reverses the freeze state for the SE's subject Pod and
// records the resolution as a follow-up SE{Type=PodUnfrozen}. The
// reconciler is idempotent: re-applying the unfreeze on an
// already-unfrozen Pod is a no-op.
//
// Two unfreeze paths converge here:
//  1. Manual: an authorized SA stamps
//     `ugallu.io/incident-acknowledged=true` on the SE.
//  2. Auto-unfreeze: when ForensicsConfig.spec.cleanup.
//     autoUnfreezeAfter > 0, the reconciler treats
//     `creationTimestamp + autoUnfreezeAfter` as an implicit
//     acknowledgement deadline. Past the deadline (and absent a
//     manual ack) the unfreeze fires with
//     `signals.reason=auto-unfreeze-grace-elapsed`.
func (r *UnfreezeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rlog := log.FromContext(ctx).WithName("forensics-unfreeze").WithValues("name", req.Name)
	se := &securityv1alpha1.SecurityEvent{}
	if err := r.Get(ctx, req.NamespacedName, se); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if se.Spec.Class != "Forensic" {
		return ctrl.Result{}, nil
	}
	switch se.Spec.Type {
	case securityv1alpha1.TypeIncidentCaptureCompleted, securityv1alpha1.TypeIncidentCaptureFailed:
	default:
		return ctrl.Result{}, nil
	}
	if strings.EqualFold(se.Annotations[unfreezeAppliedAnnotation], "true") {
		// already processed
		return ctrl.Result{}, nil
	}

	autoUnfreezeReason := ""
	manualAck := strings.EqualFold(se.Annotations[IncidentAcknowledgedAnnotation], "true")
	// On IncidentCaptureFailed, an annotation overrides the
	// auto-unfreeze policy. Without override (default = "auto"),
	// the same grace window as a Completed SE applies — a stranded
	// pod is worse than a slightly-early unfreeze. With
	// "manual" the operator waits for an admin ack (e.g.
	// credentials/configuration failures need human triage before
	// releasing the suspect pod).
	failurePolicy := se.Annotations[FailureUnfreezePolicyAnnotation]
	if se.Spec.Type == securityv1alpha1.TypeIncidentCaptureFailed && strings.EqualFold(failurePolicy, "manual") && !manualAck {
		// Stays frozen until ack.
		return ctrl.Result{}, nil
	}
	if !manualAck {
		// No manual ack — check whether auto-unfreeze is configured
		// and whether the grace window has elapsed.
		grace, requeueAfter, err := r.autoUnfreezeStatus(ctx, se)
		if err != nil {
			return ctrl.Result{}, err
		}
		if grace == 0 {
			// Auto-unfreeze disabled: wait for the manual ack.
			return ctrl.Result{}, nil
		}
		if requeueAfter > 0 {
			// Grace window not yet elapsed; come back later.
			return ctrl.Result{RequeueAfter: requeueAfter}, nil
		}
		autoUnfreezeReason = "auto-unfreeze-grace-elapsed"
		if se.Spec.Type == securityv1alpha1.TypeIncidentCaptureFailed {
			autoUnfreezeReason = "auto-unfreeze-after-capture-failed"
		}
	}

	if se.Spec.Subject.Name == "" || se.Spec.Subject.Namespace == "" {
		return ctrl.Result{}, nil
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      se.Spec.Subject.Name,
			Namespace: se.Spec.Subject.Namespace,
			UID:       se.Spec.Subject.UID,
		},
	}
	// Reconstruct enough Incident state to feed the step runner.
	// The completion SE picked up here carries `incident.uid` in
	// its signals so re-running the unfreeze on the same incident
	// converges on the deterministic ER name.
	incidentUID := se.Spec.Signals["incident.uid"]
	if incidentUID == "" {
		// Fallback: synthesize from the SE UID so the ER name
		// stays deterministic per acknowledged SE.
		incidentUID = string(se.UID)
	}
	exec := &StepExecution{
		Incident: &Incident{
			UID:           incidentUID,
			TriggerSE:     se,
			SuspectPod:    types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name},
			SuspectPodUID: string(pod.UID),
		},
		Pod: pod,
	}
	if r.StepRunner == nil {
		// Unwired path (tests / pre-Sprint-3 callers): fall back
		// to the freezer directly so the unfreeze still happens.
		if err := r.Freezer.Unfreeze(ctx, pod); err != nil {
			rlog.Info("unfreeze step failed (direct path)", "err", err)
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
	} else if err := r.StepRunner.Run(ctx, &PodUnfreezeStep{Freezer: r.Freezer}, exec); err != nil {
		rlog.Info("unfreeze step failed", "err", err)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	patch := client.MergeFrom(se.DeepCopy())
	if se.Annotations == nil {
		se.Annotations = map[string]string{}
	}
	se.Annotations[unfreezeAppliedAnnotation] = "true"
	if autoUnfreezeReason != "" {
		se.Annotations["ugallu.io/incident-unfreeze-reason"] = autoUnfreezeReason
	}
	if err := r.Patch(ctx, se, patch); err != nil {
		return ctrl.Result{}, err
	}
	pipelineStepsTotal.WithLabelValues("pod_unfreeze", "ok").Inc()
	if autoUnfreezeReason != "" {
		autoUnfreezeTotal.WithLabelValues("fired").Inc()
	}
	rlog.Info("pod unfrozen", "pod", pod.Namespace+"/"+pod.Name, "reason", autoUnfreezeReason)
	return ctrl.Result{}, nil
}

// autoUnfreezeStatus reads the ForensicsConfig and reports the
// auto-unfreeze grace window plus how long until it elapses for
// the supplied SE. Returns:
//   - grace=0 when auto-unfreeze is disabled (the operator waits
//     for a manual ack instead).
//   - requeueAfter>0 when auto-unfreeze IS configured but the
//     grace window has not yet elapsed (caller requeues).
//   - requeueAfter=0 when the window has elapsed and the caller
//     should fire the unfreeze.
func (r *UnfreezeReconciler) autoUnfreezeStatus(ctx context.Context, se *securityv1alpha1.SecurityEvent) (grace, requeueAfter time.Duration, err error) {
	cfg := &securityv1alpha1.ForensicsConfig{}
	if getErr := r.Get(ctx, client.ObjectKey{Name: DefaultForensicsConfigName}, cfg); getErr != nil {
		if apierrors.IsNotFound(getErr) {
			return 0, 0, nil
		}
		return 0, 0, getErr
	}
	grace = cfg.Spec.Cleanup.AutoUnfreezeAfter.Duration
	if grace <= 0 {
		return 0, 0, nil
	}
	deadline := se.CreationTimestamp.Add(grace)
	remaining := time.Until(deadline)
	if remaining > 0 {
		return grace, remaining, nil
	}
	return grace, 0, nil
}

// SetupWithManager wires the unfreeze reconciler.
func (r *UnfreezeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("forensics-unfreeze").
		For(&securityv1alpha1.SecurityEvent{}).
		Complete(r)
}

// unfreezeAppliedAnnotation marks an SE the unfreeze controller has
// already processed so duplicate reconciles are cheap.
const unfreezeAppliedAnnotation = "ugallu.io/incident-unfreeze-applied"

// FailureUnfreezePolicyAnnotation is read on IncidentCaptureFailed
// SEs to decide whether the unfreeze loop runs the same auto path
// as Completed (`auto`, default — empty value) or pauses for an
// explicit ack (`manual` — admin must triage before release, e.g.
// the snapshot binary aborted on `creds`/`config` step).
const FailureUnfreezePolicyAnnotation = "ugallu.io/failure-unfreeze-policy"
