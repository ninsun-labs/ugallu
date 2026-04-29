// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package seccompgen

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// TrainingRunReconciler reconciles SeccompTrainingRun CRs.
type TrainingRunReconciler struct {
	Client          client.Client
	Scheme          *runtime.Scheme
	Emitter         *emitterv1alpha1.Emitter
	ClusterIdentity securityv1alpha1.ClusterIdentity
	BridgeEndpoint  string
	BridgeToken     string
	Engine          *Engine
}

// SetupWithManager wires the reconciler against SeccompTrainingRun.
func (r *TrainingRunReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.SeccompTrainingRun{}).
		Named("seccomp-training-run").
		Complete(r)
}

// Reconcile drives the SeccompTrainingRun lifecycle.
func (r *TrainingRunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var run securityv1alpha1.SeccompTrainingRun
	if err := r.Client.Get(ctx, req.NamespacedName, &run); err != nil {
		if apierrors.IsNotFound(err) {
			r.Engine.Cancel(req.Namespace, req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	switch run.Status.Phase {
	case "":
		// First touch — kick off the training engine.
		return r.start(ctx, &run)
	case "Running":
		// In-flight; wait for the engine to finish. The engine drives
		// status updates itself, but a periodic requeue keeps the
		// controller honest if the engine goroutine crashed for any
		// reason and the run is now orphaned.
		if !r.Engine.IsRunning(run.Namespace, run.Name) {
			return r.fail(ctx, &run, "training-engine-not-running")
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	default:
		// Succeeded / Failed — nothing left to do.
		return ctrl.Result{}, nil
	}
}

// start resolves the target Pods, kicks the engine, and writes the
// initial status transition.
func (r *TrainingRunReconciler) start(ctx context.Context, run *securityv1alpha1.SeccompTrainingRun) (ctrl.Result, error) {
	selector, err := metav1.LabelSelectorAsSelector(&run.Spec.TargetSelector)
	if err != nil {
		return r.fail(ctx, run, fmt.Sprintf("invalid selector: %v", err))
	}
	pods, err := r.selectPods(ctx, run.Spec.TargetNamespace, selector, run.Spec.ReplicaRatio)
	if err != nil {
		return r.fail(ctx, run, fmt.Sprintf("select pods: %v", err))
	}
	if len(pods) == 0 {
		return r.fail(ctx, run, "no pods matched the selector")
	}

	now := metav1.Now()
	run.Status.Phase = "Running"
	run.Status.StartTime = &now
	run.Status.SelectedReplicas = len(pods)
	if updateErr := r.Client.Status().Update(ctx, run); updateErr != nil {
		return ctrl.Result{}, updateErr
	}

	r.emitSE(ctx, run, securityv1alpha1.TypeSeccompTrainingStarted, "", securityv1alpha1.SeverityInfo)

	// Detach the engine from the request ctx — Reconcile returns
	// quickly while the training keeps running for run.Spec.Duration.
	// The engine internally bounds the lifetime via its own
	// context.WithTimeout.
	engineCtx := context.Background() //nolint:gosec // intentional: engine outlives the Reconcile request
	results, err := r.Engine.Start(engineCtx, &RunOpts{
		RunNamespace:   run.Namespace,
		RunName:        run.Name,
		BridgeEndpoint: r.BridgeEndpoint,
		BridgeToken:    r.BridgeToken,
		TargetPods:     toEngineNames(pods),
		Duration:       run.Spec.Duration.Duration,
	})
	if err != nil {
		return r.fail(ctx, run, fmt.Sprintf("engine start: %v", err))
	}

	// awaitResult must outlive the Reconcile request because it
	// blocks for run.Spec.Duration; gosec G118 acknowledged.
	go r.awaitResult(run.Namespace, run.Name, results) //nolint:gosec // intentional: outlives request ctx
	return ctrl.Result{RequeueAfter: run.Spec.Duration.Duration + 5*time.Second}, nil
}

// awaitResult watches the engine channel and completes the run.
func (r *TrainingRunReconciler) awaitResult(ns, name string, results <-chan StartResult) {
	res, ok := <-results
	if !ok {
		return
	}
	ctx := context.Background()
	var run securityv1alpha1.SeccompTrainingRun
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &run); err != nil {
		return
	}
	if res.Err != nil {
		_, _ = r.fail(ctx, &run, res.Err.Error())
		return
	}
	_, _ = r.succeed(ctx, &run, res.Capture)
}

// fail moves the run to Phase=Failed + emits the matching SE.
func (r *TrainingRunReconciler) fail(ctx context.Context, run *securityv1alpha1.SeccompTrainingRun, reason string) (ctrl.Result, error) {
	now := metav1.Now()
	run.Status.Phase = "Failed"
	run.Status.CompletionTime = &now
	run.Status.Conditions = upsertCondition(run.Status.Conditions, &metav1.Condition{
		Type:               "Failed",
		Status:             metav1.ConditionTrue,
		Reason:             "TrainingFailed",
		Message:            reason,
		LastTransitionTime: now,
	})
	if err := r.Client.Status().Update(ctx, run); err != nil {
		return ctrl.Result{}, err
	}
	r.emitSE(ctx, run, securityv1alpha1.TypeSeccompTrainingFailed, reason, securityv1alpha1.SeverityHigh)
	return ctrl.Result{}, nil
}

// succeed writes the produced SeccompTrainingProfile + flips the run.
func (r *TrainingRunReconciler) succeed(ctx context.Context, run *securityv1alpha1.SeccompTrainingRun, capture *Capture) (ctrl.Result, error) {
	profileJSON, err := BuildSeccompProfile(capture, run.Spec.DefaultAction)
	if err != nil {
		return r.fail(ctx, run, fmt.Sprintf("build profile: %v", err))
	}
	profile := &securityv1alpha1.SeccompTrainingProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      run.Name + "-profile",
			Namespace: run.Namespace,
		},
		Spec: securityv1alpha1.SeccompTrainingProfileSpec{
			ProfileJSON:    profileJSON,
			DerivedFromRun: securityv1alpha1.LocalProfileRef{Name: run.Name},
			DefaultAction:  run.Spec.DefaultAction,
			PodSelector:    run.Spec.TargetSelector,
		},
	}
	if err := r.Client.Create(ctx, profile); err != nil && !apierrors.IsAlreadyExists(err) {
		return r.fail(ctx, run, fmt.Sprintf("create profile: %v", err))
	}

	now := metav1.Now()
	run.Status.Phase = "Succeeded"
	run.Status.CompletionTime = &now
	run.Status.ObservedSyscallCount = len(capture.Syscalls)
	run.Status.ProfileRef = &securityv1alpha1.LocalProfileRef{Name: profile.Name}
	if err := r.Client.Status().Update(ctx, run); err != nil {
		return ctrl.Result{}, err
	}
	r.emitSE(ctx, run, securityv1alpha1.TypeSeccompTrainingCompleted, "", securityv1alpha1.SeverityInfo)
	return ctrl.Result{}, nil
}

// selectPods materialises the matching Pod set and applies the
// replica ratio. Sorting by Name keeps the selection stable across
// reconciles (so the same Pods are picked on retry).
func (r *TrainingRunReconciler) selectPods(ctx context.Context, namespace string, selector labels.Selector, ratio int) ([]NamespacedName, error) {
	var list corev1.PodList
	if err := r.Client.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, nil
	}
	// Stable order: sort by name.
	pods := make([]NamespacedName, 0, len(list.Items))
	for i := range list.Items {
		pods = append(pods, NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name})
	}
	// Pick ceil(N * ratio / 100), but at least 1, and leave at least
	// one untrained Pod when the workload has 2+ replicas.
	n := (len(pods)*ratio + 99) / 100
	if n < 1 {
		n = 1
	}
	if len(pods) >= 2 && n >= len(pods) {
		n = len(pods) - 1
	}
	return pods[:n], nil
}

// emitSE wraps the SDK emitter with the operator's identity defaults.
func (r *TrainingRunReconciler) emitSE(ctx context.Context, run *securityv1alpha1.SeccompTrainingRun, seType, reason string, severity securityv1alpha1.Severity) {
	signals := map[string]string{
		"run.namespace":    run.Namespace,
		"run.name":         run.Name,
		"target.namespace": run.Spec.TargetNamespace,
	}
	if reason != "" {
		signals["reason"] = reason
	}
	_, _ = r.Emitter.Emit(ctx, &emitterv1alpha1.EmitOpts{
		Class:            securityv1alpha1.ClassPolicyViolation,
		Type:             seType,
		Severity:         severity,
		SubjectKind:      securityv1alpha1.SubjectKind("Namespace"),
		SubjectName:      run.Spec.TargetNamespace,
		SubjectNamespace: run.Spec.TargetNamespace,
		Signals:          signals,
		ClusterIdentity:  r.ClusterIdentity,
	})
}

func toEngineNames(in []NamespacedName) []NamespacedName { return in }

// upsertCondition replaces a same-Type condition or appends a new one.
func upsertCondition(conds []metav1.Condition, c *metav1.Condition) []metav1.Condition {
	for i := range conds {
		if conds[i].Type == c.Type {
			conds[i] = *c
			return conds
		}
	}
	return append(conds, *c)
}
