// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// ConditionTypeReady is the ForensicsConfig status condition the
// reconciler writes after every successful spec read. Status=True
// + Reason=Loaded means the operator is reconciling against the
// supplied spec; Status=False + Reason=NotFound means the
// singleton CR is missing and the operator falls back to defaults.
const ConditionTypeReady = "Ready"

// ConfigReconciler watches the singleton ForensicsConfig
// CR and surfaces operator-side runtime state into its status:
//   - FreezeBackend (auto-detected at boot, refreshed every 10m)
//   - LastConfigLoadAt (the most recent successful spec read)
//   - In-flight incident count (visible via kubectl describe so
//     operations can spot a stuck pipeline without reading metrics)
//
// The reconciler is leader-elected via the manager so only one
// replica writes status; the others stay idle.
type ConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// CNI is the freeze-backend detector populated at startup.
	CNI *CNIDetector

	// Pipeline is read-only: the reconciler reports the in-flight
	// incident count from Pipeline.InFlight().
	Pipeline *Pipeline
}

// Reconcile is the controller-runtime entry point. It always
// requeues the singleton 30s later so the FreezeBackend status
// stays fresh against the periodic CNI refresh.
func (r *ConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Name != DefaultForensicsConfigName {
		return ctrl.Result{}, nil
	}
	rlog := log.FromContext(ctx).WithName("forensics-config")

	cfg := &securityv1alpha1.ForensicsConfig{}
	if err := r.Get(ctx, req.NamespacedName, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			rlog.Info("ForensicsConfig 'default' missing; operator runs with built-in defaults")
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	patch := cfg.DeepCopy()
	now := metav1.NewTime(time.Now())

	if r.CNI != nil {
		patch.Status.FreezeBackend = string(r.CNI.Backend())
	}
	if r.Pipeline != nil {
		patch.Status.InFlightIncidents = r.Pipeline.InFlight()
	}
	patch.Status.LastConfigLoadAt = &now

	cond := metav1.Condition{
		Type:               ConditionTypeReady,
		Status:             metav1.ConditionTrue,
		Reason:             "Loaded",
		Message:            fmt.Sprintf("spec read; FreezeBackend=%s", patch.Status.FreezeBackend),
		LastTransitionTime: now,
		ObservedGeneration: cfg.Generation,
	}
	if r.CNI != nil && r.CNI.FailureCount() > 0 {
		cond.Reason = "CNIDetectIntermittent"
		cond.Message = fmt.Sprintf("%s (cni-detect failures=%d)", cond.Message, r.CNI.FailureCount())
	}
	upsertCondition(&patch.Status.Conditions, &cond)

	if err := r.Status().Patch(ctx, patch, client.MergeFrom(cfg)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch ForensicsConfig status: %w", err)
	}
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// SetupWithManager wires the reconciler.
func (r *ConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.CNI == nil {
		return errors.New("forensics-config: CNI detector is required")
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("forensics-config").
		For(&securityv1alpha1.ForensicsConfig{}).
		Complete(r)
}

// upsertCondition replaces the entry whose Type matches cond.Type,
// preserving LastTransitionTime when Status didn't actually change
// so kubectl's "since" stays useful.
func upsertCondition(list *[]metav1.Condition, cond *metav1.Condition) {
	for i := range *list {
		if (*list)[i].Type != cond.Type {
			continue
		}
		if (*list)[i].Status == cond.Status {
			cond.LastTransitionTime = (*list)[i].LastTransitionTime
		}
		(*list)[i] = *cond
		return
	}
	*list = append(*list, *cond)
}
