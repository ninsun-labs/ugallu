// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// LabelSecurityEventUID is the label that links bundles and EventResponses
// to their parent SecurityEvent for fast list-by-event queries.
const LabelSecurityEventUID = "ugallu.io/security-event-uid"

// LabelManagedBy identifies the controller that owns a resource.
const LabelManagedBy = "app.kubernetes.io/managed-by"

// ManagedByAttestor is the value of LabelManagedBy for resources
// created by the attestor.
const ManagedByAttestor = "ugallu-attestor"

// SecurityEventBundleReconciler creates a Pending AttestationBundle for
// each SecurityEvent that is in the Active phase (or has no phase set,
// which is the canonical post-emit state in v1alpha1 - phase Pending was
// removed by review H3).
//
// Idempotent: if the bundle already exists for the given SecurityEvent,
// the reconciler is a no-op. Bundle name is deterministic.
type SecurityEventBundleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile maps a SecurityEvent to its AttestationBundle.
func (r *SecurityEventBundleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("securityevent", req.Name)

	se := &securityv1alpha1.SecurityEvent{}
	if err := r.Get(ctx, req.NamespacedName, se); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Skip terminal phases. An empty phase is valid (= just emitted).
	switch se.Status.Phase {
	case securityv1alpha1.SecurityEventPhaseAttested,
		securityv1alpha1.SecurityEventPhaseArchived:
		return ctrl.Result{}, nil
	}

	bundleName := fmt.Sprintf("att-se-%s", se.Name)

	existing := &securityv1alpha1.AttestationBundle{}
	err := r.Get(ctx, client.ObjectKey{Name: bundleName}, existing)
	if err == nil {
		// Already exists; AttestationBundleReconciler will drive its lifecycle.
		return ctrl.Result{}, nil
	}
	if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("get existing bundle: %w", err)
	}

	bundle := &securityv1alpha1.AttestationBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: bundleName,
			Labels: map[string]string{
				LabelSecurityEventUID:         string(se.UID),
				LabelManagedBy:                ManagedByAttestor,
				"app.kubernetes.io/part-of":   "ugallu",
				"app.kubernetes.io/component": "attestation",
			},
		},
		Spec: securityv1alpha1.AttestationBundleSpec{
			AttestedFor: corev1.ObjectReference{
				APIVersion: securityv1alpha1.GroupVersion.String(),
				Kind:       "SecurityEvent",
				Name:       se.Name,
				UID:        se.UID,
			},
		},
	}

	if err := r.Create(ctx, bundle); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "create AttestationBundle failed")
		return ctrl.Result{}, fmt.Errorf("create bundle: %w", err)
	}
	logger.Info("created AttestationBundle (Pending)", "bundle", bundleName)
	return ctrl.Result{}, nil
}

// SetupWithManager wires the reconciler to a controller-runtime manager.
func (r *SecurityEventBundleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("securityevent-bundle").
		For(&securityv1alpha1.SecurityEvent{}).
		Complete(r)
}
