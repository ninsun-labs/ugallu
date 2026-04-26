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

// EventResponseBundleReconciler creates a Pending AttestationBundle for
// each EventResponse that has reached a terminal phase
// (Succeeded / Failed / Cancelled). Idempotent.
type EventResponseBundleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile maps an EventResponse to its AttestationBundle.
func (r *EventResponseBundleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("eventresponse", req.Name)

	er := &securityv1alpha1.EventResponse{}
	if err := r.Get(ctx, req.NamespacedName, er); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !isERTerminal(er.Status.Phase) {
		// Not terminal yet; skip until next transition.
		return ctrl.Result{}, nil
	}

	bundleName := fmt.Sprintf("att-er-%s", er.Name)

	existing := &securityv1alpha1.AttestationBundle{}
	err := r.Get(ctx, client.ObjectKey{Name: bundleName}, existing)
	if err == nil {
		return ctrl.Result{}, nil
	}
	if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("get existing bundle: %w", err)
	}

	bundle := &securityv1alpha1.AttestationBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: bundleName,
			Labels: map[string]string{
				LabelSecurityEventUID:          string(er.Spec.SecurityEventRef.UID),
				LabelManagedBy:                 ManagedByAttestor,
				"app.kubernetes.io/part-of":    "ugallu",
				"app.kubernetes.io/component":  "attestation",
				"ugallu.io/event-response-uid": string(er.UID),
			},
		},
		Spec: securityv1alpha1.AttestationBundleSpec{
			AttestedFor: corev1.ObjectReference{
				APIVersion: securityv1alpha1.GroupVersion.String(),
				Kind:       "EventResponse",
				Name:       er.Name,
				UID:        er.UID,
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
func (r *EventResponseBundleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("eventresponse-bundle").
		For(&securityv1alpha1.EventResponse{}).
		Complete(r)
}

func isERTerminal(p securityv1alpha1.EventResponsePhase) bool {
	switch p {
	case securityv1alpha1.EventResponsePhaseSucceeded,
		securityv1alpha1.EventResponsePhaseFailed,
		securityv1alpha1.EventResponsePhaseCancelled:
		return true
	}
	return false
}
