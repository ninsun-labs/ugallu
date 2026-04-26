// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor_test

import (
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/attestor"
)

// erFixture builds a minimal valid EventResponse owned by the given parent
// SecurityEvent UID. The Spec is immutable post-creation, so each test
// uses a fresh name to avoid collisions.
func erFixture(name, parentSEName, parentSEUID string) *securityv1alpha1.EventResponse {
	return &securityv1alpha1.EventResponse{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: securityv1alpha1.EventResponseSpec{
			SecurityEventRef: securityv1alpha1.SecurityEventRef{
				Name: parentSEName,
				UID:  types.UID(parentSEUID),
			},
			Responder: securityv1alpha1.ResponderRef{
				Kind:    "Controller",
				Name:    "test-responder",
				Version: "v0.0.1",
			},
			Action: securityv1alpha1.Action{
				Type: securityv1alpha1.ActionPodFreeze,
				Parameters: map[string]string{
					"duration": "30m",
				},
			},
		},
	}
}

// TestEventResponseBundleReconciler_CreatesBundleOnTerminal asserts that
// once the EventResponse reaches a terminal phase (Succeeded), the
// reconciler creates the corresponding Pending AttestationBundle.
func TestEventResponseBundleReconciler_CreatesBundleOnTerminal(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	er := erFixture("er-bundle-create", "parent-se-1", "parent-uid-1")
	if err := k8sClient.Create(ctx, er); err != nil {
		t.Fatalf("create ER: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, er) })

	// Mark Status.Phase=Succeeded via /status subresource.
	patch := client.MergeFrom(er.DeepCopy())
	er.Status.Phase = securityv1alpha1.EventResponsePhaseSucceeded
	er.Status.Outcome = &securityv1alpha1.Outcome{
		Type:    securityv1alpha1.OutcomeActionTaken,
		Message: "PodFreeze applied",
	}
	if err := k8sClient.Status().Patch(ctx, er, patch); err != nil {
		t.Fatalf("status patch: %v", err)
	}

	r := &attestor.EventResponseBundleReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: er.Name},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	bundle := &securityv1alpha1.AttestationBundle{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: "att-er-" + er.Name}, bundle); err != nil {
		t.Fatalf("expected bundle to exist: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, bundle) })

	if bundle.Spec.AttestedFor.Kind != "EventResponse" {
		t.Errorf("AttestedFor.Kind = %q, want EventResponse", bundle.Spec.AttestedFor.Kind)
	}
	if bundle.Spec.AttestedFor.UID != er.UID {
		t.Errorf("AttestedFor.UID = %q, want %q", bundle.Spec.AttestedFor.UID, er.UID)
	}
	if bundle.Labels[attestor.LabelSecurityEventUID] != "parent-uid-1" {
		t.Errorf("LabelSecurityEventUID = %q, want parent-uid-1", bundle.Labels[attestor.LabelSecurityEventUID])
	}
	if bundle.Labels["ugallu.io/event-response-uid"] != string(er.UID) {
		t.Errorf("event-response-uid label = %q, want %q", bundle.Labels["ugallu.io/event-response-uid"], er.UID)
	}
	if bundle.Labels[attestor.LabelManagedBy] != attestor.ManagedByAttestor {
		t.Errorf("missing or wrong %s label", attestor.LabelManagedBy)
	}
}

// TestEventResponseBundleReconciler_SkipsNonTerminal confirms that an
// EventResponse still in Pending or Running produces NO bundle.
func TestEventResponseBundleReconciler_SkipsNonTerminal(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	cases := []struct {
		name  string
		phase securityv1alpha1.EventResponsePhase
	}{
		{"pending", securityv1alpha1.EventResponsePhasePending},
		{"running", securityv1alpha1.EventResponsePhaseRunning},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			er := erFixture("er-skip-"+tc.name, "parent-se-skip", "parent-uid-skip")
			if err := k8sClient.Create(ctx, er); err != nil {
				t.Fatalf("create ER: %v", err)
			}
			t.Cleanup(func() { _ = k8sClient.Delete(ctx, er) })

			if tc.phase != "" {
				patch := client.MergeFrom(er.DeepCopy())
				er.Status.Phase = tc.phase
				if err := k8sClient.Status().Patch(ctx, er, patch); err != nil {
					t.Fatalf("status patch: %v", err)
				}
			}

			r := &attestor.EventResponseBundleReconciler{Client: k8sClient, Scheme: scheme}
			if _, err := r.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: er.Name},
			}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			bundle := &securityv1alpha1.AttestationBundle{}
			err := k8sClient.Get(ctx, client.ObjectKey{Name: "att-er-" + er.Name}, bundle)
			if err == nil {
				_ = k8sClient.Delete(ctx, bundle)
				t.Fatalf("expected NO bundle for non-terminal phase %q", tc.phase)
			}
			if !apierrors.IsNotFound(err) {
				t.Fatalf("expected NotFound, got %v", err)
			}
		})
	}
}

// TestEventResponseBundleReconciler_AllTerminalPhases asserts that
// each of the three terminal phases (Succeeded, Failed, Cancelled)
// triggers bundle creation.
func TestEventResponseBundleReconciler_AllTerminalPhases(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	cases := []struct {
		name  string
		phase securityv1alpha1.EventResponsePhase
	}{
		{"succeeded", securityv1alpha1.EventResponsePhaseSucceeded},
		{"failed", securityv1alpha1.EventResponsePhaseFailed},
		{"cancelled", securityv1alpha1.EventResponsePhaseCancelled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			er := erFixture("er-term-"+tc.name, "p-se", "p-uid")
			if err := k8sClient.Create(ctx, er); err != nil {
				t.Fatalf("create ER: %v", err)
			}
			t.Cleanup(func() { _ = k8sClient.Delete(ctx, er) })

			patch := client.MergeFrom(er.DeepCopy())
			er.Status.Phase = tc.phase
			if err := k8sClient.Status().Patch(ctx, er, patch); err != nil {
				t.Fatalf("status patch: %v", err)
			}

			r := &attestor.EventResponseBundleReconciler{Client: k8sClient, Scheme: scheme}
			if _, err := r.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: er.Name},
			}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			bundle := &securityv1alpha1.AttestationBundle{}
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: "att-er-" + er.Name}, bundle); err != nil {
				t.Fatalf("expected bundle for phase %q: %v", tc.phase, err)
			}
			t.Cleanup(func() { _ = k8sClient.Delete(ctx, bundle) })
		})
	}
}

// TestEventResponseBundleReconciler_Idempotent asserts that re-running
// the reconciler does not create duplicates and does not error.
func TestEventResponseBundleReconciler_Idempotent(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	er := erFixture("er-bundle-idem", "p-se-i", "p-uid-i")
	if err := k8sClient.Create(ctx, er); err != nil {
		t.Fatalf("create ER: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, er) })

	patch := client.MergeFrom(er.DeepCopy())
	er.Status.Phase = securityv1alpha1.EventResponsePhaseFailed
	if err := k8sClient.Status().Patch(ctx, er, patch); err != nil {
		t.Fatalf("status patch: %v", err)
	}

	r := &attestor.EventResponseBundleReconciler{Client: k8sClient, Scheme: scheme}
	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: er.Name},
		}); err != nil {
			t.Fatalf("Reconcile #%d: %v", i, err)
		}
	}

	bundle := &securityv1alpha1.AttestationBundle{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: "att-er-" + er.Name}, bundle); err != nil {
		t.Fatalf("expected bundle to exist: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, bundle) })
}
