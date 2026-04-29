// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("corev1: %v", err)
	}
	if err := securityv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("securityv1alpha1: %v", err)
	}
	return s
}

// TestUnfreezeOnFailed_ManualPolicyKeepsFrozen asserts that an
// IncidentCaptureFailed SE with failure-unfreeze-policy=manual
// stays frozen until an explicit ack lands. The reconcile must
// return early at the policy gate — without reaching the Freezer
// (left nil, which would panic if the gate failed open).
func TestUnfreezeOnFailed_ManualPolicyKeepsFrozen(t *testing.T) {
	se := &securityv1alpha1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "se-failed-manual",
			Annotations: map[string]string{
				FailureUnfreezePolicyAnnotation: "manual",
			},
		},
		Spec: securityv1alpha1.SecurityEventSpec{
			Class: "Forensic",
			Type:  securityv1alpha1.TypeIncidentCaptureFailed,
			Subject: securityv1alpha1.SubjectTier1{
				Kind: "Pod", Name: "p", Namespace: "team-a",
			},
		},
	}
	scheme := newTestScheme(t)
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(se).Build()

	r := &UnfreezeReconciler{Client: fc, Scheme: scheme} // Freezer nil — must not be reached.
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: se.Name}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("manual policy should return no requeue, got RequeueAfter=%v", res.RequeueAfter)
	}

	var got securityv1alpha1.SecurityEvent
	if err := fc.Get(context.Background(), client.ObjectKey{Name: se.Name}, &got); err != nil {
		t.Fatalf("get SE: %v", err)
	}
	if got.Annotations[unfreezeAppliedAnnotation] == "true" {
		t.Errorf("manual policy must not stamp unfreeze-applied; got annotations=%v", got.Annotations)
	}
}

// TestUnfreezeOnFailed_NonForensicSkips asserts the reconciler
// short-circuits cleanly on non-Forensic SEs (the watcher
// should not trigger on Detection / Anomaly types either, but the
// fail-safe gate covers a misrouted Reconcile call).
func TestUnfreezeOnFailed_NonForensicSkips(t *testing.T) {
	se := &securityv1alpha1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "se-detection"},
		Spec: securityv1alpha1.SecurityEventSpec{
			Class: "Detection",
			Type:  securityv1alpha1.TypeClusterAdminGranted,
		},
	}
	scheme := newTestScheme(t)
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(se).Build()

	r := &UnfreezeReconciler{Client: fc, Scheme: scheme}
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: se.Name}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("non-Forensic SE should not requeue")
	}
}
