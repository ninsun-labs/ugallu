// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor_test

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/attestor"
)

// TestSecurityEventBundleReconciler_CreatesPendingBundle asserts that a
// reconcile of a fresh SecurityEvent produces a Pending AttestationBundle
// with the deterministic name and the correct AttestedFor reference.
func TestSecurityEventBundleReconciler_CreatesPendingBundle(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	se := &securityv1alpha1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "se-bundle-create"},
		Spec: securityv1alpha1.SecurityEventSpec{
			Class:    securityv1alpha1.ClassDetection,
			Type:     securityv1alpha1.TypePrivilegedPodChange,
			Severity: securityv1alpha1.SeverityHigh,
			ClusterIdentity: securityv1alpha1.ClusterIdentity{
				ClusterName: "test",
				ClusterID:   "test-uid",
			},
			Source: securityv1alpha1.SourceRef{
				Kind: "Controller",
				Name: "test-source",
			},
			Subject: securityv1alpha1.SubjectTier1{
				Kind: "Pod",
				Name: "target",
				Pod:  &securityv1alpha1.PodSubject{NodeName: "n1"},
			},
			DetectedAt: metav1.Now(),
		},
	}
	if err := k8sClient.Create(ctx, se); err != nil {
		t.Fatalf("create SE: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, se) })

	r := &attestor.SecurityEventBundleReconciler{
		Client: k8sClient,
		Scheme: scheme,
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: se.Name},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	bundle := &securityv1alpha1.AttestationBundle{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: "att-se-" + se.Name}, bundle); err != nil {
		t.Fatalf("expected bundle to exist: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, bundle) })

	if bundle.Spec.AttestedFor.Kind != "SecurityEvent" {
		t.Errorf("AttestedFor.Kind = %q, want SecurityEvent", bundle.Spec.AttestedFor.Kind)
	}
	if bundle.Spec.AttestedFor.Name != se.Name {
		t.Errorf("AttestedFor.Name = %q, want %q", bundle.Spec.AttestedFor.Name, se.Name)
	}
	if bundle.Spec.AttestedFor.UID != se.UID {
		t.Errorf("AttestedFor.UID = %q, want %q", bundle.Spec.AttestedFor.UID, se.UID)
	}
	if bundle.Labels[attestor.LabelSecurityEventUID] != string(se.UID) {
		t.Errorf("missing or wrong %s label", attestor.LabelSecurityEventUID)
	}
	if bundle.Labels[attestor.LabelManagedBy] != attestor.ManagedByAttestor {
		t.Errorf("missing or wrong %s label", attestor.LabelManagedBy)
	}
}

// TestSecurityEventBundleReconciler_Idempotent confirms that re-running
// the reconciler on the same SE does not create a duplicate bundle and
// does not error.
func TestSecurityEventBundleReconciler_Idempotent(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	se := &securityv1alpha1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "se-bundle-idem"},
		Spec: securityv1alpha1.SecurityEventSpec{
			Class:           securityv1alpha1.ClassDetection,
			Type:            securityv1alpha1.TypeAnonymousAccess,
			Severity:        securityv1alpha1.SeverityCritical,
			ClusterIdentity: securityv1alpha1.ClusterIdentity{ClusterName: "t"},
			Source:          securityv1alpha1.SourceRef{Kind: "Controller", Name: "t"},
			Subject: securityv1alpha1.SubjectTier1{
				Kind:    "Cluster",
				Name:    "t",
				Cluster: &securityv1alpha1.ClusterSubject{ClusterID: "t"},
			},
			DetectedAt: metav1.Now(),
		},
	}
	if err := k8sClient.Create(ctx, se); err != nil {
		t.Fatalf("create SE: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, se) })

	r := &attestor.SecurityEventBundleReconciler{Client: k8sClient, Scheme: scheme}
	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: se.Name}}); err != nil {
			t.Fatalf("Reconcile #%d: %v", i, err)
		}
	}

	bundle := &securityv1alpha1.AttestationBundle{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: "att-se-" + se.Name}, bundle); err != nil {
		t.Fatalf("expected bundle to exist: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, bundle) })
}

// TestSecurityEventBundleReconciler_SkipsTerminalPhase confirms that a
// SecurityEvent already in Attested or Archived phase produces no bundle.
func TestSecurityEventBundleReconciler_SkipsTerminalPhase(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	se := &securityv1alpha1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "se-bundle-terminal"},
		Spec: securityv1alpha1.SecurityEventSpec{
			Class:           securityv1alpha1.ClassDetection,
			Type:            securityv1alpha1.TypeWildcardRBACBinding,
			Severity:        securityv1alpha1.SeverityHigh,
			ClusterIdentity: securityv1alpha1.ClusterIdentity{ClusterName: "t"},
			Source:          securityv1alpha1.SourceRef{Kind: "Controller", Name: "t"},
			Subject: securityv1alpha1.SubjectTier1{
				Kind: "Pod",
				Name: "t",
				Pod:  &securityv1alpha1.PodSubject{NodeName: "n"},
			},
			DetectedAt: metav1.Now(),
		},
	}
	if err := k8sClient.Create(ctx, se); err != nil {
		t.Fatalf("create SE: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, se) })

	// Mark Status as already Attested via the /status subresource.
	patch := client.MergeFrom(se.DeepCopy())
	se.Status.Phase = securityv1alpha1.SecurityEventPhaseAttested
	se.Status.AttestationDigest = "sha256:already-done"
	se.Status.AttestationBundleRef = &corev1.ObjectReference{
		Kind: "AttestationBundle",
		Name: "att-se-" + se.Name,
	}
	if err := k8sClient.Status().Patch(ctx, se, patch); err != nil {
		t.Fatalf("status patch: %v", err)
	}

	r := &attestor.SecurityEventBundleReconciler{Client: k8sClient, Scheme: scheme}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: se.Name}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	bundle := &securityv1alpha1.AttestationBundle{}
	err := k8sClient.Get(ctx, client.ObjectKey{Name: "att-se-" + se.Name}, bundle)
	if err == nil {
		t.Fatal("expected NO bundle to exist for terminal-phase SE")
	}
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected NotFound, got %v", err)
	}
}
