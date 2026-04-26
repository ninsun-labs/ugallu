// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor_test

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/attestor"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/logger"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

// newTestSigner returns an Ed25519 in-process signer for use in
// AttestationBundleReconciler tests.
func newTestSigner(t *testing.T) sign.Signer {
	t.Helper()
	s, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	return s
}

// TestAttestationBundleReconciler_PromotesPendingToSealed asserts that
// the skeleton pipeline transitions a Pending bundle to Sealed and that
// the parent SecurityEvent is patched with Phase=Attested + the
// AttestationBundleRef + the StatementDigest.
func TestAttestationBundleReconciler_PromotesPendingToSealed(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	se := &securityv1alpha1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "se-bundle-promote"},
		Spec: securityv1alpha1.SecurityEventSpec{
			Class:           securityv1alpha1.ClassDetection,
			Type:            securityv1alpha1.TypeHostPathMount,
			Severity:        securityv1alpha1.SeverityHigh,
			ClusterIdentity: securityv1alpha1.ClusterIdentity{ClusterName: "t"},
			Source:          securityv1alpha1.SourceRef{Kind: "Controller", Name: "t"},
			Subject: securityv1alpha1.SubjectTier1{
				Kind: "Pod",
				Name: "tp",
				Pod:  &securityv1alpha1.PodSubject{NodeName: "n1"},
			},
			DetectedAt: metav1.Now(),
		},
	}
	if err := k8sClient.Create(ctx, se); err != nil {
		t.Fatalf("create SE: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, se) })

	bundle := &securityv1alpha1.AttestationBundle{
		ObjectMeta: metav1.ObjectMeta{Name: "att-se-" + se.Name},
		Spec: securityv1alpha1.AttestationBundleSpec{
			AttestedFor: corev1.ObjectReference{
				APIVersion: securityv1alpha1.GroupVersion.String(),
				Kind:       "SecurityEvent",
				Name:       se.Name,
				UID:        se.UID,
			},
		},
	}
	if err := k8sClient.Create(ctx, bundle); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, bundle) })

	signer := newTestSigner(t)
	r := &attestor.AttestationBundleReconciler{
		Client:       k8sClient,
		Scheme:       scheme,
		Signer:       signer,
		Logger:       logger.NewStubLogger(),
		AttestorMeta: sign.AttestorMeta{Name: "ugallu-attestor", Version: "test"},
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: bundle.Name}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// Bundle should be Sealed.
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: bundle.Name}, bundle); err != nil {
		t.Fatalf("Get bundle: %v", err)
	}
	if bundle.Status.Phase != securityv1alpha1.AttestationBundlePhaseSealed {
		t.Errorf("Phase = %q, want Sealed", bundle.Status.Phase)
	}
	if !strings.HasPrefix(bundle.Status.StatementDigest, "sha256:") {
		t.Errorf("StatementDigest = %q, want sha256:* prefix", bundle.Status.StatementDigest)
	}
	if bundle.Status.SealedAt == nil {
		t.Error("SealedAt is nil")
	}
	if bundle.Status.Signature == nil || bundle.Status.Signature.Mode != securityv1alpha1.SigningModeEd25519Dev {
		t.Errorf("Signature = %+v, want Mode=ed25519-dev", bundle.Status.Signature)
	}
	if bundle.Status.Signature != nil && !strings.HasPrefix(bundle.Status.Signature.KeyID, "ed25519:") {
		t.Errorf("Signature.KeyID = %q, want ed25519: prefix", bundle.Status.Signature.KeyID)
	}
	if bundle.Status.Signature != nil && bundle.Status.Signature.KeyID != signer.KeyID() {
		t.Errorf("Signature.KeyID = %q, want %q (signer's)", bundle.Status.Signature.KeyID, signer.KeyID())
	}

	// Transparency-log entry must be populated by the StubLogger.
	if bundle.Status.RekorEntry == nil {
		t.Fatal("RekorEntry is nil; logger pipeline did not run")
	}
	if bundle.Status.RekorEntry.UUID == "" {
		t.Errorf("RekorEntry.UUID is empty")
	}
	if bundle.Status.RekorEntry.LogIndex < 1 {
		t.Errorf("RekorEntry.LogIndex = %d, want >= 1", bundle.Status.RekorEntry.LogIndex)
	}

	// Conditions must reflect the partial state: Signed True, Logged True,
	// WORMArchival False (NotImplemented).
	cond := func(t string) *metav1.Condition {
		for i := range bundle.Status.Conditions {
			if bundle.Status.Conditions[i].Type == t {
				return &bundle.Status.Conditions[i]
			}
		}
		return nil
	}
	if c := cond("Signed"); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("Signed condition = %+v, want True", c)
	}
	if c := cond("Logged"); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("Logged condition = %+v, want True", c)
	}
	if c := cond("WORMArchival"); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("WORMArchival condition = %+v, want False", c)
	} else if c.Reason != "NotImplemented" {
		t.Errorf("WORMArchival.Reason = %q, want NotImplemented", c.Reason)
	}

	// Parent SE should be Attested with back-ref.
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: se.Name}, se); err != nil {
		t.Fatalf("Get SE: %v", err)
	}
	if se.Status.Phase != securityv1alpha1.SecurityEventPhaseAttested {
		t.Errorf("SE.Phase = %q, want Attested", se.Status.Phase)
	}
	if se.Status.AttestationDigest != bundle.Status.StatementDigest {
		t.Errorf("SE.AttestationDigest = %q, want %q", se.Status.AttestationDigest, bundle.Status.StatementDigest)
	}
	if se.Status.AttestationBundleRef == nil || se.Status.AttestationBundleRef.Name != bundle.Name {
		t.Errorf("SE.AttestationBundleRef = %+v, want pointing to %q", se.Status.AttestationBundleRef, bundle.Name)
	}
}

// TestAttestationBundleReconciler_NoOpOnSealed asserts that a bundle
// already in Sealed phase is not re-patched.
func TestAttestationBundleReconciler_NoOpOnSealed(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	bundle := &securityv1alpha1.AttestationBundle{
		ObjectMeta: metav1.ObjectMeta{Name: "att-se-noop"},
		Spec: securityv1alpha1.AttestationBundleSpec{
			AttestedFor: corev1.ObjectReference{
				APIVersion: securityv1alpha1.GroupVersion.String(),
				Kind:       "SecurityEvent",
				Name:       "nonexistent",
			},
		},
	}
	if err := k8sClient.Create(ctx, bundle); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, bundle) })

	// Force Sealed.
	patch := client.MergeFrom(bundle.DeepCopy())
	now := metav1.Now()
	bundle.Status.Phase = securityv1alpha1.AttestationBundlePhaseSealed
	bundle.Status.StatementDigest = "sha256:preset"
	bundle.Status.SealedAt = &now
	if err := k8sClient.Status().Patch(ctx, bundle, patch); err != nil {
		t.Fatalf("status patch: %v", err)
	}

	r := &attestor.AttestationBundleReconciler{
		Client:       k8sClient,
		Scheme:       scheme,
		Signer:       newTestSigner(t),
		Logger:       logger.NewStubLogger(),
		AttestorMeta: sign.AttestorMeta{Name: "ugallu-attestor", Version: "test"},
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: bundle.Name}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := &securityv1alpha1.AttestationBundle{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: bundle.Name}, got); err != nil {
		t.Fatalf("Get bundle: %v", err)
	}
	if got.Status.StatementDigest != "sha256:preset" {
		t.Errorf("StatementDigest = %q, want sha256:preset (no-op expected)", got.Status.StatementDigest)
	}
}
