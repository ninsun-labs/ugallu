// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package ttl_test

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/worm"
	ttlrt "github.com/ninsun-labs/ugallu/sdk/pkg/runtime/ttl"
)

// newSE builds a SecurityEvent with the minimum spec needed to pass
// admission. The caller can mutate before Create.
func newSE(name string, sev securityv1alpha1.Severity) *securityv1alpha1.SecurityEvent {
	return &securityv1alpha1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: securityv1alpha1.SecurityEventSpec{
			Class:           securityv1alpha1.ClassDetection,
			Type:            securityv1alpha1.TypeHostPathMount,
			Severity:        sev,
			ClusterIdentity: securityv1alpha1.ClusterIdentity{ClusterName: "t", ClusterID: "c1"},
			Source:          securityv1alpha1.SourceRef{Kind: "Controller", Name: "t"},
			Subject: securityv1alpha1.SubjectTier1{
				Kind: "Pod",
				Name: "tp",
				Pod:  &securityv1alpha1.PodSubject{NodeName: "n1"},
			},
			DetectedAt: metav1.Now(),
		},
	}
}

// newSealedBundle creates an AttestationBundle in Phase=Sealed for the
// given SE.
func newSealedBundle(t *testing.T, name, seName string, seUID types.UID) *securityv1alpha1.AttestationBundle {
	t.Helper()
	b := &securityv1alpha1.AttestationBundle{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: securityv1alpha1.AttestationBundleSpec{
			AttestedFor: corev1.ObjectReference{
				APIVersion: securityv1alpha1.GroupVersion.String(),
				Kind:       "SecurityEvent",
				Name:       seName,
				UID:        seUID,
			},
		},
	}
	if err := k8sClient.Create(ctxT(), b); err != nil {
		t.Fatalf("create bundle %q: %v", name, err)
	}
	patch := client.MergeFrom(b.DeepCopy())
	now := metav1.Now()
	b.Status.Phase = securityv1alpha1.AttestationBundlePhaseSealed
	b.Status.SealedAt = &now
	b.Status.StatementDigest = "sha256:test"
	if err := k8sClient.Status().Patch(ctxT(), b, patch); err != nil {
		t.Fatalf("patch bundle status: %v", err)
	}
	return b
}

// newStubUploader creates a worm.StubUploader rooted at t.TempDir().
func newStubUploader(t *testing.T) worm.Uploader {
	t.Helper()
	u, err := worm.NewStubUploader(t.TempDir())
	if err != nil {
		t.Fatalf("NewStubUploader: %v", err)
	}
	return u
}

// TestSecurityEventTTL_ArchivesAfterTTL verifies that an SE past its
// severity TTL with a Sealed parent bundle is snapshotted and deleted.
func TestSecurityEventTTL_ArchivesAfterTTL(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	se := newSE("ttl-se-archive", securityv1alpha1.SeverityMedium)
	if err := k8sClient.Create(ctx, se); err != nil {
		t.Fatalf("create SE: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, se) })

	// Backdate the creationTimestamp by re-patching (envtest doesn't
	// allow setting creation, so the SE's TTL is overridden via
	// annotation to be much shorter than its actual age).
	patchAnno(t, se, map[string]string{ttlrt.AnnotationTTL: "1ns"})

	bundle := newSealedBundle(t, "att-se-"+se.Name, se.Name, se.UID)
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, bundle) })

	uploader := newStubUploader(t)
	r := &ttlrt.SecurityEventTTLReconciler{
		Client:       k8sClient,
		Scheme:       scheme,
		WormUploader: uploader,
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: se.Name}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := &securityv1alpha1.SecurityEvent{}
	err := k8sClient.Get(ctx, client.ObjectKey{Name: se.Name}, got)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected SE deleted, got err=%v phase=%q", err, got.Status.Phase)
	}
}

// TestSecurityEventTTL_PostponesIfBundleNotSealed verifies that an SE
// past its TTL but with a non-Sealed parent bundle is kept (and the
// reconciler asks for a requeue).
func TestSecurityEventTTL_PostponesIfBundleNotSealed(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	se := newSE("ttl-se-postpone", securityv1alpha1.SeverityMedium)
	if err := k8sClient.Create(ctx, se); err != nil {
		t.Fatalf("create SE: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, se) })
	patchAnno(t, se, map[string]string{ttlrt.AnnotationTTL: "1ns"})

	// Bundle exists but is NOT Sealed.
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

	r := &ttlrt.SecurityEventTTLReconciler{
		Client:                  k8sClient,
		Scheme:                  scheme,
		WormUploader:            newStubUploader(t),
		PostponeOnMissingBundle: 10 * time.Minute,
	}
	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: se.Name}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("RequeueAfter = %v, want > 0 (postpone)", res.RequeueAfter)
	}

	// SE must still exist.
	got := &securityv1alpha1.SecurityEvent{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: se.Name}, got); err != nil {
		t.Fatalf("SE was deleted despite non-Sealed bundle: %v", err)
	}
}

// TestSecurityEventTTL_FrozenAnnotationSkips verifies legal-hold
// behavior: a frozen SE is never archived, even past TTL with a Sealed
// bundle.
func TestSecurityEventTTL_FrozenAnnotationSkips(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	se := newSE("ttl-se-frozen", securityv1alpha1.SeverityMedium)
	if err := k8sClient.Create(ctx, se); err != nil {
		t.Fatalf("create SE: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, se) })
	patchAnno(t, se, map[string]string{
		ttlrt.AnnotationTTL:       "1ns",
		ttlrt.AnnotationTTLFrozen: "true",
	})
	bundle := newSealedBundle(t, "att-se-"+se.Name, se.Name, se.UID)
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, bundle) })

	r := &ttlrt.SecurityEventTTLReconciler{
		Client:       k8sClient,
		Scheme:       scheme,
		WormUploader: newStubUploader(t),
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: se.Name}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := &securityv1alpha1.SecurityEvent{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: se.Name}, got); err != nil {
		t.Fatalf("SE missing despite frozen annotation: %v", err)
	}
}

// TestSecurityEventTTL_PostponeUntilAnnotation verifies that a future
// postpone-until annotation defers archiving.
func TestSecurityEventTTL_PostponeUntilAnnotation(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	se := newSE("ttl-se-pp-anno", securityv1alpha1.SeverityMedium)
	if err := k8sClient.Create(ctx, se); err != nil {
		t.Fatalf("create SE: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, se) })
	future := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	patchAnno(t, se, map[string]string{
		ttlrt.AnnotationTTL:              "1ns",
		ttlrt.AnnotationTTLPostponeUntil: future,
	})
	bundle := newSealedBundle(t, "att-se-"+se.Name, se.Name, se.UID)
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, bundle) })

	r := &ttlrt.SecurityEventTTLReconciler{
		Client:       k8sClient,
		Scheme:       scheme,
		WormUploader: newStubUploader(t),
	}
	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: se.Name}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("RequeueAfter = %v, want > 0 (postpone)", res.RequeueAfter)
	}
	got := &securityv1alpha1.SecurityEvent{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: se.Name}, got); err != nil {
		t.Fatalf("SE was deleted despite postpone-until: %v", err)
	}
}

// TestAttestationBundleTTL_ArchivesPastGrace verifies a Sealed bundle
// past its grace window is archived and deleted.
func TestAttestationBundleTTL_ArchivesPastGrace(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	b := &securityv1alpha1.AttestationBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "ttl-ab-archive",
			Annotations: map[string]string{ttlrt.AnnotationTTL: "1ns"},
		},
		Spec: securityv1alpha1.AttestationBundleSpec{
			AttestedFor: corev1.ObjectReference{
				APIVersion: securityv1alpha1.GroupVersion.String(),
				Kind:       "SecurityEvent",
				Name:       "irrelevant",
			},
		},
	}
	if err := k8sClient.Create(ctx, b); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, b) })
	// Phase=Sealed with a SealedAt in the distant past.
	patch := client.MergeFrom(b.DeepCopy())
	past := metav1.NewTime(time.Now().Add(-30 * 24 * time.Hour))
	b.Status.Phase = securityv1alpha1.AttestationBundlePhaseSealed
	b.Status.SealedAt = &past
	b.Status.StatementDigest = "sha256:past"
	if err := k8sClient.Status().Patch(ctx, b, patch); err != nil {
		t.Fatalf("patch status: %v", err)
	}

	r := &ttlrt.AttestationBundleTTLReconciler{
		Client:       k8sClient,
		Scheme:       scheme,
		WormUploader: newStubUploader(t),
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: b.Name}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := &securityv1alpha1.AttestationBundle{}
	err := k8sClient.Get(ctx, client.ObjectKey{Name: b.Name}, got)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected bundle deleted, got err=%v phase=%q", err, got.Status.Phase)
	}
}

// TestAttestationBundleTTL_NoOpUntilSealed verifies a Pending bundle is
// not archived, regardless of age.
func TestAttestationBundleTTL_NoOpUntilSealed(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	b := &securityv1alpha1.AttestationBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "ttl-ab-pending",
			Annotations: map[string]string{ttlrt.AnnotationTTL: "1ns"},
		},
		Spec: securityv1alpha1.AttestationBundleSpec{
			AttestedFor: corev1.ObjectReference{
				APIVersion: securityv1alpha1.GroupVersion.String(),
				Kind:       "SecurityEvent",
				Name:       "irrelevant",
			},
		},
	}
	if err := k8sClient.Create(ctx, b); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, b) })

	r := &ttlrt.AttestationBundleTTLReconciler{
		Client:       k8sClient,
		Scheme:       scheme,
		WormUploader: newStubUploader(t),
	}
	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: b.Name}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("RequeueAfter = %v, want > 0 for non-Sealed bundle", res.RequeueAfter)
	}
	got := &securityv1alpha1.AttestationBundle{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: b.Name}, got); err != nil {
		t.Fatalf("bundle was deleted despite Pending phase: %v", err)
	}
}

// patchAnno merges the supplied annotations into the object via a
// strategic merge patch.
func patchAnno(t *testing.T, obj client.Object, annos map[string]string) {
	t.Helper()
	// Refresh, then apply annotations.
	switch o := obj.(type) {
	case *securityv1alpha1.SecurityEvent:
		fresh := &securityv1alpha1.SecurityEvent{}
		if err := k8sClient.Get(ctxT(), client.ObjectKeyFromObject(o), fresh); err != nil {
			t.Fatalf("refresh SE: %v", err)
		}
		patch := client.MergeFrom(fresh.DeepCopy())
		if fresh.Annotations == nil {
			fresh.Annotations = map[string]string{}
		}
		for k, v := range annos {
			fresh.Annotations[k] = v
		}
		if err := k8sClient.Patch(ctxT(), fresh, patch); err != nil {
			t.Fatalf("patch SE annotations: %v", err)
		}
		// Refresh caller's view of UID etc.
		*o = *fresh
	default:
		t.Fatalf("patchAnno: unsupported type %T", obj)
	}
}
