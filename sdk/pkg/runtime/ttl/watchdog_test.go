// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package ttl_test

import (
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	ttlrt "github.com/ninsun-labs/ugallu/sdk/pkg/runtime/ttl"
)

// listWatchdogSEs returns all SecurityEvents created by the watchdog
// (filtered by the ugallu.io/watchdog label).
func listWatchdogSEs(t *testing.T) []securityv1alpha1.SecurityEvent {
	t.Helper()
	list := &securityv1alpha1.SecurityEventList{}
	if err := k8sClient.List(ctxT(), list, client.MatchingLabels{"ugallu.io/watchdog": "attestor"}); err != nil {
		t.Fatalf("list SEs: %v", err)
	}
	return list.Items
}

// makeLease creates the attestor leader Lease with the given renewTime.
// nil renewTime leaves the spec unset (simulating a never-renewed lease).
func makeLease(t *testing.T, ns string, renew *time.Time) *coordinationv1.Lease {
	t.Helper()
	holder := "ugallu-attestor-1"
	ld := int32(15)
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ttlrt.AttestorLeaseName,
			Namespace: ns,
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       &holder,
			LeaseDurationSeconds: &ld,
		},
	}
	if renew != nil {
		mt := metav1.NewMicroTime(*renew)
		lease.Spec.RenewTime = &mt
	}
	if err := k8sClient.Create(ctxT(), lease); err != nil {
		t.Fatalf("create Lease: %v", err)
	}
	return lease
}

// patchLeaseRenew updates the Lease's RenewTime via a MergeFrom patch.
func patchLeaseRenew(t *testing.T, lease *coordinationv1.Lease, renew time.Time) {
	t.Helper()
	patch := client.MergeFrom(lease.DeepCopy())
	mt := metav1.NewMicroTime(renew)
	lease.Spec.RenewTime = &mt
	if err := k8sClient.Patch(ctxT(), lease, patch); err != nil {
		t.Fatalf("patch Lease renewTime: %v", err)
	}
}

// cleanupWatchdogSEs deletes any SEs left over from prior watchdog
// tests so each test starts with a clean slate.
func cleanupWatchdogSEs(t *testing.T) {
	t.Helper()
	ses := listWatchdogSEs(t)
	for i := range ses {
		_ = k8sClient.Delete(ctxT(), &ses[i])
	}
}

// TestAttestorWatchdog_EmitsSEWhenLeaseStale creates a Lease whose
// renewTime is 30 minutes old and verifies the watchdog emits a single
// AttestorUnavailable SE.
func TestAttestorWatchdog_EmitsSEWhenLeaseStale(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()
	cleanupWatchdogSEs(t)

	const ns = "ugallu-test-wd-stale"
	ensureTTLConfigNamespace(t, ns)

	stale := time.Now().Add(-30 * time.Minute)
	lease := makeLease(t, ns, &stale)
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, lease) })

	r := &ttlrt.AttestorWatchdogReconciler{
		Client:         k8sClient,
		Scheme:         scheme,
		LeaseNamespace: ns,
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: ns, Name: ttlrt.AttestorLeaseName,
	}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	ses := listWatchdogSEs(t)
	if len(ses) != 1 {
		t.Fatalf("got %d watchdog SEs, want 1: %+v", len(ses), ses)
	}
	if ses[0].Spec.Type != securityv1alpha1.TypeAttestorUnavailable {
		t.Errorf("SE.Type = %q, want %q", ses[0].Spec.Type, securityv1alpha1.TypeAttestorUnavailable)
	}
	if ses[0].Spec.Class != securityv1alpha1.ClassAnomaly {
		t.Errorf("SE.Class = %q, want Anomaly", ses[0].Spec.Class)
	}
	t.Cleanup(func() { cleanupWatchdogSEs(t) })
}

// TestAttestorWatchdog_DedupesWithinWindow asserts that consecutive
// stale-lease reconciles inside the dedup window only produce one SE.
func TestAttestorWatchdog_DedupesWithinWindow(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()
	cleanupWatchdogSEs(t)

	const ns = "ugallu-test-wd-dedup"
	ensureTTLConfigNamespace(t, ns)

	stale := time.Now().Add(-30 * time.Minute)
	lease := makeLease(t, ns, &stale)
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, lease) })

	r := &ttlrt.AttestorWatchdogReconciler{
		Client:         k8sClient,
		Scheme:         scheme,
		LeaseNamespace: ns,
		DedupWindow:    time.Hour,
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: ttlrt.AttestorLeaseName}}
	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile #%d: %v", i, err)
		}
	}
	ses := listWatchdogSEs(t)
	if len(ses) != 1 {
		t.Fatalf("got %d SEs, want 1 (dedup): %+v", len(ses), ses)
	}
	t.Cleanup(func() { cleanupWatchdogSEs(t) })
}

// TestAttestorWatchdog_RecoveryEmitsRecoveredSE verifies that after a
// stale-then-fresh sequence the watchdog emits an AttestorRecovered SE.
func TestAttestorWatchdog_RecoveryEmitsRecoveredSE(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()
	cleanupWatchdogSEs(t)

	const ns = "ugallu-test-wd-recover"
	ensureTTLConfigNamespace(t, ns)

	stale := time.Now().Add(-30 * time.Minute)
	lease := makeLease(t, ns, &stale)
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, lease) })

	r := &ttlrt.AttestorWatchdogReconciler{
		Client:         k8sClient,
		Scheme:         scheme,
		LeaseNamespace: ns,
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: ttlrt.AttestorLeaseName}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile (stale): %v", err)
	}

	patchLeaseRenew(t, lease, time.Now())
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile (fresh): %v", err)
	}

	ses := listWatchdogSEs(t)
	var sawDown, sawUp bool
	for _, se := range ses {
		switch se.Spec.Type {
		case securityv1alpha1.TypeAttestorUnavailable:
			sawDown = true
		case securityv1alpha1.TypeAttestorRecovered:
			sawUp = true
		}
	}
	if !sawDown || !sawUp {
		t.Errorf("missing SE; sawDown=%v sawUp=%v: %+v", sawDown, sawUp, ses)
	}
	t.Cleanup(func() { cleanupWatchdogSEs(t) })
}

// TestAttestorWatchdog_FreshLeaseNoOp verifies a fresh Lease never
// produces an SE.
func TestAttestorWatchdog_FreshLeaseNoOp(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()
	cleanupWatchdogSEs(t)

	const ns = "ugallu-test-wd-fresh"
	ensureTTLConfigNamespace(t, ns)

	fresh := time.Now()
	lease := makeLease(t, ns, &fresh)
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, lease) })

	r := &ttlrt.AttestorWatchdogReconciler{
		Client:         k8sClient,
		Scheme:         scheme,
		LeaseNamespace: ns,
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: ns, Name: ttlrt.AttestorLeaseName,
	}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if ses := listWatchdogSEs(t); len(ses) != 0 {
		t.Errorf("got %d SEs, want 0 for fresh Lease: %+v", len(ses), ses)
	}
}
