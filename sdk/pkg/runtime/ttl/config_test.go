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
	ttlrt "github.com/ninsun-labs/ugallu/sdk/pkg/runtime/ttl"
)

// ensureTTLConfigNamespace makes sure the namespace consulted by the
// TTL reconcilers exists in envtest. Idempotent.
func ensureTTLConfigNamespace(t *testing.T, name string) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := k8sClient.Create(ctxT(), ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create ns %q: %v", name, err)
	}
}

// TestTTLConfig_OverridesSeverityWindow verifies that a TTLConfig with
// a custom critical TTL is honoured (overriding the design-09 default
// of 7d). We set critical=1ns; with no annotation override, an SE of
// severity=critical should be archived immediately.
func TestTTLConfig_OverridesSeverityWindow(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	const ns = "ugallu-test-cfg-override"
	ensureTTLConfigNamespace(t, ns)

	tc := &securityv1alpha1.TTLConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: ns},
		Spec: securityv1alpha1.TTLConfigSpec{
			Defaults: securityv1alpha1.TTLDefaults{
				SecurityEvent: securityv1alpha1.SeverityTTL{
					Critical: metav1.Duration{Duration: time.Nanosecond},
				},
			},
		},
	}
	if err := k8sClient.Create(ctx, tc); err != nil {
		t.Fatalf("create TTLConfig: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, tc) })

	se := newSE("ttl-cfg-override", securityv1alpha1.SeverityCritical)
	if err := k8sClient.Create(ctx, se); err != nil {
		t.Fatalf("create SE: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, se) })

	bundle := newSealedBundle(t, "att-se-"+se.Name, se.Name, se.UID)
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, bundle) })

	r := &ttlrt.SecurityEventTTLReconciler{
		Client:             k8sClient,
		Scheme:             scheme,
		WormUploader:       newStubUploader(t),
		TTLConfigNamespace: ns,
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: se.Name}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := &securityv1alpha1.SecurityEvent{}
	err := k8sClient.Get(ctx, client.ObjectKey{Name: se.Name}, got)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected SE archived (TTL=1ns from TTLConfig), got err=%v", err)
	}
}

// TestTTLConfig_MissingFallsBackToDefaults verifies that the absence of
// a TTLConfig in the configured namespace causes the reconciler to use
// the baked-in design-09 defaults. A medium SE with no annotation
// override and creation time "now" must NOT be archived (24h default).
func TestTTLConfig_MissingFallsBackToDefaults(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()

	const ns = "ugallu-test-cfg-missing"
	ensureTTLConfigNamespace(t, ns)

	se := newSE("ttl-cfg-missing", securityv1alpha1.SeverityMedium)
	if err := k8sClient.Create(ctx, se); err != nil {
		t.Fatalf("create SE: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, se) })

	bundle := newSealedBundle(t, "att-se-"+se.Name, se.Name, se.UID)
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, bundle) })

	r := &ttlrt.SecurityEventTTLReconciler{
		Client:             k8sClient,
		Scheme:             scheme,
		WormUploader:       newStubUploader(t),
		TTLConfigNamespace: ns,
	}
	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: se.Name}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("RequeueAfter = %v, want > 0 (24h default not yet expired)", res.RequeueAfter)
	}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: se.Name}, &securityv1alpha1.SecurityEvent{}); err != nil {
		t.Fatalf("SE was archived despite default TTL still pending: %v", err)
	}
}
