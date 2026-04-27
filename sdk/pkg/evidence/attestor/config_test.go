// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor_test

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/attestor"
)

// ensureNamespace makes sure ns exists in envtest.
func ensureNamespace(t *testing.T, name string) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := k8sClient.Create(ctxT(), ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create ns %q: %v", name, err)
	}
}

// TestLoadAttestorConfig_PrefersDefault verifies that when multiple
// AttestorConfig CRs exist, "default" is preferred.
func TestLoadAttestorConfig_PrefersDefault(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()
	const ns = "ugallu-test-attcfg-default"
	ensureNamespace(t, ns)

	other := &securityv1alpha1.AttestorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "secondary", Namespace: ns},
		Spec: securityv1alpha1.AttestorConfigSpec{
			SigningMode: securityv1alpha1.SigningModeFulcioKeyless,
			Rekor:       securityv1alpha1.RekorConfig{Enabled: true, URL: "https://other.example/rekor"},
		},
	}
	if err := k8sClient.Create(ctx, other); err != nil {
		t.Fatalf("create secondary: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, other) })

	def := &securityv1alpha1.AttestorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: ns},
		Spec: securityv1alpha1.AttestorConfigSpec{
			SigningMode: securityv1alpha1.SigningModeOpenBaoTransit,
			Rekor:       securityv1alpha1.RekorConfig{Enabled: true, URL: "https://default.example/rekor"},
		},
	}
	if err := k8sClient.Create(ctx, def); err != nil {
		t.Fatalf("create default: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, def) })

	got, err := attestor.LoadAttestorConfig(ctx, k8sClient, ns)
	if err != nil {
		t.Fatalf("LoadAttestorConfig: %v", err)
	}
	if got == nil {
		t.Fatal("got nil spec, want default")
	}
	if got.SigningMode != securityv1alpha1.SigningModeOpenBaoTransit {
		t.Errorf("SigningMode = %q, want openbao-transit (the default CR's value)", got.SigningMode)
	}
	if got.Rekor.URL != "https://default.example/rekor" {
		t.Errorf("Rekor.URL = %q, want default's URL", got.Rekor.URL)
	}
}

// TestLoadAttestorConfig_MissingReturnsNil verifies the no-config path.
func TestLoadAttestorConfig_MissingReturnsNil(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()
	const ns = "ugallu-test-attcfg-missing"
	ensureNamespace(t, ns)

	got, err := attestor.LoadAttestorConfig(ctx, k8sClient, ns)
	if err != nil {
		t.Fatalf("LoadAttestorConfig: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil spec, got %+v", got)
	}
}
