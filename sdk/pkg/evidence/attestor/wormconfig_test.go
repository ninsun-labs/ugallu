// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor_test

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/attestor"
)

// TestLoadWORMConfig_PrefersDefault verifies that when multiple
// WORMConfig CRs exist, "default" is preferred.
func TestLoadWORMConfig_PrefersDefault(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()
	const ns = "ugallu-test-wormcfg-default"
	ensureNamespace(t, ns)

	other := &securityv1alpha1.WORMConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "secondary", Namespace: ns},
		Spec: securityv1alpha1.WORMConfigSpec{
			Backend:  securityv1alpha1.WORMBackendAWSS3,
			Endpoint: "https://other.example/s3",
			Bucket:   "other-bucket",
			Encryption: securityv1alpha1.EncryptionConfig{
				Mode: securityv1alpha1.EncryptionSSEKMS,
			},
		},
	}
	if err := k8sClient.Create(ctx, other); err != nil {
		t.Fatalf("create secondary: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, other) })

	def := &securityv1alpha1.WORMConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: ns},
		Spec: securityv1alpha1.WORMConfigSpec{
			Backend:  securityv1alpha1.WORMBackendSeaweedFS,
			Endpoint: "https://default.example/s3",
			Bucket:   "default-bucket",
			Encryption: securityv1alpha1.EncryptionConfig{
				Mode: securityv1alpha1.EncryptionSSEKMS,
			},
		},
	}
	if err := k8sClient.Create(ctx, def); err != nil {
		t.Fatalf("create default: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, def) })

	got, err := attestor.LoadWORMConfig(ctx, k8sClient, ns)
	if err != nil {
		t.Fatalf("LoadWORMConfig: %v", err)
	}
	if got == nil {
		t.Fatal("got nil spec, want default")
	}
	if got.Backend != securityv1alpha1.WORMBackendSeaweedFS {
		t.Errorf("Backend = %q, want seaweedfs (the default CR's backend)", got.Backend)
	}
	if got.Bucket != "default-bucket" {
		t.Errorf("Bucket = %q, want default-bucket", got.Bucket)
	}
}

// TestLoadWORMConfig_MissingReturnsNil verifies the no-config path.
func TestLoadWORMConfig_MissingReturnsNil(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()
	const ns = "ugallu-test-wormcfg-missing"
	ensureNamespace(t, ns)

	got, err := attestor.LoadWORMConfig(ctx, k8sClient, ns)
	if err != nil {
		t.Fatalf("LoadWORMConfig: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil spec, got %+v", got)
	}
}

// TestResolveWORMCredentials_FromSecret verifies the access-key +
// secret-key fields are pulled from the referenced Secret.
func TestResolveWORMCredentials_FromSecret(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()
	const ns = "ugallu-test-wormcfg-creds"
	ensureNamespace(t, ns)

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "worm-creds", Namespace: ns},
		Data: map[string][]byte{
			attestor.WORMCredentialsAccessKeyField: []byte("AKIA-test"),
			attestor.WORMCredentialsSecretKeyField: []byte("super-secret"),
		},
	}
	if err := k8sClient.Create(ctx, sec); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, sec) })

	spec := &securityv1alpha1.WORMConfigSpec{
		CredentialsSecretRef: &corev1.LocalObjectReference{Name: "worm-creds"},
	}
	access, secret, err := attestor.ResolveWORMCredentials(ctx, k8sClient, ns, spec)
	if err != nil {
		t.Fatalf("ResolveWORMCredentials: %v", err)
	}
	if access != "AKIA-test" || secret != "super-secret" {
		t.Errorf("got (%q, %q), want (AKIA-test, super-secret)", access, secret)
	}
}

// TestResolveWORMCredentials_NilSpec returns empty without error so the
// caller can fall back to the AWS credential chain.
func TestResolveWORMCredentials_NilSpec(t *testing.T) {
	access, secret, err := attestor.ResolveWORMCredentials(nil, nil, "ns", nil) //nolint:staticcheck // exercises nil-spec branch
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if access != "" || secret != "" {
		t.Errorf("expected empty creds, got (%q, %q)", access, secret)
	}
}

// TestResolveWORMCredentials_MissingSecret surfaces a clear error when
// the referenced Secret is absent.
func TestResolveWORMCredentials_MissingSecret(t *testing.T) {
	if cfg == nil {
		t.Skip("envtest not started")
	}
	ctx := ctxT()
	const ns = "ugallu-test-wormcfg-missing-secret"
	ensureNamespace(t, ns)

	spec := &securityv1alpha1.WORMConfigSpec{
		CredentialsSecretRef: &corev1.LocalObjectReference{Name: "does-not-exist"},
	}
	if _, _, err := attestor.ResolveWORMCredentials(ctx, k8sClient, ns, spec); err == nil {
		t.Fatal("expected error for missing secret")
	}
}
