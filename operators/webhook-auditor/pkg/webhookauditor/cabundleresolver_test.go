// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor

import (
	"bytes"
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFindIndirectRef(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        *IndirectRef
		wantErr     bool
	}{
		{"absent", map[string]string{"foo": "bar"}, nil, false},
		{"empty annotations", nil, nil, false},
		{"valid", map[string]string{AnnotationCertManagerInjectFromSecret: "cert-manager/ca-bundle"}, &IndirectRef{Namespace: "cert-manager", Name: "ca-bundle"}, false},
		{"trimmed", map[string]string{AnnotationCertManagerInjectFromSecret: "  cert-manager/ca-bundle  "}, &IndirectRef{Namespace: "cert-manager", Name: "ca-bundle"}, false},
		{"missing slash", map[string]string{AnnotationCertManagerInjectFromSecret: "cert-manager-ca-bundle"}, nil, true},
		{"empty ns", map[string]string{AnnotationCertManagerInjectFromSecret: "/ca-bundle"}, nil, true},
		{"empty name", map[string]string{AnnotationCertManagerInjectFromSecret: "cert-manager/"}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FindIndirectRef(tc.annotations)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.want == nil {
				if got != nil {
					t.Errorf("want nil, got %+v", got)
				}
				return
			}
			if got == nil || got.Namespace != tc.want.Namespace || got.Name != tc.want.Name {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestCABundleResolver_Resolve(t *testing.T) {
	pemBytes := generateSelfSignedPEM(t, "trusted-ca")

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)

	secretCertManager := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "cert-manager", Name: "ca-bundle"},
		Data:       map[string][]byte{"ca.crt": pemBytes},
	}
	secretTLS := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "tls-ca"},
		Data:       map[string][]byte{"tls.crt": pemBytes},
	}
	secretEmpty := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "cert-manager", Name: "no-keys"},
		Data:       map[string][]byte{"unrecognised": []byte("garbage")},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secretCertManager, secretTLS, secretEmpty).
		Build()

	allowed := []string{"cert-manager", "kube-system"}
	r := NewCABundleResolver(c, allowed)

	t.Run("ca.crt key", func(t *testing.T) {
		got, err := r.Resolve(context.Background(), &IndirectRef{Namespace: "cert-manager", Name: "ca-bundle"})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if !bytes.Equal(got, pemBytes) {
			t.Errorf("got %d bytes, want %d", len(got), len(pemBytes))
		}
	})

	t.Run("tls.crt fallback key", func(t *testing.T) {
		got, err := r.Resolve(context.Background(), &IndirectRef{Namespace: "kube-system", Name: "tls-ca"})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if !bytes.Equal(got, pemBytes) {
			t.Errorf("tls.crt path failed")
		}
	})

	t.Run("forbidden namespace", func(t *testing.T) {
		_, err := r.Resolve(context.Background(), &IndirectRef{Namespace: "kyverno-system", Name: "anything"})
		if !errors.Is(err, ErrIndirectRefForbidden) {
			t.Errorf("err = %v, want ErrIndirectRefForbidden", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := r.Resolve(context.Background(), &IndirectRef{Namespace: "cert-manager", Name: "missing"})
		if err == nil {
			t.Error("expected not-found error, got nil")
		}
	})

	t.Run("no recognised key", func(t *testing.T) {
		_, err := r.Resolve(context.Background(), &IndirectRef{Namespace: "cert-manager", Name: "no-keys"})
		if err == nil {
			t.Error("expected no-key error, got nil")
		}
	})
}

func TestResolveOrEmpty(t *testing.T) {
	pemBytes := generateSelfSignedPEM(t, "trusted-ca")

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "cert-manager", Name: "ca-bundle"},
		Data:       map[string][]byte{"ca.crt": pemBytes},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	r := NewCABundleResolver(c, []string{"cert-manager"})

	t.Run("direct caBundle wins", func(t *testing.T) {
		got := r.ResolveOrEmpty(context.Background(), pemBytes, map[string]string{
			AnnotationCertManagerInjectFromSecret: "cert-manager/ca-bundle",
		}, nil)
		if !bytes.Equal(got, pemBytes) {
			t.Error("direct caBundle should win over annotation")
		}
	})

	t.Run("annotation deref happy", func(t *testing.T) {
		got := r.ResolveOrEmpty(context.Background(), nil, map[string]string{
			AnnotationCertManagerInjectFromSecret: "cert-manager/ca-bundle",
		}, nil)
		if !bytes.Equal(got, pemBytes) {
			t.Errorf("got %d bytes, want %d", len(got), len(pemBytes))
		}
	})

	t.Run("forbidden namespace falls back to caBundle", func(t *testing.T) {
		var fallbackReason string
		got := r.ResolveOrEmpty(context.Background(), nil, map[string]string{
			AnnotationCertManagerInjectFromSecret: "kyverno/ca",
		}, func(reason string) { fallbackReason = reason })
		if got != nil {
			t.Errorf("got %d bytes, want nil (fallback)", len(got))
		}
		if fallbackReason != "namespace_forbidden" {
			t.Errorf("fallback reason = %q, want namespace_forbidden", fallbackReason)
		}
	})

	t.Run("nil resolver", func(t *testing.T) {
		var nilR *CABundleResolver
		var fallbackReason string
		got := nilR.ResolveOrEmpty(context.Background(), nil, map[string]string{
			AnnotationCertManagerInjectFromSecret: "cert-manager/ca-bundle",
		}, func(reason string) { fallbackReason = reason })
		if got != nil {
			t.Errorf("nil resolver should return original bytes, got %d", len(got))
		}
		if fallbackReason != "resolver_disabled" {
			t.Errorf("fallback reason = %q, want resolver_disabled", fallbackReason)
		}
	})
}

// silence unused — fake client import
var _ = client.Object(&corev1.Secret{})
