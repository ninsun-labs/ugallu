// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AnnotationCertManagerInjectFromSecret is the cert-manager-canonical
// annotation that points at a Secret holding the CA bundle to inject
// into a MutatingWebhookConfiguration / ValidatingWebhookConfiguration
// at create time. Format: "<namespace>/<name>".
//
// Followed when MWC.spec.webhooks[i].clientConfig.caBundle is empty so
// webhooks managed by cert-manager are scored on the CA they're about
// to be injected with, not as untrusted.
const AnnotationCertManagerInjectFromSecret = "cert-manager.io/inject-ca-from-secret" //nolint:gosec // annotation key, not a credential

// CABundleResolver dereferences indirect caBundle references when the
// webhook's clientConfig.caBundle is empty. It is the bridge between
// the on-CR-spec analysis (cabundle.go AnalyzeCABundle) and the
// real-world fact that cert-manager injects the bundle out-of-band.
//
// Concurrent-safe: the underlying client.Reader is.
type CABundleResolver struct {
	// Reader is a non-cached reader (mgr.GetAPIReader()) to avoid
	// pre-loading every Secret in the cluster into the controller-runtime
	// cache. Each lookup is one apiserver round-trip; the operator
	// only calls it on webhooks with empty caBundle, which is rare in
	// healthy clusters (Wave 3 §W3.1).
	Reader client.Reader

	// AllowedNamespaces is the trustedCASources allowlist from
	// WebhookAuditorConfig.spec.trustedCASources. A reference outside
	// this set is rejected — protects against a malicious MWC pointing
	// at an attacker-controlled Secret.
	AllowedNamespaces map[string]struct{}
}

// NewCABundleResolver builds a resolver from the WebhookAuditorConfig
// spec values. Empty allowedNamespaces means "no indirect deref" —
// every empty caBundle is treated as untrusted (the conservative
// default the operator runs with when the admin hasn't configured
// trustedCASources).
func NewCABundleResolver(reader client.Reader, allowedNamespaces []string) *CABundleResolver {
	allow := make(map[string]struct{}, len(allowedNamespaces))
	for _, ns := range allowedNamespaces {
		allow[ns] = struct{}{}
	}
	return &CABundleResolver{
		Reader:            reader,
		AllowedNamespaces: allow,
	}
}

// IndirectRef is the parsed result of inspecting webhook annotations
// for cert-manager-style indirect CA injection.
type IndirectRef struct {
	Namespace string
	Name      string
}

// FindIndirectRef inspects the webhook configuration's metadata
// annotations for `cert-manager.io/inject-ca-from-secret`. Returns
// (nil, nil) when the annotation is absent.
func FindIndirectRef(annotations map[string]string) (*IndirectRef, error) {
	v, ok := annotations[AnnotationCertManagerInjectFromSecret]
	if !ok {
		return nil, nil
	}
	parts := strings.SplitN(strings.TrimSpace(v), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("annotation %s value %q: expected <namespace>/<name>",
			AnnotationCertManagerInjectFromSecret, v)
	}
	return &IndirectRef{Namespace: parts[0], Name: parts[1]}, nil
}

// ErrIndirectRefForbidden is returned when the indirect Secret lives
// in a namespace not listed in trustedCASources. Treated by the
// scorer the same as an empty caBundle (untrusted).
var ErrIndirectRefForbidden = errors.New("indirect caBundle reference outside trustedCASources allowlist")

// Resolve looks up the Secret pointed at by ref and extracts the CA
// PEM material. Returns the bytes ready to pass to AnalyzeCABundle.
//
// Tries data keys in order: "ca.crt" (cert-manager canonical),
// "tls.crt" (kubernetes.io/tls Secret), "ca.pem" (legacy). The first
// non-empty key wins.
//
// Returns ErrIndirectRefForbidden when ref.Namespace is not in
// AllowedNamespaces (defense in depth even though the RBAC is
// already namespace-scoped).
func (r *CABundleResolver) Resolve(ctx context.Context, ref *IndirectRef) ([]byte, error) {
	if r == nil || r.Reader == nil {
		return nil, errors.New("CABundleResolver: nil reader")
	}
	if ref == nil {
		return nil, errors.New("CABundleResolver.Resolve: nil ref")
	}
	if _, ok := r.AllowedNamespaces[ref.Namespace]; !ok {
		return nil, fmt.Errorf("namespace %q: %w", ref.Namespace, ErrIndirectRefForbidden)
	}
	sec := &corev1.Secret{}
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, sec); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("secret %s/%s not found", ref.Namespace, ref.Name)
		}
		return nil, fmt.Errorf("secret %s/%s get: %w", ref.Namespace, ref.Name, err)
	}
	for _, key := range []string{"ca.crt", "tls.crt", "ca.pem"} {
		if v, ok := sec.Data[key]; ok && len(v) > 0 {
			return v, nil
		}
	}
	return nil, fmt.Errorf("secret %s/%s: no recognised CA key (ca.crt / tls.crt / ca.pem)", ref.Namespace, ref.Name)
}

// ResolveOrEmpty is the helper the Evaluator uses: given a
// (caBundleOnSpec, annotations) pair, returns the bytes that should
// be analysed. Falls back to caBundleOnSpec when annotations are
// absent or invalid; logs the fallback decision via the optional
// onFallback hook so the operator metrics can count
// indirect-ref failures.
func (r *CABundleResolver) ResolveOrEmpty(ctx context.Context, caBundleOnSpec []byte, annotations map[string]string, onFallback func(reason string)) []byte {
	if strings.TrimSpace(string(caBundleOnSpec)) != "" {
		return caBundleOnSpec // direct caBundle wins
	}
	ref, err := FindIndirectRef(annotations)
	if err != nil {
		if onFallback != nil {
			onFallback("annotation_parse_error")
		}
		return caBundleOnSpec
	}
	if ref == nil {
		return caBundleOnSpec
	}
	if r == nil {
		if onFallback != nil {
			onFallback("resolver_disabled")
		}
		return caBundleOnSpec
	}
	bytes, err := r.Resolve(ctx, ref)
	if err != nil {
		reason := "resolve_error"
		if errors.Is(err, ErrIndirectRefForbidden) {
			reason = "namespace_forbidden"
		}
		if onFallback != nil {
			onFallback(reason)
		}
		return caBundleOnSpec
	}
	return bytes
}
