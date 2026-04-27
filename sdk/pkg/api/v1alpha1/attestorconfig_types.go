// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AttestorConfigSpec is the runtime config for the attestor (design 06 S8).
type AttestorConfigSpec struct {
	// SigningMode selects the cryptographic mode: fulcio-keyless, openbao-transit, or dual.
	// +kubebuilder:default=fulcio-keyless
	SigningMode SigningMode `json:"signingMode,omitempty"`

	// Fulcio configures Fulcio keyless signing (used when SigningMode is fulcio-keyless or dual).
	Fulcio *FulcioConfig `json:"fulcio,omitempty"`

	// OpenBao configures OpenBao transit signing (used when SigningMode is openbao-transit or dual).
	OpenBao *OpenBaoConfig `json:"openbao,omitempty"`

	// DualMode tunes dual-sign verification semantics.
	DualMode *DualModeConfig `json:"dualMode,omitempty"`

	// Rekor configures the transparency log endpoint (always uploaded, design 06).
	Rekor RekorConfig `json:"rekor"`
}

// FulcioConfig describes the Fulcio CA + OIDC issuer.
type FulcioConfig struct {
	// Issuer is the OIDC issuer URL (e.g. the K8s API server's
	// well-known issuer, or a SPIFFE/Auth0/etc identity provider).
	Issuer string `json:"issuer"`

	// FulcioURL is the Fulcio v2 CA endpoint base URL.
	FulcioURL string `json:"fulcioURL"`

	// OIDCTokenPath is the file path of the OIDC token presented to
	// Fulcio. Defaults to the projected SA token mount when empty
	// (DefaultFulcioOIDCTokenPath in the SDK).
	OIDCTokenPath string `json:"oidcTokenPath,omitempty"`

	// CABundleSecret references a Secret containing the Fulcio CA
	// trust bundle in key "ca.crt". Empty uses the system trust
	// store (the default for the public Sigstore Fulcio).
	CABundleSecret *SecretReference `json:"caBundleSecret,omitempty"`

	// InsecureSkipVerify disables TLS verification toward Fulcio —
	// dev/lab only.
	// +kubebuilder:default=false
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// OpenBaoConfig describes the OpenBao transit endpoint and key.
type OpenBaoConfig struct {
	// Address is the OpenBao base URL, e.g.
	// "https://openbao.openbao.svc.cluster.local:8200".
	Address string `json:"address"`

	// TransitMount is the path of the transit secrets engine,
	// e.g. "transit".
	// +kubebuilder:default=transit
	TransitMount string `json:"transitMount,omitempty"`

	// KeyName is the transit key used to sign the in-toto Statement
	// PAE. The key MUST be of type ed25519 for ed25519 attestations
	// (the default), or rsa-pss-sha256/ecdsa-p256 for the matching
	// SigningMode variants.
	KeyName string `json:"keyName"`

	// KeyType selects the OpenBao transit key type. Maps to the
	// corresponding signature algorithm. Default ed25519 mirrors
	// the in-process Ed25519Signer.
	// +kubebuilder:default=ed25519
	// +kubebuilder:validation:Enum=ed25519;ecdsa-p256;rsa-pss-2048
	KeyType string `json:"keyType,omitempty"`

	// AuthMount is the path of the Kubernetes auth method,
	// e.g. "auth/kubernetes". Defaults to "auth/kubernetes".
	// +kubebuilder:default=auth/kubernetes
	AuthMount string `json:"authMount,omitempty"`

	// AuthRole is the OpenBao Kubernetes auth role bound to the
	// attestor's ServiceAccount. The role must permit the transit
	// sign + read-key policies on the configured KeyName.
	AuthRole string `json:"authRole"`

	// CABundleSecret references a Secret holding the CA cert that
	// signed the OpenBao server cert (PEM in key "ca.crt"). Empty
	// uses the system CA store.
	CABundleSecret *SecretReference `json:"caBundleSecret,omitempty"`

	// InsecureSkipVerify disables TLS verification — dev/lab only.
	// +kubebuilder:default=false
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// SecretReference is a namespace-scoped Secret pointer.
type SecretReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// DualModeConfig tunes dual-signature verification semantics.
type DualModeConfig struct {
	// RequireAll enforces both signatures valid (default false: OR semantics).
	RequireAll bool `json:"requireAll,omitempty"`
}

// RekorConfig is the transparency log endpoint.
type RekorConfig struct {
	// +kubebuilder:default=true
	Enabled bool   `json:"enabled,omitempty"`
	URL     string `json:"url"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=attcfg
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.signingMode`
// +kubebuilder:printcolumn:name="Rekor",type=string,JSONPath=`.spec.rekor.url`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AttestorConfig is the namespaced config CR for ugallu-attestor.
type AttestorConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AttestorConfigSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// AttestorConfigList is the list type for AttestorConfig.
type AttestorConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AttestorConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AttestorConfig{}, &AttestorConfigList{})
}
