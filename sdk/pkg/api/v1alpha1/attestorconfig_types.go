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
	Issuer    string `json:"issuer"`
	FulcioURL string `json:"fulcioURL"`
}

// OpenBaoConfig describes the OpenBao transit endpoint and key.
type OpenBaoConfig struct {
	Address      string `json:"address"`
	TransitMount string `json:"transitMount"`
	KeyName      string `json:"keyName"`
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
