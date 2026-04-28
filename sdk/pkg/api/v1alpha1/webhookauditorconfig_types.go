// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WebhookAuditorConfigSpec is the runtime config the
// ugallu-webhook-auditor operator reads to decide which admission
// webhooks (MutatingWebhookConfiguration / ValidatingWebhookConfiguration)
// to score and what to ignore (design 21 §W3-W4).
type WebhookAuditorConfigSpec struct {
	// RiskThreshold gates SE emission. A webhook with RiskScore strictly
	// below this value does not produce a top-level
	// `MutatingWebhookHighRisk` / `ValidatingWebhookHighRisk` SE; the
	// individual sub-score SEs (e.g. `WebhookCAUntrusted`) still fire
	// when their condition is met.
	// +kubebuilder:default=60
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	RiskThreshold int32 `json:"riskThreshold,omitempty"`

	// Ignore lists name-glob patterns that skip evaluation entirely.
	// Used to whitelist ugallu's own admission policies, cert-manager,
	// and RKE2 system webhooks.
	Ignore []WebhookIgnoreRule `json:"ignore,omitempty"`

	// TrustedSubjectDNs is the canonical RFC 4514 DN allowlist for
	// caBundle CAs. A webhook whose caBundle chain root has a subject
	// DN in this list does NOT trigger the `WebhookCAUntrusted`
	// sub-score. Stable across cert-manager rotations (see §W3.1).
	TrustedSubjectDNs []string `json:"trustedSubjectDNs,omitempty"`

	// TrustedCASources lists namespaces where the operator is allowed
	// to read Secret data to dereference indirect caBundle references.
	// Scope is intentionally narrow: cluster-wide Secret read would
	// blow the cache.DisableFor=Secret guarantee (design 20 §F).
	TrustedCASources []TrustedCASource `json:"trustedCASources,omitempty"`
}

// WebhookIgnoreRule is a single skip-list entry.
type WebhookIgnoreRule struct {
	// APIVersionGlob filters by the webhook configuration apiVersion
	// (e.g. "admissionregistration.k8s.io/v1"). Empty matches any.
	APIVersionGlob string `json:"apiVersionGlob,omitempty"`

	// NameGlobs matches the metadata.name of the MWC/VWC. Glob syntax
	// (`*` wildcard, no regex). Required.
	NameGlobs []string `json:"nameGlobs"`
}

// TrustedCASource is a namespace where indirect caBundle Secrets live.
type TrustedCASource struct {
	// Namespace where the Secret holding the trusted caBundle lives.
	Namespace string `json:"namespace"`
}

// WebhookAuditorConfigStatus surfaces operator-side runtime state for
// kubectl visibility.
type WebhookAuditorConfigStatus struct {
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastConfigLoadAt marks the most recent successful read of the spec.
	LastConfigLoadAt *metav1.Time `json:"lastConfigLoadAt,omitempty"`

	// ObservedWebhooks reports the live MWC+VWC count in the cluster
	// at the most recent reconcile. Drift across reconciles signals
	// admission churn.
	ObservedWebhooks int32 `json:"observedWebhooks,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=webhookauditorcfg
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Threshold",type=integer,JSONPath=`.spec.riskThreshold`
// +kubebuilder:printcolumn:name="Observed",type=integer,JSONPath=`.status.observedWebhooks`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WebhookAuditorConfig is the cluster-scoped singleton (name="default")
// that governs the ugallu-webhook-auditor operator.
type WebhookAuditorConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WebhookAuditorConfigSpec   `json:"spec,omitempty"`
	Status WebhookAuditorConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WebhookAuditorConfigList is the list type for WebhookAuditorConfig.
type WebhookAuditorConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WebhookAuditorConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WebhookAuditorConfig{}, &WebhookAuditorConfigList{})
}
