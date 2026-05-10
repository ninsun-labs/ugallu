// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WORMConfigSpec is the runtime config for the WORM adapter.
type WORMConfigSpec struct {
	// +kubebuilder:default=seaweedfs
	Backend WORMBackend `json:"backend,omitempty"`

	Endpoint string `json:"endpoint"`
	Region   string `json:"region,omitempty"`
	Bucket   string `json:"bucket"`

	CredentialsSecretRef *corev1.LocalObjectReference `json:"credentialsSecretRef,omitempty"`

	Encryption EncryptionConfig `json:"encryption"`

	Retention RetentionConfig `json:"retention"`

	Multipart MultipartConfig `json:"multipart,omitempty"`

	Quotas QuotaConfig `json:"quotas,omitempty"`
}

// EncryptionConfig is the at-rest encryption mode.
type EncryptionConfig struct {
	// +kubebuilder:default=sse-kms
	Mode     EncryptionMode `json:"mode,omitempty"`
	KMSKeyID string         `json:"kmsKeyID,omitempty"`
}

// RetentionConfig holds per-evidence retention defaults.
type RetentionConfig struct {
	// Bundle minimum retention (parent SecurityEvent/EventResponse TTL + 7d).
	Bundle metav1.Duration `json:"bundle,omitempty"`

	// ForensicsFs retention for filesystem snapshots (default 1y).
	ForensicsFs metav1.Duration `json:"forensicsFs,omitempty"`

	// ForensicsMem retention for memory snapshots (default 1y).
	ForensicsMem metav1.Duration `json:"forensicsMem,omitempty"`

	// SubjectTier2 retention for full subject snapshots (default 90d).
	SubjectTier2 metav1.Duration `json:"subjectTier2,omitempty"`

	// AuditCapture retention for audit log chunks (default 1y).
	AuditCapture metav1.Duration `json:"auditCapture,omitempty"`

	// AppliedPolicy retention for policy YAML records (default = parent).
	AppliedPolicy metav1.Duration `json:"appliedPolicy,omitempty"`

	// HardCapMax safety bound on any retention (default 7y).
	HardCapMax metav1.Duration `json:"hardCapMax,omitempty"`
}

// MultipartConfig tunes S3 multi-part upload behaviour.
type MultipartConfig struct {
	Threshold   *resource.Quantity `json:"threshold,omitempty"`
	ChunkSize   *resource.Quantity `json:"chunkSize,omitempty"`
	Concurrency int                `json:"concurrency,omitempty"`
}

// QuotaConfig sets a soft-quota threshold to emit anomalies.
type QuotaConfig struct {
	// +kubebuilder:default=80
	SoftQuotaPercent int `json:"softQuotaPercent,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=wormcfg
// +kubebuilder:printcolumn:name="Backend",type=string,JSONPath=`.spec.backend`
// +kubebuilder:printcolumn:name="Bucket",type=string,JSONPath=`.spec.bucket`
// +kubebuilder:printcolumn:name="Encryption",type=string,JSONPath=`.spec.encryption.mode`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WORMConfig is the namespaced config CR for the WORM adapter.
type WORMConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec WORMConfigSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// WORMConfigList is the list type for WORMConfig.
type WORMConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WORMConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WORMConfig{}, &WORMConfigList{})
}
