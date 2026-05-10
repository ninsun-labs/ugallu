// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TTLConfigSpec is the runtime config for ugallu-ttl.
type TTLConfigSpec struct {
	Defaults TTLDefaults `json:"defaults"`

	// +kubebuilder:default=true
	ArchiveSnapshotEnabled bool `json:"archiveSnapshotEnabled,omitempty"`

	Postpone PostponeConfig `json:"postpone,omitempty"`

	Worker WorkerConfig `json:"worker,omitempty"`
}

// TTLDefaults holds per-CR TTL windows.
type TTLDefaults struct {
	SecurityEvent     SeverityTTL                `json:"securityEvent"`
	EventResponse     EventResponseTTL           `json:"eventResponse"`
	AttestationBundle AttestationBundleTTLConfig `json:"attestationBundle"`
}

// SeverityTTL is per-severity TTL for SecurityEvent.
type SeverityTTL struct {
	// +kubebuilder:default="6h"
	Info metav1.Duration `json:"info,omitempty"`
	// +kubebuilder:default="12h"
	Low metav1.Duration `json:"low,omitempty"`
	// +kubebuilder:default="24h"
	Medium metav1.Duration `json:"medium,omitempty"`
	// +kubebuilder:default="72h"
	High metav1.Duration `json:"high,omitempty"`
	// +kubebuilder:default="168h"
	Critical metav1.Duration `json:"critical,omitempty"`
}

// EventResponseTTL controls EventResponse retention.
type EventResponseTTL struct {
	// +kubebuilder:default=matchParent
	// +kubebuilder:validation:Enum=matchParent;constant
	Strategy string `json:"strategy,omitempty"`

	// Constant is used when strategy is "constant".
	Constant metav1.Duration `json:"constant,omitempty"`
}

// AttestationBundleTTLConfig controls AttestationBundle retention.
type AttestationBundleTTLConfig struct {
	// +kubebuilder:default=parentPlusGrace
	// +kubebuilder:validation:Enum=parentPlusGrace
	Strategy string `json:"strategy,omitempty"`

	// +kubebuilder:default="168h"
	Grace metav1.Duration `json:"grace,omitempty"`
}

// PostponeConfig tunes the postpone retry behaviour.
type PostponeConfig struct {
	// +kubebuilder:default="1h"
	InitialDelay metav1.Duration `json:"initialDelay,omitempty"`
	// +kubebuilder:default="24h"
	MaxDelay metav1.Duration `json:"maxDelay,omitempty"`
	// +kubebuilder:default=7
	MaxAttempts int `json:"maxAttempts,omitempty"`
}

// WorkerConfig tunes the worker pool.
type WorkerConfig struct {
	// +kubebuilder:default=10
	PoolSize int `json:"poolSize,omitempty"`

	// QueueRateLimit is the max events/sec processed (e.g., "100").
	QueueRateLimit *resource.Quantity `json:"queueRateLimit,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=ttlcfg
// +kubebuilder:printcolumn:name="Critical-TTL",type=string,JSONPath=`.spec.defaults.securityEvent.critical`
// +kubebuilder:printcolumn:name="Pool",type=integer,JSONPath=`.spec.worker.poolSize`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TTLConfig is the namespaced config CR for ugallu-ttl.
type TTLConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec TTLConfigSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// TTLConfigList is the list type for TTLConfig.
type TTLConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TTLConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TTLConfig{}, &TTLConfigList{})
}
