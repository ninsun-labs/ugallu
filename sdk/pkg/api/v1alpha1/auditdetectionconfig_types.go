// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AuditDetectionConfigSpec is the runtime config the
// ugallu-audit-detection operator reads. The CR is optional: the
// operator originally shipped without it (everything via cmd flags).
// The event-bus gRPC stream lets other operators (tenant-escape,
// future reasoners) subscribe to the AuditEvent stream the sigma
// engine already consumes.
//
// Backwards-compatible: when the CR is absent, audit-detection runs
// without the gRPC bus. When present with EventBus.Enabled false,
// same. When EventBus.Enabled=true, the operator exposes the stream
// and applies the per-consumer filter and rate limit.
type AuditDetectionConfigSpec struct {
	// EventBus exposes the audit-event stream as a server-streaming
	// gRPC. Disabled by default for backwards compatibility.
	// +optional
	EventBus AuditDetectionEventBus `json:"eventBus,omitempty"`

	// Consumers declares the operators authorised to subscribe.
	// Empty when the bus is disabled. Each consumer pulls events
	// matching its filter + capped at MaxEventsPerSec.
	// +optional
	Consumers []AuditDetectionConsumer `json:"consumers,omitempty"`
}

// AuditDetectionEventBus configures the gRPC event-bus endpoint.
type AuditDetectionEventBus struct {
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// ListenAddr is the gRPC bind address (e.g. ":8444").
	// +kubebuilder:default=":8444"
	ListenAddr string `json:"listenAddr,omitempty"`

	// TokenSecret references the bearer-token Secret used for
	// consumer auth (mTLS lands as a follow-up). When unset, the bus
	// runs without auth (lab-only).
	// +optional
	TokenSecret *corev1.SecretKeySelector `json:"tokenSecret,omitempty"`
}

// AuditDetectionConsumer is one subscriber declaration.
type AuditDetectionConsumer struct {
	// Name is the human-readable consumer id (e.g. "tenant-escape").
	// Surfaced in metrics labels.
	Name string `json:"name"`

	// Filter narrows the event stream server-side. Empty filter =
	// every event.
	// +optional
	Filter AuditDetectionConsumerFilter `json:"filter,omitempty"`

	// MaxEventsPerSec caps the per-consumer rate. Zero = no cap
	// (server still applies its global token bucket).
	// +optional
	MaxEventsPerSec uint32 `json:"maxEventsPerSec,omitempty"`
}

// AuditDetectionConsumerFilter prunes the event stream before it
// reaches the consumer.
type AuditDetectionConsumerFilter struct {
	// ObjectRefHasNamespace, when true, drops cluster-scoped events.
	// Useful for tenant-escape (only namespaced subjects matter).
	// +optional
	ObjectRefHasNamespace bool `json:"objectRefHasNamespace,omitempty"`

	// VerbAllowlist constrains the verbs forwarded. Empty = match-all.
	// +optional
	VerbAllowlist []string `json:"verbAllowlist,omitempty"`
}

// AuditDetectionConfigStatus surfaces operator-side state.
type AuditDetectionConfigStatus struct {
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastConfigLoadAt marks the most recent successful spec read.
	LastConfigLoadAt *metav1.Time `json:"lastConfigLoadAt,omitempty"`

	// ConsumersConnected is the live count of bus subscribers.
	ConsumersConnected int32 `json:"consumersConnected,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=auditdetectioncfg
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="BusEnabled",type=boolean,JSONPath=`.spec.eventBus.enabled`
// +kubebuilder:printcolumn:name="Consumers",type=integer,JSONPath=`.status.consumersConnected`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AuditDetectionConfig is the cluster-scoped singleton (name="default")
// that governs the ugallu-audit-detection operator.
type AuditDetectionConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuditDetectionConfigSpec   `json:"spec,omitempty"`
	Status AuditDetectionConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AuditDetectionConfigList is the list type for AuditDetectionConfig.
type AuditDetectionConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuditDetectionConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AuditDetectionConfig{}, &AuditDetectionConfigList{})
}
