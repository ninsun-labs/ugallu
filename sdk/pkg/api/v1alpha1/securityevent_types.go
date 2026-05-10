// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecurityEventSpec is the immutable description of a security-relevant fact.
// All fields are set at emit and never modified post-creation (enforced by
// admission policy).
type SecurityEventSpec struct {
	// Class is the closed taxonomy class (D1).
	Class Class `json:"class"`

	// Type is the curated catalog type. Validated by admission policy
	// against the SDK constants list, with override label for experiments.
	Type string `json:"type"`

	// Severity is the 5-grade scale (D7).
	Severity Severity `json:"severity"`

	// ClusterIdentity carries multi-cluster identity (D4).
	ClusterIdentity ClusterIdentity `json:"clusterIdentity"`

	// Source identifies the controller that emitted the event.
	Source SourceRef `json:"source"`

	// Subject is the K8s object snapshot (Tier-1) that the event is about.
	Subject SubjectTier1 `json:"subject"`

	// DetectedAt is the wall-clock observation timestamp from the source.
	DetectedAt metav1.Time `json:"detectedAt"`

	// Signals are unstructured key-value facts about the observation (<= 8KB).
	// +kubebuilder:validation:MaxProperties=128
	Signals map[string]string `json:"signals,omitempty"`

	// Evidence references blobs in WORM (DSSE, snapshots, attached policy, etc.).
	Evidence []EvidenceRef `json:"evidence,omitempty"`

	// Parents are predecessor SecurityEvents in the correlation graph
	// (used by reasoners that emit Class=Anomaly events).
	Parents []corev1.ObjectReference `json:"parents,omitempty"`

	// CorrelationID is a free-form group identifier shared by related events.
	CorrelationID string `json:"correlationID,omitempty"`

	// TraceParent is a W3C traceparent for cross-operator distributed tracing.
	TraceParent string `json:"traceparent,omitempty"`
}

// SecurityEventStatus is the mutable lifecycle metadata.
// Status updates are restricted by RBAC + admission policy.
type SecurityEventStatus struct {
	// Phase is the lifecycle phase (Active -> Attested -> Archived).
	Phase SecurityEventPhase `json:"phase,omitempty"`

	// Acknowledged marks human-driven incident closure (admission-policy gated).
	Acknowledged bool `json:"acknowledged,omitempty"`

	// AcknowledgedBy is the SA / username that performed the ack.
	AcknowledgedBy string `json:"acknowledgedBy,omitempty"`

	// AcknowledgedAt is when the ack was performed.
	AcknowledgedAt *metav1.Time `json:"acknowledgedAt,omitempty"`

	// AttestationDigest is the sha256 of the in-toto Statement (set by attestor).
	AttestationDigest string `json:"attestationDigest,omitempty"`

	// AttestationBundleRef points at the AttestationBundle CR.
	AttestationBundleRef *corev1.ObjectReference `json:"attestationBundleRef,omitempty"`

	// ArchivedAt is when the TTL controller persisted the CR snapshot to WORM.
	ArchivedAt *metav1.Time `json:"archivedAt,omitempty"`

	// Conditions are the standard K8s typed conditions.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ClusterIdentity carries the cluster-of-origin (D4 multi-cluster ready).
type ClusterIdentity struct {
	ClusterName string `json:"clusterName,omitempty"`
	ClusterID   string `json:"clusterID,omitempty"`
}

// SourceRef identifies the operator that emitted a SecurityEvent.
type SourceRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Instance   string `json:"instance,omitempty"`
}

// EvidenceRef points at an immutable blob stored in WORM (or external for URLs).
type EvidenceRef struct {
	MediaType string `json:"mediaType"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256,omitempty"`
	Size      int64  `json:"size,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=se
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Class",type=string,JSONPath=`.spec.class`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.spec.severity`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Subject",type=string,JSONPath=`.spec.subject.name`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SecurityEvent is the primary ugallu CRD: an immutable, attested fact
// of security relevance observed in a cluster. Cluster-scoped (D3).
type SecurityEvent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecurityEventSpec   `json:"spec,omitempty"`
	Status SecurityEventStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecurityEventList is the list type for SecurityEvent.
type SecurityEventList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityEvent `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecurityEvent{}, &SecurityEventList{})
}
