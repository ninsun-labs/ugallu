// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AttestationBundleSpec is the immutable signing assignment.
// One bundle attests one primary fact (design 05 A1: per-fact, not per-incident).
type AttestationBundleSpec struct {
	// AttestedFor points at the SecurityEvent or EventResponse being signed.
	AttestedFor corev1.ObjectReference `json:"attestedFor"`

	// ParentBundleRef is optional, used for re-attest / closure / redaction record.
	ParentBundleRef *corev1.ObjectReference `json:"parentBundleRef,omitempty"`
}

// AttestationBundleStatus is the mutable pipeline state of the bundle.
type AttestationBundleStatus struct {
	// Phase reflects the pipeline progression: Pending -> Signed -> Logged -> Sealed.
	Phase AttestationBundlePhase `json:"phase,omitempty"`

	// StatementDigest is the sha256 of the canonicalized in-toto Statement.
	StatementDigest string `json:"statementDigest,omitempty"`

	// Signature carries metadata about the cryptographic signature applied.
	Signature *SignatureInfo `json:"signature,omitempty"`

	// RekorEntry is the transparency log entry for this bundle.
	RekorEntry *RekorEntry `json:"rekorEntry,omitempty"`

	// WormRef points at the DSSE envelope archived to WORM.
	WormRef *EvidenceRef `json:"wormRef,omitempty"`

	// SignedAt is when signing succeeded.
	SignedAt *metav1.Time `json:"signedAt,omitempty"`

	// SealedAt is when the bundle reached the terminal Sealed phase.
	SealedAt *metav1.Time `json:"sealedAt,omitempty"`

	// Failures records errors encountered during pipeline stages.
	Failures []PipelineFailure `json:"failures,omitempty"`

	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// SignatureInfo describes the signing mode and key fingerprint used.
type SignatureInfo struct {
	Mode  SigningMode `json:"mode"`
	KeyID string      `json:"keyID,omitempty"`
}

// RekorEntry is the inclusion proof in the Rekor transparency log.
type RekorEntry struct {
	LogIndex       int64           `json:"logIndex"`
	UUID           string          `json:"uuid"`
	InclusionProof *InclusionProof `json:"inclusionProof,omitempty"`
}

// InclusionProof is the Merkle proof returned by Rekor.
type InclusionProof struct {
	TreeSize int64    `json:"treeSize"`
	LogIndex int64    `json:"logIndex"`
	RootHash string   `json:"rootHash,omitempty"`
	Hashes   []string `json:"hashes,omitempty"`
}

// PipelineFailure records a single stage failure for diagnostics.
type PipelineFailure struct {
	Stage     string      `json:"stage"`
	Reason    string      `json:"reason,omitempty"`
	Detail    string      `json:"detail,omitempty"`
	Timestamp metav1.Time `json:"timestamp"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=ab
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="For",type=string,JSONPath=`.spec.attestedFor.kind`
// +kubebuilder:printcolumn:name="Subject",type=string,JSONPath=`.spec.attestedFor.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.status.signature.mode`
// +kubebuilder:printcolumn:name="RekorIndex",type=integer,JSONPath=`.status.rekorEntry.logIndex`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AttestationBundle is the signed in-toto attestation of a primary fact
// (SecurityEvent or EventResponse). Cluster-scoped.
type AttestationBundle struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AttestationBundleSpec   `json:"spec,omitempty"`
	Status AttestationBundleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AttestationBundleList is the list type for AttestationBundle.
type AttestationBundleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AttestationBundle `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AttestationBundle{}, &AttestationBundleList{})
}
