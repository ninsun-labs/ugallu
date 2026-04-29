// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConfidentialAttestationBackend selects the hardware backend the
// run targets.
// +kubebuilder:validation:Enum=tpm;sev-snp;tdx
type ConfidentialAttestationBackend string

// ConfidentialAttestationBackend constants — all 3 supported from v1.
const (
	// ConfidentialAttestationBackendTPM uses the TPM 2.0 PCR quote
	// over PCRs 0-7 (firmware + bootloader + kernel measurements).
	ConfidentialAttestationBackendTPM ConfidentialAttestationBackend = "tpm"

	// ConfidentialAttestationBackendSEVSNP fetches the AMD SEV-SNP
	// attestation report from the guest's attestation interface.
	ConfidentialAttestationBackendSEVSNP ConfidentialAttestationBackend = "sev-snp"

	// ConfidentialAttestationBackendTDX fetches the Intel TDX guest
	// attestation quote.
	ConfidentialAttestationBackendTDX ConfidentialAttestationBackend = "tdx"
)

// ConfidentialAttestationVerdict is the verifier's decision.
// +kubebuilder:validation:Enum=verified;failed;indeterminate
type ConfidentialAttestationVerdict string

// ConfidentialAttestationVerdict constants.
const (
	// ConfidentialAttestationVerdictVerified — quote signature
	// chained to a trusted root + measurements match the policy.
	ConfidentialAttestationVerdictVerified ConfidentialAttestationVerdict = "verified"
	// ConfidentialAttestationVerdictFailed — chain or measurement
	// check failed; treat the node as untrusted.
	ConfidentialAttestationVerdictFailed ConfidentialAttestationVerdict = "failed"
	// ConfidentialAttestationVerdictIndeterminate — backend is
	// missing on the node (e.g. no TPM device); status is reported
	// without an enforcement decision.
	ConfidentialAttestationVerdictIndeterminate ConfidentialAttestationVerdict = "indeterminate"
)

// ConfidentialAttestationRunSpec is the runtime config the
// ugallu-confidential-attestation operator reads.
type ConfidentialAttestationRunSpec struct {
	// Backend selects the hardware path.
	Backend ConfidentialAttestationBackend `json:"backend"`

	// TargetNodeName pins the node the attester DaemonSet must
	// answer from. Required — a cluster-wide attestation cycle is
	// modelled as N runs, one per node.
	TargetNodeName string `json:"targetNodeName"`

	// Nonce is the caller-provided anti-replay value (32-byte hex
	// recommended). The attester binds the quote to this nonce so
	// a replay-attack with a previously captured quote is rejected.
	Nonce string `json:"nonce"`

	// PolicyRef points to the AttestationPolicy with expected
	// measurements. Empty = "report-only mode": the verifier
	// records the quote but emits an indeterminate verdict.
	// +optional
	PolicyRef *LocalProfileRef `json:"policyRef,omitempty"`

	// Timeout caps the run duration (TPM quote latency is ~1s but
	// the SEV-SNP attestation service may take longer).
	// +kubebuilder:default="2m"
	Timeout metav1.Duration `json:"timeout"`
}

// ConfidentialAttestationRunStatus tracks lifecycle.
type ConfidentialAttestationRunStatus struct {
	// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed
	Phase string `json:"phase,omitempty"`
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
	// ResultRef points to the ConfidentialAttestationResult the
	// run produced. Empty until Phase=Succeeded.
	// +optional
	ResultRef *LocalProfileRef `json:"resultRef,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=conar
// +kubebuilder:printcolumn:name="Backend",type="string",JSONPath=".spec.backend"
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.targetNodeName"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ConfidentialAttestationRun is one attestation cycle on one node.
type ConfidentialAttestationRun struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConfidentialAttestationRunSpec   `json:"spec"`
	Status ConfidentialAttestationRunStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConfidentialAttestationRunList contains a list of ConfidentialAttestationRun.
type ConfidentialAttestationRunList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConfidentialAttestationRun `json:"items"`
}

// ConfidentialAttestationMeasurement is one (slot, digest) pair.
// On TPM the slot is the PCR index (0..23); on SEV-SNP / TDX
// it's the report field name (e.g. "MEASUREMENT", "REPORT_DATA").
type ConfidentialAttestationMeasurement struct {
	Slot   string `json:"slot"`
	Digest string `json:"digest"`
}

// ConfidentialAttestationResultSpec carries the raw evidence + the
// verifier verdict.
type ConfidentialAttestationResultSpec struct {
	// DerivedFromRun is the ConfidentialAttestationRun that
	// produced this result. Same namespace.
	DerivedFromRun LocalProfileRef `json:"derivedFromRun"`

	// Backend mirrors the run's backend.
	Backend ConfidentialAttestationBackend `json:"backend"`

	// NodeName is the node the attester answered from.
	NodeName string `json:"nodeName"`

	// Nonce is the same value the run requested — recorded for
	// audit trail.
	Nonce string `json:"nonce"`

	// Quote is the raw attestation evidence (bytes vary by
	// backend). The verifier consumes this; downstream consumers
	// shouldn't try to parse it without the matching backend SDK.
	// +optional
	Quote []byte `json:"quote,omitempty"`

	// Signature is the quote signature (TPM EK / SNP VLEK / TDX
	// quote signing key). Empty for backends that ship signature
	// inside Quote.
	// +optional
	Signature []byte `json:"signature,omitempty"`

	// Measurements is the per-slot digest summary the verifier
	// extracted from the quote. Useful for human review without
	// reaching into the raw bytes.
	// +optional
	Measurements []ConfidentialAttestationMeasurement `json:"measurements,omitempty"`

	// Verdict is the verifier's decision.
	Verdict ConfidentialAttestationVerdict `json:"verdict"`

	// VerifierNotes carries free-form context (chain check details,
	// missing-device messages on indeterminate verdicts, etc.).
	// +optional
	VerifierNotes string `json:"verifierNotes,omitempty"`
}

// ConfidentialAttestationResultStatus carries the canonical "is the
// node currently trusted" bit, derived from Verdict.
type ConfidentialAttestationResultStatus struct {
	// Trusted is true when Verdict==verified; false otherwise.
	Trusted bool `json:"trusted,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=conares
// +kubebuilder:printcolumn:name="Backend",type="string",JSONPath=".spec.backend"
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".spec.nodeName"
// +kubebuilder:printcolumn:name="Verdict",type="string",JSONPath=".spec.verdict"
// +kubebuilder:printcolumn:name="Trusted",type="boolean",JSONPath=".status.trusted"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ConfidentialAttestationResult is the verifier's per-run report.
// Retained 7d per design (W4-D7) by ugallu-ttl; the linked
// AttestationBundle captures the long-term signed snapshot.
type ConfidentialAttestationResult struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConfidentialAttestationResultSpec   `json:"spec"`
	Status ConfidentialAttestationResultStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConfidentialAttestationResultList contains a list of ConfidentialAttestationResult.
type ConfidentialAttestationResultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConfidentialAttestationResult `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ConfidentialAttestationRun{}, &ConfidentialAttestationRunList{})
	SchemeBuilder.Register(&ConfidentialAttestationResult{}, &ConfidentialAttestationResultList{})
}
