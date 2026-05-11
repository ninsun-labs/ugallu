// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SeccompTrainingRunSpec is the runtime config the ugallu-seccomp-gen
// operator reads to drive a seccomp-profile training session.
type SeccompTrainingRunSpec struct {
	// TargetSelector picks the Pods whose syscall surface is recorded
	// during the training window. Empty selector matches every Pod
	// in the target namespace - discouraged.
	TargetSelector metav1.LabelSelector `json:"targetSelector"`

	// TargetNamespace scopes the selector. Required.
	TargetNamespace string `json:"targetNamespace"`

	// Duration is how long the operator records before finalising
	// the profile. Bounded server-side at 24h (admission policy 13)
	// to cap the privileged Tetragon TracingPolicy lifetime.
	// +kubebuilder:default="30m"
	Duration metav1.Duration `json:"duration"`

	// ReplicaRatio is the fraction of matching Pods that participate
	// in the training (0.0..1.0, expressed as percentage 0..100).
	// Production-friendly default is 50% - half the replicas continue
	// serving traffic with the existing profile while the other half
	// run the training. Admission policy 13 rejects ratios > 100 OR
	// configurations that would leave fewer than 1 untrained Pod
	// when matched-replicas >= 2.
	// +kubebuilder:default=50
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	ReplicaRatio int `json:"replicaRatio"`

	// BridgeEndpoint overrides the in-cluster tetragon-bridge service
	// address. Empty falls back to
	// "ugallu-tetragon-bridge.ugallu-system-privileged.svc:50051".
	// +optional
	BridgeEndpoint string `json:"bridgeEndpoint,omitempty"`

	// DefaultAction stamped on the produced seccomp.json for every
	// syscall not observed during training.
	// +kubebuilder:default=SCMP_ACT_ERRNO
	// +kubebuilder:validation:Enum=SCMP_ACT_ERRNO;SCMP_ACT_KILL;SCMP_ACT_LOG;SCMP_ACT_TRACE
	DefaultAction string `json:"defaultAction"`
}

// SeccompTrainingRunStatus tracks the per-run lifecycle.
type SeccompTrainingRunStatus struct {
	// Phase is the canonical lifecycle state.
	// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed
	Phase string `json:"phase,omitempty"`

	// StartTime is when the operator opened the bridge subscription.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the training window closed.
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// ObservedSyscallCount is the number of distinct syscalls
	// recorded during the run. Useful as an at-a-glance "did the
	// training capture anything" signal.
	ObservedSyscallCount int `json:"observedSyscallCount,omitempty"`

	// SelectedReplicas reports how many Pods the engine
	// actually attached to (after ReplicaRatio sampling).
	SelectedReplicas int `json:"selectedReplicas,omitempty"`

	// ProfileRef is the SeccompTrainingProfile the run produced.
	// Empty until Phase=Succeeded.
	// +optional
	ProfileRef *LocalProfileRef `json:"profileRef,omitempty"`

	// Conditions surface human-readable status (e.g. why a run
	// failed). Standard k8s convention; Type values are
	// "Ready", "Degraded", "Failed".
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// LocalProfileRef points to a SeccompTrainingProfile in the same
// namespace as the run.
type LocalProfileRef struct {
	Name string `json:"name"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=str
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Selected",type="integer",JSONPath=".status.selectedReplicas"
// +kubebuilder:printcolumn:name="Syscalls",type="integer",JSONPath=".status.observedSyscallCount"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// SeccompTrainingRun is one training session. Cluster admin creates
// it; the operator drives it to completion and writes the produced
// SeccompTrainingProfile in the same namespace.
type SeccompTrainingRun struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SeccompTrainingRunSpec   `json:"spec"`
	Status SeccompTrainingRunStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SeccompTrainingRunList contains a list of SeccompTrainingRun.
type SeccompTrainingRunList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SeccompTrainingRun `json:"items"`
}

// SeccompTrainingProfileSpec is the produced seccomp.json plus the
// metadata callers need to bind it to a Pod.
type SeccompTrainingProfileSpec struct {
	// ProfileJSON is the complete OCI-runtime seccomp profile, in
	// JSON form, the runtime applies via runtime/default-fallback.
	// Stored as raw bytes so the round-trip through the API server
	// doesn't reorder syscall arrays.
	ProfileJSON []byte `json:"profileJSON"`

	// DerivedFromRun is the SeccompTrainingRun that produced this
	// profile. Same namespace.
	DerivedFromRun LocalProfileRef `json:"derivedFromRun"`

	// DefaultAction is the action stamped on every syscall not
	// listed in the profile (mirrors the run's DefaultAction).
	// +kubebuilder:validation:Enum=SCMP_ACT_ERRNO;SCMP_ACT_KILL;SCMP_ACT_LOG;SCMP_ACT_TRACE
	DefaultAction string `json:"defaultAction"`

	// PodSelector is the label selector the profile applier (a
	// ValidatingAdmissionPolicy in mutating mode) uses to decide
	// which incoming Pods receive the profile via the
	// PodSpec.SecurityContext.SeccompProfile localhost path.
	PodSelector metav1.LabelSelector `json:"podSelector,omitempty"`
}

// SeccompTrainingProfileStatus tracks how widely the profile is
// applied. Updated by the applier.
type SeccompTrainingProfileStatus struct {
	// AppliedPodCount is the number of Pods the applier has injected
	// the profile into since publication.
	AppliedPodCount int `json:"appliedPodCount,omitempty"`

	// LastAppliedAt is the most recent injection timestamp.
	// +optional
	LastAppliedAt *metav1.Time `json:"lastAppliedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=stp
// +kubebuilder:printcolumn:name="Run",type="string",JSONPath=".spec.derivedFromRun.name"
// +kubebuilder:printcolumn:name="Applied",type="integer",JSONPath=".status.appliedPodCount"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// SeccompTrainingProfile is the seccomp.json output of a training
// run. Lives in the same namespace as the run that produced it.
type SeccompTrainingProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SeccompTrainingProfileSpec   `json:"spec"`
	Status SeccompTrainingProfileStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SeccompTrainingProfileList contains a list of SeccompTrainingProfile.
type SeccompTrainingProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SeccompTrainingProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SeccompTrainingRun{}, &SeccompTrainingRunList{})
	SchemeBuilder.Register(&SeccompTrainingProfile{}, &SeccompTrainingProfileList{})
}
