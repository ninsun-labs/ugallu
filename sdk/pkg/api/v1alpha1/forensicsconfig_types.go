// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ForensicsConfigSpec is the runtime config the ugallu-forensics
// operator reads to decide which SecurityEvents trigger an incident
// capture and how the snapshot pipeline behaves.
type ForensicsConfigSpec struct {
	// Trigger is the predicate evaluated against each incoming SE.
	// All conditions must match for the operator to start a capture.
	Trigger ForensicsTrigger `json:"trigger"`

	// WhitelistedTypes lists the SE Types eligible for capture. Empty
	// list = none (safe default; explicit opt-in only).
	WhitelistedTypes []string `json:"whitelistedTypes,omitempty"`

	// Snapshot tunes the capture pipeline (filesystem, future memory).
	Snapshot SnapshotConfig `json:"snapshot"`

	// Cleanup tunes the post-incident lifecycle (manual / auto
	// unfreeze, ack-allowlist).
	Cleanup CleanupConfig `json:"cleanup,omitempty"`

	// MaxConcurrentIncidents caps how many incidents forensics will
	// have in flight at once. Past the cap, additional triggers are
	// queued (max 100, FIFO with age-out at 5 minutes per design F8).
	// +kubebuilder:default=5
	MaxConcurrentIncidents int `json:"maxConcurrentIncidents,omitempty"`
}

// ForensicsTrigger is the SE predicate. All conditions ANDed.
type ForensicsTrigger struct {
	// Classes restricts capture to SEs of the listed classes.
	// +kubebuilder:default={Detection,Anomaly}
	// +kubebuilder:validation:items:Enum=Detection;Anomaly;PolicyViolation;Forensic;Compliance;Audit
	Classes []Class `json:"classes,omitempty"`

	// MinSeverities is the lower-bound severity allowlist.
	// +kubebuilder:default={high,critical}
	// +kubebuilder:validation:items:Enum=critical;high;medium;low;info
	MinSeverities []Severity `json:"minSeverities,omitempty"`

	// RequireAttested gates capture on AttestationBundle.Phase=Sealed.
	// Default true; setting false enables capture on raw (unsigned)
	// events - discouraged but supported for chase-the-attacker
	// scenarios where the attestor itself is being compromised.
	// +kubebuilder:default=true
	RequireAttested bool `json:"requireAttested"`

	// NamespaceAllowlist restricts capture to suspect Pods living in
	// these namespaces. Empty = all namespaces.
	NamespaceAllowlist []string `json:"namespaceAllowlist,omitempty"`
}

// SnapshotConfig tunes the per-incident snapshot pipeline.
type SnapshotConfig struct {
	// Image overrides the snapshot ephemeral container image. Empty
	// falls back to the chart default (multi-binary runtime image
	// pinned to the operator's release).
	Image string `json:"image,omitempty"`

	// FilesystemSnapshot toggles the fs-snapshot step.
	// +kubebuilder:default=true
	FilesystemSnapshot bool `json:"filesystemSnapshot"`

	// MemorySnapshot toggles the mem-snapshot step (Phase 3).
	// +kubebuilder:default=false
	MemorySnapshot bool `json:"memorySnapshot,omitempty"`

	// FilesystemPaths is the list of in-pod paths to capture. Default
	// `/proc/<pid>/root` = full container fs view.
	FilesystemPaths []string `json:"filesystemPaths,omitempty"`

	// ExcludePaths are glob patterns excluded from the filesystem
	// capture (PII, large dirs, known-clean baselines).
	ExcludePaths []string `json:"excludePaths,omitempty"`

	// MaxBytes caps the snapshot upload size. The streaming uploader
	// aborts at the cap and emits SE{Type: IncidentCaptureFailed}.
	// +kubebuilder:default="2Gi"
	MaxBytes resource.Quantity `json:"maxBytes,omitempty"`

	// TimeoutSeconds caps the snapshot duration end-to-end.
	// +kubebuilder:default=300
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
}

// CleanupConfig tunes post-incident behaviour.
type CleanupConfig struct {
	// AutoUnfreezeAfter is the duration past which a frozen Pod is
	// automatically unfrozen if no admin acknowledged the incident.
	// Zero = never auto-unfreeze (manual ack required, MVP default).
	// +kubebuilder:default="0s"
	AutoUnfreezeAfter metav1.Duration `json:"autoUnfreezeAfter,omitempty"`

	// AcknowledgeAuthorizedSAs lists ServiceAccount usernames allowed
	// to set the `ugallu.io/incident-acknowledged=true` annotation on
	// Forensic SEs. Pattern matches admission policy 4.
	AcknowledgeAuthorizedSAs []string `json:"acknowledgeAuthorizedSAs,omitempty"`
}

// ForensicsConfigStatus surfaces operator-side runtime state for
// kubectl visibility.
type ForensicsConfigStatus struct {
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// FreezeBackend is the auto-detected NetworkPolicy backend
	// (Cilium / CoreV1) the operator chose at startup. Refreshed
	// periodically.
	FreezeBackend string `json:"freezeBackend,omitempty"`

	// LastConfigLoadAt marks the most recent successful read of the
	// spec.
	LastConfigLoadAt *metav1.Time `json:"lastConfigLoadAt,omitempty"`

	// InFlightIncidents reports the live concurrent-incident count
	// at the most recent reconcile. Drift between this and
	// MaxConcurrentIncidents (in spec) signals capacity pressure.
	InFlightIncidents int64 `json:"inFlightIncidents,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=forensicscfg
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Backend",type=string,JSONPath=`.status.freezeBackend`
// +kubebuilder:printcolumn:name="Concurrency",type=integer,JSONPath=`.spec.maxConcurrentIncidents`
// +kubebuilder:printcolumn:name="Attested",type=boolean,JSONPath=`.spec.trigger.requireAttested`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ForensicsConfig is the cluster-scoped singleton (name="default")
// that governs the ugallu-forensics operator.
type ForensicsConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ForensicsConfigSpec   `json:"spec,omitempty"`
	Status ForensicsConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ForensicsConfigList is the list type for ForensicsConfig.
type ForensicsConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForensicsConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ForensicsConfig{}, &ForensicsConfigList{})
}
