// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BackupVerifyBackend is the storage backend the run targets.
// +kubebuilder:validation:Enum=velero;etcd-snapshot
type BackupVerifyBackend string

// BackupVerifyBackend constants — the v0.1.0 supported set.
const (
	// BackupVerifyBackendVelero targets a Velero Backup CR.
	BackupVerifyBackendVelero BackupVerifyBackend = "velero"
	// BackupVerifyBackendEtcdSnapshot targets a raw etcd snapshot
	// dump (k3s/RKE2/etcd-backup-operator output).
	BackupVerifyBackendEtcdSnapshot BackupVerifyBackend = "etcd-snapshot"
)

// BackupVerifyMode picks how aggressive the verification is.
// checksum-only is fast (download + sha256 + manifest schema parse);
// full-restore actually replays the backup into the sandbox namespace
// and diffs against the live source-of-truth state.
// +kubebuilder:validation:Enum=checksum-only;full-restore
type BackupVerifyMode string

// BackupVerifyMode constants.
const (
	// BackupVerifyModeChecksumOnly downloads + sha256 + manifest
	// schema validation; no restore.
	BackupVerifyModeChecksumOnly BackupVerifyMode = "checksum-only"
	// BackupVerifyModeFullRestore replays the backup into a sandbox
	// namespace and diffs the resulting object set.
	BackupVerifyModeFullRestore BackupVerifyMode = "full-restore"
)

// BackupVerifyRunSpec is the runtime config the ugallu-backup-verify
// operator reads to drive a verification cycle.
type BackupVerifyRunSpec struct {
	// Backend selects the storage backend. v0.1.0 supports
	// Velero (managed Backup CR) and etcd-snapshot (raw etcd dumps
	// produced by k3s/RKE2/etcd-backup-operator). Restic and
	// S3-raw are out of scope.
	Backend BackupVerifyBackend `json:"backend"`

	// BackupRef pins the specific backup the run targets.
	BackupRef BackupVerifyBackupRef `json:"backupRef"`

	// Mode toggles checksum-only vs full-restore. Full-restore
	// requires SandboxNamespace + a non-empty restore policy.
	// +kubebuilder:default=checksum-only
	Mode BackupVerifyMode `json:"mode"`

	// SandboxNamespace is the (cluster-local) namespace into which
	// full-restore mode replays the backup. Must NOT be a production
	// namespace — admission policy 14 enforces a name suffix
	// "-bvsandbox" for safety. Required when Mode=full-restore.
	// +optional
	SandboxNamespace string `json:"sandboxNamespace,omitempty"`

	// Timeout caps the total run duration. Bounded server-side at
	// 1h to keep verification cycles cheap.
	// +kubebuilder:default="15m"
	Timeout metav1.Duration `json:"timeout"`
}

// BackupVerifyBackupRef points at a specific backup artifact.
type BackupVerifyBackupRef struct {
	// Name of the upstream Backup resource (Velero) OR snapshot file
	// (etcd-snapshot, e.g. "etcd-snapshot-2026-04-29-0030").
	Name string `json:"name"`

	// Namespace is the Velero Backup CR namespace. Empty for
	// etcd-snapshot backend.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// StorageLocation overrides the BackupStorageLocation when
	// multiple are configured (Velero only).
	// +optional
	StorageLocation string `json:"storageLocation,omitempty"`
}

// BackupVerifyRunStatus tracks lifecycle.
type BackupVerifyRunStatus struct {
	// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed
	Phase string `json:"phase,omitempty"`

	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// ResultRef points to the BackupVerifyResult the run produced.
	// Empty until Phase=Succeeded.
	// +optional
	ResultRef *LocalProfileRef `json:"resultRef,omitempty"`

	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bvr
// +kubebuilder:printcolumn:name="Backend",type="string",JSONPath=".spec.backend"
// +kubebuilder:printcolumn:name="Mode",type="string",JSONPath=".spec.mode"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// BackupVerifyRun is one verification cycle: download + checksum +
// (optionally) sandbox restore + diff. Cluster admin creates it
// (typically from a CronJob); the operator drives lifecycle and
// writes a BackupVerifyResult in the same namespace.
type BackupVerifyRun struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BackupVerifyRunSpec   `json:"spec"`
	Status BackupVerifyRunStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BackupVerifyRunList contains a list of BackupVerifyRun.
type BackupVerifyRunList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BackupVerifyRun `json:"items"`
}

// BackupVerifyFinding is one individual issue the verifier surfaced
// during the run.
type BackupVerifyFinding struct {
	// Code is a short machine-readable identifier (e.g.
	// "checksum-mismatch", "object-count-drift", "manifest-corrupt").
	Code string `json:"code"`
	// Severity uses the canonical 5-grade scale.
	// +kubebuilder:validation:Enum=critical;high;medium;low;info
	Severity Severity `json:"severity"`
	// Detail is a human-readable explanation.
	Detail string `json:"detail"`
}

// BackupVerifyResultSpec is the output of a run.
type BackupVerifyResultSpec struct {
	// DerivedFromRun is the BackupVerifyRun that produced this
	// result. Same namespace.
	DerivedFromRun LocalProfileRef `json:"derivedFromRun"`

	// Backend mirrors the run's backend (kept for downstream
	// consumers that only look at the result).
	Backend BackupVerifyBackend `json:"backend"`

	// Mode mirrors the run's mode.
	Mode BackupVerifyMode `json:"mode"`

	// Checksum is the SHA-256 of the backup payload (lowercase hex).
	// Empty when the backend doesn't expose a single payload artifact.
	// +optional
	Checksum string `json:"checksum,omitempty"`

	// RestoredObjectCount counts how many K8s objects came back from
	// a full-restore run. Zero for checksum-only.
	// +optional
	RestoredObjectCount int `json:"restoredObjectCount,omitempty"`

	// Findings lists every issue surfaced during the run. Empty list
	// + Phase=Succeeded means the backup is healthy.
	// +optional
	Findings []BackupVerifyFinding `json:"findings,omitempty"`
}

// BackupVerifyResultStatus carries the worst observed severity for
// quick filtering.
type BackupVerifyResultStatus struct {
	// WorstSeverity is the highest severity in Findings; empty when
	// the run produced no findings.
	// +kubebuilder:validation:Enum=critical;high;medium;low;info
	// +optional
	WorstSeverity Severity `json:"worstSeverity,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bvres
// +kubebuilder:printcolumn:name="Backend",type="string",JSONPath=".spec.backend"
// +kubebuilder:printcolumn:name="Worst",type="string",JSONPath=".status.worstSeverity"
// +kubebuilder:printcolumn:name="Run",type="string",JSONPath=".spec.derivedFromRun.name"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// BackupVerifyResult is one run's per-finding report. Retained for
// 30d by the ugallu-ttl operator.
type BackupVerifyResult struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BackupVerifyResultSpec   `json:"spec"`
	Status BackupVerifyResultStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BackupVerifyResultList contains a list of BackupVerifyResult.
type BackupVerifyResultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BackupVerifyResult `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BackupVerifyRun{}, &BackupVerifyRunList{})
	SchemeBuilder.Register(&BackupVerifyResult{}, &BackupVerifyResultList{})
}
