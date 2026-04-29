// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HoneypotConfigSpec declares the decoy K8s resources the honeypot
// operator must materialise + the detection contract that fires
// when an actor reads/touches one of them.
//
// Pattern: every decoy carries the label
// `ugallu.io/decoy=true` plus an annotation
// `ugallu.io/honeypot-config=<cr-name>` that the detector uses
// to discriminate honeypots from regular cluster state on the
// audit-bus stream.
type HoneypotConfigSpec struct {
	// Decoys lists the resources the operator must create + keep
	// reconciled. Empty list = no-op (the CR can stage future
	// decoys without firing them yet).
	// +optional
	Decoys []HoneypotDecoy `json:"decoys,omitempty"`

	// EmitOnRead controls whether the detector fires on read-side
	// verbs (get/list/watch). Defaults to true; flip to false to
	// limit firing to mutating verbs (create/update/patch/delete)
	// — useful when the decoy lives in a high-traffic ns and read
	// noise overwhelms triage.
	// +kubebuilder:default=true
	// +optional
	EmitOnRead bool `json:"emitOnRead,omitempty"`

	// AllowlistedActors enumerates SA usernames
	// (`system:serviceaccount:<ns>:<name>`) that may legitimately
	// touch decoys without firing — typically backup operators
	// or the honeypot operator itself for self-checks.
	// +optional
	AllowlistedActors []string `json:"allowlistedActors,omitempty"`
}

// HoneypotDecoy is one decoy declaration.
type HoneypotDecoy struct {
	// Kind is the K8s kind of the decoy. Wave 3 ships Secret +
	// ServiceAccount; ConfigMap and Namespace land in Wave 4.
	// +kubebuilder:validation:Enum=Secret;ServiceAccount
	Kind string `json:"kind"`

	// Name is the decoy resource's metadata.name. Choose a name
	// that mimics a legitimate target (e.g. `prod-db-creds`,
	// `backup-uploader`) so the honeypot is plausible.
	Name string `json:"name"`

	// Namespace is where the decoy lands. The honeypot operator
	// must have RBAC to create resources of `Kind` in this
	// namespace.
	Namespace string `json:"namespace"`

	// Data is the optional payload for Secret decoys (key→value).
	// Stored verbatim — for plausibility populate with realistic-
	// looking but fake credentials. Ignored for non-Secret kinds.
	// +optional
	Data map[string]string `json:"data,omitempty"`
}

// HoneypotConfigStatus surfaces operator-side observations.
type HoneypotConfigStatus struct {
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// DeployedDecoys lists the decoys currently materialised on
	// the cluster (one entry per Spec.Decoys entry that
	// successfully rendered).
	DeployedDecoys []DeployedDecoy `json:"deployedDecoys,omitempty"`

	// LastReconcileAt timestamps the most recent successful reconcile.
	LastReconcileAt *metav1.Time `json:"lastReconcileAt,omitempty"`
}

// DeployedDecoy mirrors the live state of one Spec.Decoys entry.
type DeployedDecoy struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=hpcfg
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Decoys",type=integer,JSONPath=`.status.deployedDecoys[*]`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// HoneypotConfig is the cluster-scoped resource that declares the
// honeypot decoy set + the detection contract for the
// ugallu-honeypot operator.
type HoneypotConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HoneypotConfigSpec   `json:"spec,omitempty"`
	Status HoneypotConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// HoneypotConfigList is the list type for HoneypotConfig.
type HoneypotConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HoneypotConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HoneypotConfig{}, &HoneypotConfigList{})
}
