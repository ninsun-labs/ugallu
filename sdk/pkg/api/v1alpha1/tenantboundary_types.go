// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TenantBoundarySpec defines the namespaces, hostPath whitelist, and
// SA + namespace allowlists that constitute one tenant's blast radius.
// Multi-instance, cluster-scoped: each TenantBoundary names a tenant;
// cross-CR namespaceSelector overlap is reported via Status and a
// meta-event but never silently merged.
type TenantBoundarySpec struct {
	// NamespaceSelector picks the namespaces that belong to this
	// tenant. Empty selector = match-none (defensive default; the
	// admin must explicitly opt namespaces in).
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector"`

	// HostPathPolicy declares the host filesystem prefixes this
	// tenant is allowed to mount via Pod hostPath volumes. A Pod
	// in this tenant mounting outside this list AND inside another
	// tenant's allow list fires CrossTenantHostPathOverlap.
	// +optional
	HostPathPolicy HostPathPolicy `json:"hostPathPolicy,omitempty"`

	// ServiceAccountAllowlist lists SA usernames (full
	// "system:serviceaccount:<ns>:<name>" form) that may legitimately
	// cross this tenant's boundary as actors (e.g. cluster-admin
	// controllers operating on tenant resources).
	// +optional
	ServiceAccountAllowlist []string `json:"serviceAccountAllowlist,omitempty"`

	// TrustedNamespaces lists other namespaces that are allowed to
	// be the source of cross-tenant NetworkPolicy ingress without
	// triggering CrossTenantNetworkPolicy (e.g. shared "monitoring"
	// or "ingress" namespaces).
	// +optional
	TrustedNamespaces []string `json:"trustedNamespaces,omitempty"`
}

// HostPathPolicy declares the hostPath-mount allowlist for a tenant.
type HostPathPolicy struct {
	// Allow lists prefix patterns the tenant's pods may mount.
	// Suffix match: "/var/lib/team-a/" matches any path starting
	// with that prefix.
	// +optional
	Allow []string `json:"allow,omitempty"`
}

// TenantBoundaryStatus surfaces operator-side observations.
type TenantBoundaryStatus struct {
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// MatchedNamespaces is the live list of namespaces matched by
	// Spec.NamespaceSelector at the most recent reconcile.
	MatchedNamespaces []string `json:"matchedNamespaces,omitempty"`

	// MatchedPods is the count of Pods currently running across the
	// matched namespaces. Diagnostic — drift between this and the
	// expected tenant size signals miss-labelled namespaces.
	MatchedPods int32 `json:"matchedPods,omitempty"`

	// LastReconcileAt timestamps the most recent successful reconcile.
	LastReconcileAt *metav1.Time `json:"lastReconcileAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=tb
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="MatchedNamespaces",type=string,JSONPath=`.status.matchedNamespaces`
// +kubebuilder:printcolumn:name="MatchedPods",type=integer,JSONPath=`.status.matchedPods`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TenantBoundary is the cluster-scoped resource that defines one
// tenant's blast radius for the ugallu-tenant-escape operator.
type TenantBoundary struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TenantBoundarySpec   `json:"spec,omitempty"`
	Status TenantBoundaryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TenantBoundaryList is the list type for TenantBoundary.
type TenantBoundaryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TenantBoundary `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TenantBoundary{}, &TenantBoundaryList{})
}
