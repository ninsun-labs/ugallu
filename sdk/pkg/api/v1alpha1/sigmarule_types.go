// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SigmaRuleSpec is the predicate + emit declaration for a single
// detection rule consumed by audit-detection.
type SigmaRuleSpec struct {
	// Enabled gates whether the engine evaluates this rule. The
	// kubebuilder default fills in true when the user posts a CR
	// without the field; the omitempty tag is dropped on purpose so a
	// Go client setting Enabled=false survives marshal (otherwise the
	// false would be omitted and the apiserver would apply the
	// default).
	//
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// Description is a free-form human-readable summary.
	// +kubebuilder:validation:MaxLength=1024
	Description string `json:"description,omitempty"`

	// Match is the predicate evaluated against each audit-log entry.
	Match SigmaMatch `json:"match"`

	// Emit produces the SecurityEvent on match.
	Emit SigmaEmit `json:"emit"`

	// RateLimit overrides the global token bucket.
	RateLimit *SigmaRateLimit `json:"rateLimit,omitempty"`

	// References point at upstream rule sources (Sigma community,
	// CIS, etc.) for traceability.
	References []string `json:"references,omitempty"`

	// Tags are free-form labels for grouping rules in dashboards.
	Tags []string `json:"tags,omitempty"`
}

// SigmaMatch is the evaluated predicate. Top-level fields combine
// with implicit AND. AnyOf restores OR; Not negates the nested
// match. The split into SigmaMatch (top) + SigmaMatchLeaf (inside
// AnyOf / Not) deliberately caps recursion at depth 1: nested Not is
// not allowed and AnyOf is one level deep, which also lets the
// OpenAPI schema generator finish.
type SigmaMatch struct {
	SigmaMatchLeaf `json:",inline"`

	// AnyOf restores OR composition between sibling matches. Each
	// entry is a leaf (no further AnyOf/Not nesting).
	AnyOf []SigmaMatchLeaf `json:"anyOf,omitempty"`

	// Not negates the contained match. Single-level only.
	Not *SigmaMatchLeaf `json:"not,omitempty"`
}

// SigmaMatchLeaf is the leaf shape - every primitive predicate but
// neither AnyOf nor Not. The split keeps the CRD schema finite while
// the Go runtime compiles SigmaMatch + SigmaMatchLeaf into the same
// internal tree.
type SigmaMatchLeaf struct {
	// Verb is matched against AuditEvent.verb (any-of semantics).
	// +kubebuilder:validation:items:Enum=create;update;patch;delete;get;list;watch;deletecollection;connect
	Verb []string `json:"verb,omitempty"`

	// ObjectRef matches AuditEvent.objectRef.
	ObjectRef *ObjectRefMatch `json:"objectRef,omitempty"`

	// User matches AuditEvent.user.
	User *UserMatch `json:"user,omitempty"`

	// Subresource matches AuditEvent.objectRef.subresource ("" matches none).
	Subresource []string `json:"subresource,omitempty"`

	// RequestObjectGlob applies (jsonPath, glob) pairs against
	// AuditEvent.requestObject. AND across entries.
	RequestObjectGlob []GlobMatch `json:"requestObjectGlob,omitempty"`
}

// ObjectRefMatch narrows SigmaMatch on objectRef fields.
type ObjectRefMatch struct {
	APIGroup    []string `json:"apiGroup,omitempty"`
	APIVersion  []string `json:"apiVersion,omitempty"`
	Resource    []string `json:"resource,omitempty"`
	Subresource []string `json:"subresource,omitempty"`
	Namespace   []string `json:"namespace,omitempty"`
	NameGlob    []string `json:"nameGlob,omitempty"`
}

// UserMatch narrows SigmaMatch on user fields.
type UserMatch struct {
	UsernameGlob []string `json:"usernameGlob,omitempty"`
	Groups       []string `json:"groups,omitempty"`
}

// GlobMatch is a (jsonPath, glob[]) pair applied against the
// AuditEvent.requestObject body.
type GlobMatch struct {
	// JSONPath is a restricted JSONPath expression, e.g.
	// "$.spec.containers[*].image".
	JSONPath string `json:"jsonPath"`

	// Patterns is a list of globs (any-of). Max 8 `*` wildcards per
	// pattern, validated by admission policy 6.
	Patterns []string `json:"patterns"`
}

// SigmaEmit produces the SecurityEvent on match.
type SigmaEmit struct {
	// SecurityEventType MUST be a value from the type catalog.
	// Validated by admission policy 6 at apply-time and re-checked
	// by the engine at runtime.
	SecurityEventType string `json:"securityEventType"`

	// +kubebuilder:validation:Enum=critical;high;medium;low;info
	Severity Severity `json:"severity"`

	// +kubebuilder:default=Detection
	// +kubebuilder:validation:Enum=Detection;Anomaly;PolicyViolation;Audit;Compliance;Forensic
	Class Class `json:"class,omitempty"`

	// Signals are extra k/v pairs baked into SE.Spec.Signals.
	// Templating uses ${verb}, ${user.username}, ${objectRef.name}.
	Signals map[string]string `json:"signals,omitempty"`
}

// SigmaRateLimit overrides the per-rule token bucket.
type SigmaRateLimit struct {
	// +kubebuilder:default=50
	Burst int `json:"burst,omitempty"`

	// +kubebuilder:default=5
	SustainedPerSec int `json:"sustainedPerSec,omitempty"`
}

// SigmaRuleStatus is the runtime feedback the controller writes back.
type SigmaRuleStatus struct {
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// MatchCount is the lifetime hit count, best-effort sum across
	// replicas (informers may double-count during failover).
	MatchCount int64 `json:"matchCount,omitempty"`

	// LastMatchedAt marks the most recent emit triggered by the rule.
	LastMatchedAt *metav1.Time `json:"lastMatchedAt,omitempty"`

	// DroppedRateLimit counts hits dropped by the per-rule bucket.
	DroppedRateLimit int64 `json:"droppedRateLimit,omitempty"`

	// ParseError, if non-empty, marks the rule as runtime-invalid
	// (e.g. catalog drift). Admission policy 6 catches most cases at
	// apply-time; this surfaces residual drift.
	ParseError string `json:"parseError,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=sigmarule
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.emit.securityEventType`
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.spec.emit.severity`
// +kubebuilder:printcolumn:name="Enabled",type=boolean,JSONPath=`.spec.enabled`
// +kubebuilder:printcolumn:name="Hits",type=integer,JSONPath=`.status.matchCount`
// +kubebuilder:printcolumn:name="LastMatch",type=date,JSONPath=`.status.lastMatchedAt`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SigmaRule is a detection rule the audit-detection operator
// evaluates against the apiserver/kubelet audit log stream.
// Cluster-scoped (rules cross namespaces by design).
type SigmaRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SigmaRuleSpec   `json:"spec,omitempty"`
	Status SigmaRuleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SigmaRuleList is the list type for SigmaRule.
type SigmaRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SigmaRule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SigmaRule{}, &SigmaRuleList{})
}
