// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ComplianceScanBackend selects the scanner the run drives.
// +kubebuilder:validation:Enum=kube-bench;falco;cel-custom
type ComplianceScanBackend string

// ComplianceScanBackend constants — the v0.1.0 supported set.
const (
	// ComplianceScanBackendKubeBench runs the upstream kube-bench
	// CIS Kubernetes Benchmark against the cluster.
	ComplianceScanBackendKubeBench ComplianceScanBackend = "kube-bench"

	// ComplianceScanBackendFalco evaluates the configured Falco
	// rule set against runtime events for the scan window.
	ComplianceScanBackendFalco ComplianceScanBackend = "falco"

	// ComplianceScanBackendCELCustom evaluates the cluster against
	// the operator-curated CEL ruleset (custom controls — typically
	// a SOC2/ISO27001 mapping).
	ComplianceScanBackendCELCustom ComplianceScanBackend = "cel-custom"
)

// ComplianceScanRunSpec is the runtime config the
// ugallu-compliance-scan operator reads to drive a single scan.
type ComplianceScanRunSpec struct {
	// Backend selects the scanner.
	Backend ComplianceScanBackend `json:"backend"`

	// Profile is a backend-specific identifier.
	//   - kube-bench: a target version, e.g. "cis-1.10".
	//   - falco:      the Falco source name (e.g. "ruleset-1").
	//   - cel-custom: the operator-side rule pack name.
	Profile string `json:"profile"`

	// ControlMappings carries the SOC2 / ISO27001 mapping the
	// reporter stamps on the produced result. Empty means the
	// reporter falls back to the in-tree default mapping.
	// +optional
	ControlMappings []ControlMapping `json:"controlMappings,omitempty"`

	// Timeout caps the total scan duration. Bounded server-side at
	// 30m by admission policy 15.
	// +kubebuilder:default="10m"
	Timeout metav1.Duration `json:"timeout"`
}

// ControlMapping links a CIS / Falco / CEL check id to the
// regulatory framework's control id.
type ControlMapping struct {
	// CheckID is the scanner-native identifier.
	CheckID string `json:"checkID"`
	// Frameworks lists the framework→controlID pairs this check
	// satisfies (SOC2 / ISO27001 / PCI-DSS / NIST 800-53).
	// +listType=atomic
	Frameworks []FrameworkControl `json:"frameworks"`
}

// FrameworkControl is one (framework, controlID) pair.
type FrameworkControl struct {
	// Name of the regulatory framework, lowercase
	// (soc2|iso27001|pci-dss|nist-800-53|custom).
	// +kubebuilder:validation:Enum=soc2;iso27001;pci-dss;nist-800-53;custom
	Name string `json:"name"`
	// ControlID inside the framework.
	ControlID string `json:"controlID"`
}

// ComplianceScanRunStatus tracks lifecycle.
type ComplianceScanRunStatus struct {
	// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed
	Phase string `json:"phase,omitempty"`

	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// ResultRef points to the ComplianceScanResult the run wrote.
	// Empty until Phase=Succeeded.
	// +optional
	ResultRef *LocalProfileRef `json:"resultRef,omitempty"`

	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=csr
// +kubebuilder:printcolumn:name="Backend",type="string",JSONPath=".spec.backend"
// +kubebuilder:printcolumn:name="Profile",type="string",JSONPath=".spec.profile"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ComplianceScanRun is one scan cycle.
type ComplianceScanRun struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ComplianceScanRunSpec   `json:"spec"`
	Status ComplianceScanRunStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ComplianceScanRunList contains a list of ComplianceScanRun.
type ComplianceScanRunList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceScanRun `json:"items"`
}

// ComplianceCheckResult is one scanner row.
type ComplianceCheckResult struct {
	// CheckID is the scanner-native identifier.
	CheckID string `json:"checkID"`

	// Title is a human-readable description of the check.
	Title string `json:"title"`

	// Outcome is the canonical pass/fail state.
	// +kubebuilder:validation:Enum=pass;fail;warn;skip
	Outcome string `json:"outcome"`

	// Severity uses the canonical 5-grade scale.
	// +kubebuilder:validation:Enum=critical;high;medium;low;info
	// +optional
	Severity Severity `json:"severity,omitempty"`

	// Detail is free-form scanner output (one line is enough; the
	// raw scanner artifact lives in the WORM bucket).
	// +optional
	Detail string `json:"detail,omitempty"`

	// Frameworks copies the matching ControlMapping entries.
	// +optional
	Frameworks []FrameworkControl `json:"frameworks,omitempty"`
}

// ComplianceScanResultSpec is the per-check report the scan produced.
type ComplianceScanResultSpec struct {
	// DerivedFromRun is the ComplianceScanRun that produced this
	// result. Same namespace.
	DerivedFromRun LocalProfileRef `json:"derivedFromRun"`

	// Backend / Profile mirror the run for downstream consumers
	// that only see the result.
	Backend ComplianceScanBackend `json:"backend"`
	Profile string                `json:"profile"`

	// Checks is the per-check report.
	// +optional
	Checks []ComplianceCheckResult `json:"checks,omitempty"`

	// Summary is a {pass,fail,warn,skip}→count map.
	// +optional
	Summary map[string]int `json:"summary,omitempty"`
}

// ComplianceScanResultStatus carries the worst observed severity.
type ComplianceScanResultStatus struct {
	// +kubebuilder:validation:Enum=critical;high;medium;low;info
	// +optional
	WorstSeverity Severity `json:"worstSeverity,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=csres
// +kubebuilder:printcolumn:name="Backend",type="string",JSONPath=".spec.backend"
// +kubebuilder:printcolumn:name="Worst",type="string",JSONPath=".status.worstSeverity"
// +kubebuilder:printcolumn:name="Run",type="string",JSONPath=".spec.derivedFromRun.name"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ComplianceScanResult is the per-check report. Retained 365d per
// design (W4-D7) by the ugallu-ttl operator.
type ComplianceScanResult struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ComplianceScanResultSpec   `json:"spec"`
	Status ComplianceScanResultStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ComplianceScanResultList contains a list of ComplianceScanResult.
type ComplianceScanResultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceScanResult `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ComplianceScanRun{}, &ComplianceScanRunList{})
	SchemeBuilder.Register(&ComplianceScanResult{}, &ComplianceScanResultList{})
}
