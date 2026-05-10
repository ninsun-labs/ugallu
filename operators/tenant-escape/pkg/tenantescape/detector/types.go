// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package detector implements the 4 cross-tenant detectors.
// Each detector is a pure function over an input envelope
// (audit event OR Tetragon process exec) plus the active
// TenantBoundary set.
package detector

import (
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// Finding is the structured output of a detector hit.
type Finding struct {
	Type     string
	Severity string
	Subject  Subject
	Signals  map[string]string
}

// Has reports whether the finding fires.
func (f *Finding) Has() bool { return f != nil && f.Type != "" }

// Subject is the resolved attribution for the SE.
type Subject struct {
	Kind      string
	Name      string
	Namespace string
	UID       types.UID
}

// BoundarySet is the read-only view of the active TenantBoundary
// CRs. Detectors query it to determine which tenant a namespace
// belongs to + the per-tenant allowlists.
type BoundarySet interface {
	// TenantOf returns the boundary name (CR.Name) that owns the
	// given namespace, or "" if no boundary matches.
	TenantOf(namespace string) string

	// HostPathTenantOf returns the boundary name that has the given
	// hostPath prefix in its allow list, or "" if no boundary owns
	// it.
	HostPathTenantOf(path string) string

	// SAAllowedFor reports whether actorSA may legitimately cross
	// targetTenant's boundary as an actor.
	SAAllowedFor(actorSA, targetTenant string) bool

	// NamespaceTrustedBy reports whether sourceNS is in
	// targetTenant.TrustedNamespaces.
	NamespaceTrustedBy(sourceNS, targetTenant string) bool
}

// AuditInput is the abstraction the audit-bus-driven detectors
// operate on. Filled by the source layer from
// auditstreamv1.AuditEvent.
type AuditInput struct {
	AuditID         string
	Verb            string
	UserUsername    string
	UserNamespace   string // parsed from `system:serviceaccount:<ns>:<name>` when applicable
	ObjectAPIGroup  string
	ObjectResource  string
	ObjectNamespace string
	ObjectName      string
	ObjectUID       types.UID

	// RequestObject is the JSON-encoded request body when present
	// (audit policy decides). Some detectors (HostPathOverlap)
	// need to peek inside.
	RequestObject []byte
}

// ExecInput is the abstraction the Tetragon-driven detector
// operates on. Filled by the source layer from a Tetragon
// process_exec event.
type ExecInput struct {
	ExecutorPodNamespace string
	ExecutorUsername     string

	TargetPodNamespace string
	TargetPodName      string
	TargetPodUID       types.UID

	Command string
}

// AuditDetector matches against audit events.
type AuditDetector interface {
	Name() string
	Evaluate(in *AuditInput, boundaries BoundarySet) *Finding
}

// ExecDetector matches against Tetragon exec events.
type ExecDetector interface {
	Name() string
	Evaluate(in *ExecInput, boundaries BoundarySet) *Finding
}

// Helpers ---------------------------------------------------------

// Severity returns the canonical severity string for a Finding type.
func Severity(seType string) string {
	switch seType {
	case securityv1alpha1.TypeCrossTenantHostPathOverlap,
		securityv1alpha1.TypeCrossTenantExec:
		return string(securityv1alpha1.SeverityCritical)
	case securityv1alpha1.TypeCrossTenantSecretAccess,
		securityv1alpha1.TypeCrossTenantNetworkPolicy:
		return string(securityv1alpha1.SeverityHigh)
	}
	return string(securityv1alpha1.SeverityMedium)
}
