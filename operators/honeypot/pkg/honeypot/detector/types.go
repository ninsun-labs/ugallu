// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package detector implements the 2 honeypot tripwire detectors
// design 21 §H4 prescribes. Each detector is a pure function over
// an audit envelope + the live decoy Index.
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

// AuditInput is the abstraction the audit-bus-driven detectors
// operate on. Filled by the source layer from
// auditstreamv1.AuditEvent.
type AuditInput struct {
	AuditID         string
	Verb            string
	UserUsername    string
	ObjectAPIGroup  string
	ObjectResource  string
	ObjectNamespace string
	ObjectName      string
	ObjectUID       types.UID

	// RequestObject is the JSON-encoded request body when present.
	// HoneypotMisplaced needs to peek inside Pod specs.
	RequestObject []byte
}

// AuditDetector matches against audit events.
type AuditDetector interface {
	Name() string
	Evaluate(in *AuditInput) *Finding
}

// Severity returns the canonical severity string for a Finding type.
// Mapping pinned by design 21 §H4.
func Severity(seType string) string {
	switch seType {
	case securityv1alpha1.TypeHoneypotTriggered:
		return string(securityv1alpha1.SeverityCritical)
	case securityv1alpha1.TypeHoneypotMisplaced:
		return string(securityv1alpha1.SeverityHigh)
	}
	return string(securityv1alpha1.SeverityMedium)
}
