// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package detector implements the 5 DNS anomaly detectors design
// 21 §D3 prescribes. Each detector is a pure function of (DNSEvent,
// per-detector state) → MaybeFinding. State is encapsulated per
// detector — no cross-detector shared state.
package detector

import (
	"k8s.io/apimachinery/pkg/types"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsevent"
)

// Finding is the structured output of a detector hit. Empty Type
// (zero-value Finding) means "no fire" — callers use Has() to check.
type Finding struct {
	Type     string            // SE type (e.g. TypeDNSExfiltration)
	Severity string            // SE severity hint
	Subject  Subject           // pod / external attribution
	Signals  map[string]string // structured detail for SE.spec.signals
}

// Has reports whether the finding fires.
func (f *Finding) Has() bool { return f != nil && f.Type != "" }

// Subject is the resolved attribution for the SE. Filled by the
// reconciler before forwarding to the emitter — detectors don't
// need to know about the resolver.
type Subject struct {
	Kind       string // "Pod" | "External"
	Name       string
	Namespace  string
	UID        types.UID
	Unresolved bool
}

// Detector is the common interface. Each detector receives every
// DNSEvent and decides if it fires.
type Detector interface {
	Name() string
	Evaluate(ev *dnsevent.DNSEvent) Finding
}
