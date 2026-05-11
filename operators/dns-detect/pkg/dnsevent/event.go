// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package dnsevent holds the source-agnostic DNSEvent shape every
// backend produces and every detector consumes. It exists in its
// own package to break the import cycle between
// pkg/dnsdetect (dispatcher + reconciler) and pkg/dnsdetect/source
// (CoreDNS plugin + Tetragon kprobe backends) - both need to refer
// to the type.
package dnsevent

import (
	"net"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// DNSEvent is the shape every source backend (CoreDNS plugin stream,
// Tetragon kprobe fallback) hands to the detector pipeline. Fields
// are nullable when the source can't populate them - the fallback
// path leaves payload-heavy fields zero-valued.
type DNSEvent struct {
	Source     SourceKind
	Timestamp  time.Time
	NodeName   string
	SrcIP      net.IP
	SrcCgroup  uint64 // 0 when SO_PEEKCRED unavailable
	DstIP      net.IP
	DstPort    uint16
	QName      string
	QType      string        // "A" | "AAAA" | "TXT" | ...
	QClass     string        // typically "IN"
	RCODE      uint8         // RFC 1035 RCODE; 0 = NOERROR
	ResponseRR []string      // canonical text rendering; empty for Tetragon
	Latency    time.Duration // 0 for Tetragon
	PayloadLen int           // total qname + response bytes

	// Pod is the resolver-enriched namespace/name pair for the
	// source. Empty namespace + name = External (resolver miss).
	Pod        types.NamespacedName
	SubjectUID types.UID
}

// SourceKind tags the backend that produced the event.
type SourceKind string

// Source kind discriminators - match
// DNSDetectConfig.spec.source.primary in the SDK CRD.
const (
	SourceCoreDNSPlugin  SourceKind = "coredns_plugin"
	SourceTetragonKprobe SourceKind = "tetragon_kprobe"
)
