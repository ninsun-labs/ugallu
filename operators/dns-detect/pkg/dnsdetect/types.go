// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package dnsdetect exposes the controller-runtime wiring for the
// ugallu-dns-detect operator (design 21 §D). The 5 anomaly detectors
// + source backends ship in subsequent commits.
package dnsdetect

import (
	"net"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// DNSEvent is the source-agnostic shape every backend (CoreDNS plugin
// stream, Tetragon kprobe fallback) hands to the detector pipeline.
// Fields are nullable when the source can't populate them — the
// fallback path leaves payload-heavy fields zero-valued.
type DNSEvent struct {
	Source     DNSSourceKind
	Timestamp  time.Time
	NodeName   string
	SrcIP      net.IP
	SrcCgroup  uint64           // 0 when SO_PEEKCRED unavailable
	DstIP      net.IP
	DstPort    uint16
	QName      string
	QType      string           // "A" | "AAAA" | "TXT" | ...
	QClass     string           // typically "IN"
	RCODE      uint8            // RFC 1035 RCODE; 0 = NOERROR
	ResponseRR []string         // canonical text rendering; empty for Tetragon
	Latency    time.Duration    // 0 for Tetragon
	PayloadLen int              // total qname + response bytes

	// Pod is the resolver-enriched namespace/name pair for the
	// source. Empty namespace + name = External (resolver miss).
	Pod        types.NamespacedName
	SubjectUID types.UID
}

// DNSSourceKind tags the backend that produced the event. Used in
// Prometheus labels and SE Signals so dashboards can split by source.
type DNSSourceKind string

const (
	DNSSourceCoreDNSPlugin  DNSSourceKind = "coredns_plugin"
	DNSSourceTetragonKprobe DNSSourceKind = "tetragon_kprobe"
)
