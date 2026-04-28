// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsevent"
)

func mkEvent(qname, qtype string, dstPort uint16) *dnsevent.DNSEvent {
	return &dnsevent.DNSEvent{
		Source:     dnsevent.SourceCoreDNSPlugin,
		QName:      qname,
		QType:      qtype,
		DstIP:      net.IPv4(10, 0, 0, 53),
		DstPort:    dstPort,
		SrcIP:      net.IPv4(10, 244, 1, 5),
		PayloadLen: len(qname),
		Pod:        types.NamespacedName{Namespace: "team-a", Name: "client-pod"},
		SubjectUID: types.UID("pod-uid-1"),
		Timestamp:  time.Now(),
	}
}

// --- Exfiltration ----------------------------------------------------

func TestExfiltrationDetector_FireAfterConsecutive(t *testing.T) {
	d := NewExfiltrationDetector(ExfiltrationConfig{
		MinLabelLen:         16,
		MinEntropy:          3.5,
		WindowSize:          10,
		ConsecutiveTriggers: 3,
	})
	// High-entropy synthetic label (random base64 → entropy ~6).
	rnd := make([]byte, 24)
	_, _ = rand.Read(rnd)
	label := base64.RawURLEncoding.EncodeToString(rnd)
	qname := label + ".example.com"

	for i := 1; i <= 2; i++ {
		ev := mkEvent(qname, "TXT", 53)
		if got := d.Evaluate(ev); got.Has() {
			t.Errorf("iteration %d: fired too early (need 3 consecutive)", i)
		}
	}
	ev := mkEvent(qname, "TXT", 53)
	got := d.Evaluate(ev)
	if !got.Has() {
		t.Fatalf("expected fire after 3 consecutive high-entropy queries")
	}
	if got.Type == "" {
		t.Errorf("Finding.Type empty")
	}
}

func TestExfiltrationDetector_LowEntropySkips(t *testing.T) {
	d := NewExfiltrationDetector(ExfiltrationConfig{
		MinLabelLen:         8,
		MinEntropy:          5.0, // very high; common alphanumeric won't reach
		ConsecutiveTriggers: 1,
	})
	ev := mkEvent("aaaaaaaaaaaaaaaaaaaaaaaaaa.example.com", "TXT", 53) // monotone, low entropy
	if got := d.Evaluate(ev); got.Has() {
		t.Errorf("low-entropy query should not fire")
	}
}

func TestExfiltrationDetector_WrongQTypeSkips(t *testing.T) {
	d := NewExfiltrationDetector(ExfiltrationConfig{ConsecutiveTriggers: 1})
	ev := mkEvent("highentropy-label-shouldfire-but-qtype-is-MX.example.com", "MX", 53)
	if got := d.Evaluate(ev); got.Has() {
		t.Errorf("non-TXT/A/AAAA qtype should skip")
	}
}

// --- Tunneling -------------------------------------------------------

func TestTunnelingDetector_Base64Match(t *testing.T) {
	d := NewTunnelingDetector(TunnelingConfig{RatelimitPerPod: time.Millisecond})
	// Random binary → base64 → high entropy decoded.
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	encoded := base64.StdEncoding.EncodeToString(raw)
	qname := encoded + ".attacker.example"

	got := d.Evaluate(mkEvent(qname, "A", 53))
	if !got.Has() {
		t.Fatalf("expected tunneling fire on base64 label")
	}
	// Rate-limit: second call within window should NOT re-fire.
	if got2 := d.Evaluate(mkEvent(qname, "A", 53)); got2.Has() {
		t.Errorf("ratelimit failed — second call within window fired")
	}
}

func TestTunnelingDetector_TextLabelSkips(t *testing.T) {
	d := NewTunnelingDetector(TunnelingConfig{})
	if got := d.Evaluate(mkEvent("www.example.com", "A", 53)); got.Has() {
		t.Errorf("normal qname should not fire tunneling detector")
	}
}

// --- Blocklist -------------------------------------------------------

func TestBlocklistDetector_ExactAndSuffix(t *testing.T) {
	d := NewBlocklistDetector()
	d.SetEntries(map[string]string{
		"evil.example":     "default",
		"*.malicious.test": "default",
		"# comment":        "default",
		"":                 "default",
	})
	for _, tc := range []struct {
		qname string
		fire  bool
	}{
		{"evil.example", true},
		{"sub.malicious.test", true},
		{"www.example.com", false},
		{"malicious.test", false}, // suffix requires subdomain
	} {
		ev := mkEvent(tc.qname, "A", 53)
		got := d.Evaluate(ev)
		if got.Has() != tc.fire {
			t.Errorf("qname=%q fire=%v, want %v", tc.qname, got.Has(), tc.fire)
		}
	}
}

// --- YoungDomain -----------------------------------------------------

type mockAgeLookup map[string]int

func (m mockAgeLookup) AgeDays(domain string) (int, bool) {
	v, ok := m[domain]
	return v, ok
}

func TestYoungDomainDetector(t *testing.T) {
	lookup := mockAgeLookup{
		"young.test":   5,
		"old.test":     365,
		"unknown.test": -1, // simulate "not in lookup"
	}
	delete(lookup, "unknown.test")
	d := NewYoungDomainDetector(YoungDomainConfig{ThresholdDays: 30}, lookup)

	if got := d.Evaluate(mkEvent("sub.young.test", "A", 53)); !got.Has() {
		t.Errorf("young domain should fire")
	}
	if got := d.Evaluate(mkEvent("sub.old.test", "A", 53)); got.Has() {
		t.Errorf("old domain should not fire")
	}
	if got := d.Evaluate(mkEvent("sub.unknown.test", "A", 53)); got.Has() {
		t.Errorf("unknown domain should not fire (conservative)")
	}
}

func TestYoungDomainDetector_NilLookupSkips(t *testing.T) {
	d := NewYoungDomainDetector(YoungDomainConfig{}, nil)
	if got := d.Evaluate(mkEvent("anything.test", "A", 53)); got.Has() {
		t.Errorf("nil lookup should disable detector")
	}
}

// --- AnomalousPort ---------------------------------------------------

func TestAnomalousPortDetector(t *testing.T) {
	d := NewAnomalousPortDetector()
	for _, tc := range []struct {
		port uint16
		fire bool
	}{
		{53, false},
		{0, false}, // unknown port → skip
		{5353, true},
		{1234, true},
	} {
		got := d.Evaluate(mkEvent("normal.example.com", "A", tc.port))
		if got.Has() != tc.fire {
			t.Errorf("port=%d fire=%v, want %v", tc.port, got.Has(), tc.fire)
		}
	}
}
