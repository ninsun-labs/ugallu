// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"math"
	"strconv"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsevent"
)

// ExfiltrationConfig matches DNSDetectConfig.spec.detectors.exfiltration
// (design 21 §D3.1).
type ExfiltrationConfig struct {
	MinLabelLen         int
	MinEntropy          float64
	WindowSize          int
	ConsecutiveTriggers int
}

// ExfiltrationDetector flags TXT/A queries with abnormally long +
// high-entropy labels, sustained across a window.
type ExfiltrationDetector struct {
	cfg   ExfiltrationConfig
	mu    sync.Mutex
	state map[types.UID]*exfilState
}

type exfilState struct {
	highEntropyCount int
	totalSeen        int
	totalPayloadLen  int
}

// NewExfiltrationDetector returns a detector with sane defaults
// applied if cfg has zero-values.
func NewExfiltrationDetector(cfg ExfiltrationConfig) *ExfiltrationDetector {
	if cfg.MinLabelLen <= 0 {
		cfg.MinLabelLen = 60
	}
	if cfg.MinEntropy <= 0 {
		cfg.MinEntropy = 4.0
	}
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 64
	}
	if cfg.ConsecutiveTriggers <= 0 {
		cfg.ConsecutiveTriggers = 3
	}
	return &ExfiltrationDetector{
		cfg:   cfg,
		state: make(map[types.UID]*exfilState),
	}
}

// Name returns the detector name (used in metrics labels).
func (d *ExfiltrationDetector) Name() string { return "exfiltration" }

// Evaluate runs the heuristic. State is keyed on the resolved Subject
// UID — events from External (unresolved) sources skip the detector
// since rarely-seen external sources don't have a meaningful "window".
func (d *ExfiltrationDetector) Evaluate(ev *dnsevent.DNSEvent) Finding {
	if ev == nil || ev.SubjectUID == "" {
		return Finding{}
	}
	if ev.QType != "A" && ev.QType != "AAAA" && ev.QType != "TXT" {
		return Finding{}
	}
	leftLabel := leftmostLabel(ev.QName)
	if len(leftLabel) < d.cfg.MinLabelLen {
		return Finding{}
	}
	entropy := shannonEntropy(leftLabel)
	if entropy < d.cfg.MinEntropy {
		return Finding{}
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.state[ev.SubjectUID]
	if !ok {
		st = &exfilState{}
		d.state[ev.SubjectUID] = st
	}
	st.totalSeen++
	st.highEntropyCount++
	st.totalPayloadLen += ev.PayloadLen
	if st.totalSeen > d.cfg.WindowSize {
		// Roll the window: count proportionally back to the threshold
		// so a sustained slow burn doesn't decay too fast.
		st.totalSeen = d.cfg.WindowSize
		if st.highEntropyCount > d.cfg.WindowSize {
			st.highEntropyCount = d.cfg.WindowSize
		}
	}

	if st.highEntropyCount < d.cfg.ConsecutiveTriggers {
		return Finding{}
	}
	// Reset the count after firing so repeat-fires require fresh
	// signals (avoids a single burst → infinite alerts).
	consecutive := st.highEntropyCount
	totalLen := st.totalPayloadLen
	st.highEntropyCount = 0
	st.totalPayloadLen = 0

	return Finding{
		Type:     securityv1alpha1.TypeDNSExfiltration,
		Severity: string(securityv1alpha1.SeverityHigh),
		Subject:  subjectFromEvent(ev),
		Signals: map[string]string{
			"qname_sample":      ev.QName,
			"entropy_avg":       strconv.FormatFloat(entropy, 'f', 2, 64),
			"payload_len_total": strconv.Itoa(totalLen),
			"consecutive_count": strconv.Itoa(consecutive),
		},
	}
}

// shannonEntropy returns Shannon entropy in bits of `s`.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[byte]int, 64)
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// leftmostLabel returns the first dot-separated label of an FQDN.
// "abc.example.com." → "abc". "noeolDots" → "noeolDots".
func leftmostLabel(qname string) string {
	qname = strings.TrimSuffix(qname, ".")
	if i := strings.IndexByte(qname, '.'); i >= 0 {
		return qname[:i]
	}
	return qname
}

func subjectFromEvent(ev *dnsevent.DNSEvent) Subject {
	if ev.Pod.Namespace == "" || ev.Pod.Name == "" {
		s := Subject{Kind: "External", Unresolved: true}
		if ev.SrcIP != nil {
			s.Name = ev.SrcIP.String()
		}
		return s
	}
	return Subject{
		Kind:      "Pod",
		Namespace: ev.Pod.Namespace,
		Name:      ev.Pod.Name,
		UID:       ev.SubjectUID,
	}
}
