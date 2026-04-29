// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsevent"
)

// base64Pattern matches a label that looks like base64 (16+ chars,
// optional padding). Tightened to avoid matching short alphanum
// hashes that aren't tunneling payloads.
var base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]{16,}={0,2}$`)

// TunnelingConfig matches DNSDetectConfig.spec.detectors.tunneling.
type TunnelingConfig struct {
	RatelimitPerPod time.Duration // 0 → 1 minute
}

// TunnelingDetector flags base64-decodable subdomain labels.
type TunnelingDetector struct {
	cfg      TunnelingConfig
	mu       sync.Mutex
	lastFire map[types.UID]time.Time
	now      func() time.Time // injectable for tests
}

// NewTunnelingDetector returns a detector with defaults applied.
func NewTunnelingDetector(cfg TunnelingConfig) *TunnelingDetector {
	if cfg.RatelimitPerPod <= 0 {
		cfg.RatelimitPerPod = time.Minute
	}
	return &TunnelingDetector{
		cfg:      cfg,
		lastFire: make(map[types.UID]time.Time),
		now:      time.Now,
	}
}

// Name returns the detector name.
func (d *TunnelingDetector) Name() string { return "tunneling" }

// Evaluate runs the heuristic. Returns at most one Finding per
// (Pod-or-SrcIP, ratelimitPerPod) window. Falls back to a SrcIP-
// derived synthetic UID when the event has no resolved SubjectUID
// (the resolver wiring is a Wave 4 follow-up).
func (d *TunnelingDetector) Evaluate(ev *dnsevent.DNSEvent) Finding {
	if ev == nil {
		return Finding{}
	}
	leftLabel := leftmostLabel(ev.QName)
	if !base64Pattern.MatchString(leftLabel) {
		return Finding{}
	}
	decoded, err := base64.StdEncoding.DecodeString(leftLabel)
	if err != nil {
		// Try URL-safe variant (base64.RawURLEncoding strips padding,
		// but the regex insisted on padding so RawURL is irrelevant
		// here; keep the StdEncoding-only path for now).
		return Finding{}
	}
	if shannonEntropy(string(decoded)) < 3.5 {
		// Decoded payload is too low-entropy → likely a coincidental
		// alphanumeric match, not real binary content.
		return Finding{}
	}

	rateKey := ev.SubjectUID
	if rateKey == "" {
		if ev.SrcIP == nil {
			return Finding{}
		}
		rateKey = types.UID("ip-" + ev.SrcIP.String())
	}

	d.mu.Lock()
	last, seen := d.lastFire[rateKey]
	now := d.now()
	if seen && now.Sub(last) < d.cfg.RatelimitPerPod {
		d.mu.Unlock()
		return Finding{}
	}
	d.lastFire[rateKey] = now
	d.mu.Unlock()

	sample := decoded
	if len(sample) > 32 {
		sample = sample[:32]
	}
	return Finding{
		Type:     securityv1alpha1.TypeDNSTunneling,
		Severity: string(securityv1alpha1.SeverityHigh),
		Subject:  subjectFromEvent(ev),
		Signals: map[string]string{
			"decoded_sample": hex.EncodeToString(sample),
			"qname":          ev.QName,
		},
	}
}
