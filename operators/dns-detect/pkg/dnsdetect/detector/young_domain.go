// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"strconv"
	"strings"
	"sync"
	"time"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsdetect"
)

// YoungDomainConfig matches DNSDetectConfig.spec.detectors.youngDomain.
type YoungDomainConfig struct {
	ThresholdDays int
}

// AgeLookup is the indirection the detector uses to ask "how old is
// this domain?". Implementations: RDAPLookup (production) +
// in-memory mock (tests). Returning ageDays<0 means "unknown" — the
// detector treats unknowns as a no-fire (conservative; an outbound
// failure to RDAP should not generate alerts).
type AgeLookup interface {
	AgeDays(domain string) (int, bool)
}

// YoungDomainDetector flags queries for domains registered within
// the last N days. Lookups are async — if the cache hasn't seen the
// domain yet, the query goes through unflagged; the lookup fires in
// the background and a future query for the same domain will be
// evaluated against the cached age.
type YoungDomainDetector struct {
	cfg    YoungDomainConfig
	lookup AgeLookup

	mu       sync.Mutex
	lastFire map[string]time.Time // qname → last fire timestamp
	now      func() time.Time
}

// NewYoungDomainDetector returns a detector wired to lookup. Setting
// lookup=nil disables the detector (useful for air-gapped clusters).
func NewYoungDomainDetector(cfg YoungDomainConfig, lookup AgeLookup) *YoungDomainDetector {
	if cfg.ThresholdDays <= 0 {
		cfg.ThresholdDays = 30
	}
	return &YoungDomainDetector{
		cfg:      cfg,
		lookup:   lookup,
		lastFire: make(map[string]time.Time),
		now:      time.Now,
	}
}

// Name returns the detector name.
func (d *YoungDomainDetector) Name() string { return "young_domain" }

// Evaluate looks up the registrable domain (TLD+1 heuristic) and
// fires when its age is below the threshold.
func (d *YoungDomainDetector) Evaluate(ev *dnsdetect.DNSEvent) Finding {
	if d == nil || d.lookup == nil || ev == nil {
		return Finding{}
	}
	domain := registrableDomain(ev.QName)
	if domain == "" {
		return Finding{}
	}
	age, known := d.lookup.AgeDays(domain)
	if !known {
		// Lookup pending or failed; conservative no-fire.
		return Finding{}
	}
	if age >= d.cfg.ThresholdDays {
		return Finding{}
	}

	// Per-domain rate limit (not per-Pod; same domain hit by many
	// Pods still alerts the cluster admin once per 1h window).
	d.mu.Lock()
	last, seen := d.lastFire[domain]
	now := d.now()
	if seen && now.Sub(last) < time.Hour {
		d.mu.Unlock()
		return Finding{}
	}
	d.lastFire[domain] = now
	d.mu.Unlock()

	return Finding{
		Type:     securityv1alpha1.TypeDNSToYoungDomain,
		Severity: string(securityv1alpha1.SeverityMedium),
		Subject:  subjectFromEvent(ev),
		Signals: map[string]string{
			"qname":           ev.QName,
			"domain_age_days": strconv.Itoa(age),
			"whois_source":    "rdap",
		},
	}
}

// registrableDomain extracts the TLD+1 portion of qname. Crude
// heuristic — "evil.example.com" → "example.com", but won't handle
// PSL-aware cases like "evil.example.co.uk" (returns "co.uk"). PSL
// integration is a follow-up if accuracy proves limiting.
func registrableDomain(qname string) string {
	qname = strings.TrimSuffix(strings.ToLower(qname), ".")
	parts := strings.Split(qname, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}
