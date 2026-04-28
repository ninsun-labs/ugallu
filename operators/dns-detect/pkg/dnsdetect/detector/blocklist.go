// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"strings"
	"sync"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsdetect"
)

// BlocklistDetector matches qname against an admin-curated FQDN list.
// The list is loaded by the reconciler (ConfigMap watch) and pushed
// via SetEntries. Two match flavours: exact, and suffix (entry starts
// with "*.", matching any subdomain).
type BlocklistDetector struct {
	mu      sync.RWMutex
	exact   map[string]string // qname → blocklist source name
	suffix  map[string]string // ".example.com" → blocklist source name
}

// NewBlocklistDetector starts with an empty list.
func NewBlocklistDetector() *BlocklistDetector {
	return &BlocklistDetector{
		exact:  make(map[string]string),
		suffix: make(map[string]string),
	}
}

// SetEntries replaces the active blocklist atomically. entries is a
// map of pattern → source (typically the ConfigMap name; recorded as
// SE Signal so admins know which list flagged the query).
func (d *BlocklistDetector) SetEntries(entries map[string]string) {
	exact := make(map[string]string, len(entries))
	suffix := make(map[string]string, len(entries))
	for pattern, src := range entries {
		pattern = strings.TrimSpace(strings.ToLower(pattern))
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			// Suffix match — store with leading dot for fast lookup.
			suffix["."+pattern[2:]] = src
		} else {
			exact[pattern] = src
		}
	}
	d.mu.Lock()
	d.exact = exact
	d.suffix = suffix
	d.mu.Unlock()
}

// Name returns the detector name.
func (d *BlocklistDetector) Name() string { return "blocklist" }

// Evaluate matches qname (case-insensitive, trailing-dot-stripped)
// against the active blocklist.
func (d *BlocklistDetector) Evaluate(ev *dnsdetect.DNSEvent) Finding {
	if ev == nil {
		return Finding{}
	}
	qname := strings.ToLower(strings.TrimSuffix(ev.QName, "."))
	if qname == "" {
		return Finding{}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	if src, ok := d.exact[qname]; ok {
		return d.fire(ev, qname, src, "exact")
	}
	for suff, src := range d.suffix {
		if strings.HasSuffix(qname, suff) {
			return d.fire(ev, qname, src, "suffix"+suff)
		}
	}
	return Finding{}
}

func (d *BlocklistDetector) fire(ev *dnsdetect.DNSEvent, qname, src, matchedPattern string) Finding {
	return Finding{
		Type:     securityv1alpha1.TypeDNSToBlocklistedFQDN,
		Severity: string(securityv1alpha1.SeverityHigh),
		Subject:  subjectFromEvent(ev),
		Signals: map[string]string{
			"matched_pattern":  matchedPattern,
			"qname":            qname,
			"blocklist_source": src,
		},
	}
}
