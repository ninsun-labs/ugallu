// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// CABundleAnalysis is the deterministic verdict the RiskEvaluator
// reads. ChainSubjectDNs are RFC 4514 canonical DNs of every cert in
// the bundle (root last by convention — matching is set-based, so
// position-in-chain assumptions never apply).
type CABundleAnalysis struct {
	// Empty is true when the caBundle field on the webhook is unset
	// or all-whitespace. Treated as max-conservative (untrusted) at
	// scoring time.
	Empty bool

	// ParseError holds the first parse failure encountered. When non-empty
	// the bundle is treated as untrusted (defensive default).
	ParseError string

	// ChainSubjectDNs lists every certificate's subject DN in RFC 4514
	// canonical form (CN first, then O, then C, etc.). Use
	// MatchTrustedDN to test against a whitelist. (DN here = X.509
	// Distinguished Name, not Domain Name System — the linter doesn't
	// know the difference.)
	ChainSubjectDNs []string //nolint:revive // DN is X.509 Distinguished Name
}

// AnalyzeCABundle parses a PEM-encoded caBundle (the format webhooks
// use). Returns Empty=true when bytes is nil or whitespace; else
// returns ParseError when no certs decode (invalid PEM); else returns
// the chain subject DNs in canonical form.
//
// The function is pure — no Secret reads, no API calls. Callers that
// follow indirect caBundle references (e.g. Secret-injected by
// cert-manager) dereference upstream and pass the resolved bytes.
func AnalyzeCABundle(bytes []byte) CABundleAnalysis {
	trimmed := strings.TrimSpace(string(bytes))
	if trimmed == "" {
		return CABundleAnalysis{Empty: true}
	}

	dns := make([]string, 0, 2)
	rest := []byte(trimmed)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return CABundleAnalysis{
				ParseError: fmt.Sprintf("cert parse: %v", err),
			}
		}
		dns = append(dns, CanonicalDN(cert.Subject.String()))
	}
	if len(dns) == 0 {
		return CABundleAnalysis{
			ParseError: "no CERTIFICATE PEM block found in caBundle",
		}
	}
	return CABundleAnalysis{ChainSubjectDNs: dns}
}

// CanonicalDN normalises an X.509 RDN string to RFC 4514 canonical
// form (sorted attribute pairs within each RDN, attribute names
// upper-cased: CN, O, OU, L, ST, C). This makes whitelist comparison
// stable across rotations and across the slight stylistic differences
// of PKI tooling.
//
// Input examples:
//
//	"CN=cert-manager.io, O=Jetstack, L=London, C=GB"
//	"O=Jetstack,CN=cert-manager.io,L=London,C=GB"
//
// Both produce: "CN=cert-manager.io,O=Jetstack,L=London,C=GB".
func CanonicalDN(dn string) string {
	parts := splitTopLevel(dn, ',')
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	// Each part is a single attribute "ATTR=value" (no multi-valued
	// RDNs in K8s admission webhooks in practice). Upper-case attr.
	for i, p := range parts {
		eq := strings.IndexByte(p, '=')
		if eq <= 0 {
			continue
		}
		attr := strings.ToUpper(strings.TrimSpace(p[:eq]))
		val := strings.TrimSpace(p[eq+1:])
		parts[i] = attr + "=" + val
	}
	// Stable sort by attribute weight: CN before O before OU before L
	// before ST before C, then alpha. Stable sort preserves any
	// caller-meaningful order between equal-weight attrs (rare).
	sort.SliceStable(parts, func(i, j int) bool {
		return attrWeight(attrOf(parts[i])) < attrWeight(attrOf(parts[j]))
	})
	return strings.Join(parts, ",")
}

// MatchTrustedDN returns true when at least one DN in the analysis
// chain matches the trustedDNs allowlist (each itself in canonical
// form, checked symmetrically: caller-supplied list is canonicalised
// once).
func MatchTrustedDN(analysis CABundleAnalysis, trustedDNs []string) bool { //nolint:revive // DN is X.509 Distinguished Name
	if len(analysis.ChainSubjectDNs) == 0 {
		return false
	}
	canonTrusted := make(map[string]struct{}, len(trustedDNs))
	for _, t := range trustedDNs {
		canonTrusted[CanonicalDN(t)] = struct{}{}
	}
	for _, d := range analysis.ChainSubjectDNs {
		if _, ok := canonTrusted[d]; ok {
			return true
		}
	}
	return false
}

// ErrEmptyCABundle is exported so callers can distinguish "untrusted
// because no bundle" from "untrusted because parse error" if they
// want to.
var ErrEmptyCABundle = errors.New("caBundle is empty")

// --- helpers ---------------------------------------------------------

func attrOf(part string) string {
	eq := strings.IndexByte(part, '=')
	if eq <= 0 {
		return ""
	}
	return part[:eq]
}

// attrWeight orders the common DN attributes for canonical sort.
// Unknown attributes land after C (weight 100).
func attrWeight(attr string) int {
	switch attr {
	case "CN":
		return 1
	case "O":
		return 2
	case "OU":
		return 3
	case "L":
		return 4
	case "ST":
		return 5
	case "C":
		return 6
	default:
		return 100
	}
}

// splitTopLevel splits s on sep but respects backslash escapes. RFC
// 4514 allows escaped commas inside a value ("CN=foo\, bar"). The
// splitter walks one rune at a time.
func splitTopLevel(s string, sep byte) []string {
	out := make([]string, 0, 4)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
