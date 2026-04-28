// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestCanonicalDN(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"already canonical", "CN=cert-manager.io,O=Jetstack", "CN=cert-manager.io,O=Jetstack"},
		{"reorder + casing", "o=Jetstack, cn=cert-manager.io, l=London", "CN=cert-manager.io,O=Jetstack,L=London"},
		{"trailing whitespace", "  CN=foo ,  O=bar ", "CN=foo,O=bar"},
		{"unknown attr lands last", "X=weird,CN=foo", "CN=foo,X=weird"},
		{"escaped comma in value", `CN=foo\, bar,O=org`, `CN=foo\, bar,O=org`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanonicalDN(tc.in); got != tc.want {
				t.Errorf("CanonicalDN(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAnalyzeCABundle_Empty(t *testing.T) {
	for _, in := range [][]byte{nil, []byte(""), []byte("   \n\t  ")} {
		a := AnalyzeCABundle(in)
		if !a.Empty {
			t.Errorf("AnalyzeCABundle(%q): Empty=false, want true", in)
		}
	}
}

func TestAnalyzeCABundle_ParseError(t *testing.T) {
	a := AnalyzeCABundle([]byte("not a pem block"))
	if a.ParseError == "" {
		t.Errorf("AnalyzeCABundle(garbage): ParseError empty, want non-empty")
	}
}

func TestAnalyzeCABundle_ChainAndMatch(t *testing.T) {
	cn := "test-ca.example"
	pemBytes := generateSelfSignedPEM(t, cn)

	a := AnalyzeCABundle(pemBytes)
	if a.Empty || a.ParseError != "" {
		t.Fatalf("Empty=%v ParseError=%q", a.Empty, a.ParseError)
	}
	if len(a.ChainSubjectDNs) != 1 {
		t.Fatalf("ChainSubjectDNs len = %d, want 1: %+v", len(a.ChainSubjectDNs), a.ChainSubjectDNs)
	}
	want := "CN=" + cn
	if a.ChainSubjectDNs[0] != want {
		t.Errorf("ChainSubjectDNs[0] = %q, want %q", a.ChainSubjectDNs[0], want)
	}

	// Trusted whitelist symmetric on canonical form.
	if !MatchTrustedDN(a, []string{"cn=" + cn}) { // lowercase input — canonicalised
		t.Errorf("MatchTrustedDN should match case-insensitively after canonicalisation")
	}
	if MatchTrustedDN(a, []string{"CN=other.example"}) {
		t.Errorf("MatchTrustedDN matched a foreign DN")
	}
}

// generateSelfSignedPEM builds a tiny ed25519/ECDSA cert for tests.
func generateSelfSignedPEM(t *testing.T, cn string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
