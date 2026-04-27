// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

// fakeOpenBao mounts an httptest.Server that mocks the OpenBao HTTP
// API surface OpenBaoSigner exercises:
//   - POST /v1/auth/kubernetes/login   → returns a client token
//   - GET  /v1/transit/keys/<name>     → returns key metadata + PEM
//   - POST /v1/transit/sign/<name>     → returns vault:v1:<base64>
type fakeOpenBao struct {
	srv          *httptest.Server
	pubPEM       []byte
	priv         ed25519.PrivateKey
	loginCalls   atomic.Int32
	signCalls    atomic.Int32
	keyReadCalls atomic.Int32
}

func newFakeOpenBao(t *testing.T) *fakeOpenBao {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	f := &fakeOpenBao{pubPEM: pubPEM, priv: priv}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOpenBao) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/auth/kubernetes/login"):
		f.loginCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   "test-token-abc",
				"lease_duration": 600,
			},
		})
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/v1/transit/keys/"):
		f.keyReadCalls.Add(1)
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"latest_version": 1,
				"keys": map[string]any{
					"1": map[string]any{
						"public_key": string(f.pubPEM),
					},
				},
			},
		})
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/v1/transit/sign/"):
		f.signCalls.Add(1)
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var req struct {
			Input string `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		input, err := base64.StdEncoding.DecodeString(req.Input)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Real Ed25519 signature so callers can verify roundtrip.
		sig := ed25519.Sign(f.priv, input)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig),
			},
		})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// writeSAToken writes a fake projected SA token in t.TempDir() and
// returns the path. The token content is intentionally non-empty
// so the auth login wire request carries a value (the fake OpenBao
// doesn't validate it).
func writeSAToken(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("fake.jwt.token\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return path
}

// TestOpenBaoSigner_SignVerifyRoundtrip exercises the happy path end to
// end: construct → sign → verify the signature with the fake server's
// public key.
func TestOpenBaoSigner_SignVerifyRoundtrip(t *testing.T) {
	f := newFakeOpenBao(t)
	tokenPath := writeSAToken(t)

	signer, err := sign.NewOpenBaoSigner(context.Background(), &sign.OpenBaoSignerOptions{
		Address:     f.srv.URL,
		KeyName:     "ugallu-attestor",
		AuthRole:    "ugallu-attestor",
		SATokenPath: tokenPath,
	})
	if err != nil {
		t.Fatalf("NewOpenBaoSigner: %v", err)
	}

	if !strings.HasPrefix(signer.KeyID(), "openbao:transit/ugallu-attestor:") {
		t.Errorf("KeyID = %q, want openbao:transit/ugallu-attestor:* prefix", signer.KeyID())
	}
	if signer.Mode() != securityv1alpha1.SigningModeOpenBaoTransit {
		t.Errorf("Mode = %q, want openbao-transit", signer.Mode())
	}

	payload := []byte(`{"hello":"world"}`)
	env, err := signer.Sign(context.Background(), payload, sign.StatementMediaType)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify the DSSE envelope using the fake server's public key.
	pemBytes, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want ed25519.PublicKey", pubAny)
	}
	if err := sign.VerifyDSSE(pub, env, signer.KeyID()); err != nil {
		t.Errorf("VerifyDSSE: %v", err)
	}

	// Calls accounting: 1 login (lazy on first sign), 1 keyRead (at
	// constructor time), 1 sign (this test).
	if got := f.loginCalls.Load(); got != 1 {
		t.Errorf("login calls = %d, want 1", got)
	}
	if got := f.keyReadCalls.Load(); got != 1 {
		t.Errorf("keyRead calls = %d, want 1", got)
	}
	if got := f.signCalls.Load(); got != 1 {
		t.Errorf("sign calls = %d, want 1", got)
	}
}

// TestOpenBaoSigner_TokenCachedAcrossSigns asserts that a sequence of
// Sign() calls reuses the same vault token (no spurious /login on
// every signature).
func TestOpenBaoSigner_TokenCachedAcrossSigns(t *testing.T) {
	f := newFakeOpenBao(t)
	tokenPath := writeSAToken(t)
	signer, err := sign.NewOpenBaoSigner(context.Background(), &sign.OpenBaoSignerOptions{
		Address:     f.srv.URL,
		KeyName:     "k",
		AuthRole:    "ugallu-attestor",
		SATokenPath: tokenPath,
	})
	if err != nil {
		t.Fatalf("NewOpenBaoSigner: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := signer.Sign(context.Background(), []byte("payload"), "application/test"); err != nil {
			t.Fatalf("Sign #%d: %v", i, err)
		}
	}
	if got := f.loginCalls.Load(); got != 1 {
		t.Errorf("login calls = %d, want 1 (token must be cached)", got)
	}
	if got := f.signCalls.Load(); got != 5 {
		t.Errorf("sign calls = %d, want 5", got)
	}
}

// TestOpenBaoSigner_NewRejectsMissingFields validates the constructor
// guards against zero-value mandatory fields.
func TestOpenBaoSigner_NewRejectsMissingFields(t *testing.T) {
	cases := []struct {
		name string
		opts *sign.OpenBaoSignerOptions
	}{
		{"nil opts", nil},
		{"empty address", &sign.OpenBaoSignerOptions{KeyName: "k", AuthRole: "r"}},
		{"empty key", &sign.OpenBaoSignerOptions{Address: "https://x", AuthRole: "r"}},
		{"empty role", &sign.OpenBaoSignerOptions{Address: "https://x", KeyName: "k"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sign.NewOpenBaoSigner(context.Background(), tc.opts); err == nil {
				t.Errorf("NewOpenBaoSigner accepted invalid opts %+v", tc.opts)
			}
		})
	}
}

// TestOpenBaoSigner_FactoryWiring verifies sign.NewSigner dispatches
// to OpenBaoSigner when given mode=openbao-transit + opts.OpenBao.
func TestOpenBaoSigner_FactoryWiring(t *testing.T) {
	f := newFakeOpenBao(t)
	tokenPath := writeSAToken(t)
	signer, err := sign.NewSigner(
		context.Background(),
		securityv1alpha1.SigningModeOpenBaoTransit,
		&sign.FactoryOptions{
			OpenBao: &sign.OpenBaoSignerOptions{
				Address:     f.srv.URL,
				KeyName:     "k",
				AuthRole:    "r",
				SATokenPath: tokenPath,
			},
		},
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if signer.Mode() != securityv1alpha1.SigningModeOpenBaoTransit {
		t.Errorf("mode = %q, want openbao-transit", signer.Mode())
	}
}

// TestOpenBaoSigner_FactoryRejectsMissingOpts asserts the factory
// fails fast when openbao mode is requested without options.
func TestOpenBaoSigner_FactoryRejectsMissingOpts(t *testing.T) {
	if _, err := sign.NewSigner(
		context.Background(),
		securityv1alpha1.SigningModeOpenBaoTransit,
		nil,
	); err == nil {
		t.Fatal("factory accepted openbao-transit without opts")
	}
}
