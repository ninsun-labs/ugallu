// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package logger_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/logger"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

// signTestEnvelope returns a real DSSE envelope produced by an
// in-process Ed25519 signer plus its PEM-encoded public key.
func signTestEnvelope(t *testing.T) (env *sign.SignedEnvelope, publicKeyPEM []byte) {
	t.Helper()
	s, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	env, err = s.Sign(context.Background(), []byte(`{"hello":"world"}`), sign.StatementMediaType)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	publicKeyPEM, err = s.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	return env, publicKeyPEM
}

// TestRekorLogger_LogHappyPath verifies the request shape sent to
// Rekor and the parsing of a 201 response with an inclusion proof.
func TestRekorLogger_LogHappyPath(t *testing.T) {
	env, pem := signTestEnvelope(t)

	var (
		sawMethod      string
		sawPath        string
		sawContentType string
		sawBody        []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMethod = r.Method
		sawPath = r.URL.Path
		sawContentType = r.Header.Get("Content-Type")
		sawBody, _ = io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
			"abc-uuid-123": {
				"logIndex": 42,
				"logID": "deadbeef",
				"integratedTime": 1700000000,
				"body": "redacted",
				"verification": {
					"inclusionProof": {
						"logIndex": 42,
						"treeSize": 100,
						"rootHash": "abcd",
						"hashes": ["h1", "h2"]
					},
					"signedEntryTimestamp": "set-base64"
				}
			}
		}`))
	}))
	defer srv.Close()

	rl, err := logger.NewRekorLogger(srv.URL, pem)
	if err != nil {
		t.Fatalf("NewRekorLogger: %v", err)
	}

	entry, err := rl.Log(context.Background(), env)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	if sawMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", sawMethod)
	}
	if sawPath != "/api/v1/log/entries" {
		t.Errorf("path = %q, want /api/v1/log/entries", sawPath)
	}
	if sawContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", sawContentType)
	}

	// Verify request body shape: kind/apiVersion + nested intoto envelope.
	var got map[string]any
	if err = json.Unmarshal(sawBody, &got); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if got["kind"] != "intoto" {
		t.Errorf("kind = %v, want intoto", got["kind"])
	}
	if got["apiVersion"] != "0.0.2" {
		t.Errorf("apiVersion = %v, want 0.0.2", got["apiVersion"])
	}
	spec, _ := got["spec"].(map[string]any)
	content, _ := spec["content"].(map[string]any)
	envObj, _ := content["envelope"].(map[string]any)
	sigs, _ := envObj["signatures"].([]any)
	if len(sigs) != 1 {
		t.Fatalf("signatures len = %d, want 1", len(sigs))
	}
	sig0, _ := sigs[0].(map[string]any)
	if pubKey, _ := sig0["publicKey"].(string); pubKey == "" {
		t.Error("signature.publicKey is empty; PEM not embedded")
	}
	if keyid, _ := sig0["keyid"].(string); !strings.HasPrefix(keyid, "ed25519:") {
		t.Errorf("signature.keyid = %q, want ed25519: prefix", keyid)
	}

	// Rekor v0.0.2 wire format requires double-base64 on payload + sig
	// (DecodeEntry decodes once, dsse.Verify decodes again). Walk the
	// envelope.payload field through both decode rounds; the result
	// must equal the original DSSE payload bytes.
	wirePayload, _ := envObj["payload"].(string)
	once, err := base64.StdEncoding.DecodeString(wirePayload)
	if err != nil {
		t.Fatalf("first base64 decode of payload failed: %v", err)
	}
	twice, err := base64.StdEncoding.DecodeString(string(once))
	if err != nil {
		t.Fatalf("second base64 decode of payload failed (single-encoded?): %v", err)
	}
	if !bytes.Equal(twice, env.Payload) {
		t.Errorf("payload roundtrip mismatch after double-decode")
	}
	wireSig, _ := sig0["sig"].(string)
	sigOnce, err := base64.StdEncoding.DecodeString(wireSig)
	if err != nil {
		t.Fatalf("first base64 decode of sig failed: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(string(sigOnce)); err != nil {
		t.Fatalf("second base64 decode of sig failed (single-encoded?): %v", err)
	}

	// Verify parsed response.
	if entry.UUID != "abc-uuid-123" {
		t.Errorf("UUID = %q, want abc-uuid-123", entry.UUID)
	}
	if entry.LogIndex != 42 {
		t.Errorf("LogIndex = %d, want 42", entry.LogIndex)
	}
	if entry.IntegratedTime != 1700000000 {
		t.Errorf("IntegratedTime = %d", entry.IntegratedTime)
	}
	if entry.InclusionProof == nil {
		t.Fatal("InclusionProof is nil")
	}
	if entry.InclusionProof.TreeSize != 100 {
		t.Errorf("TreeSize = %d, want 100", entry.InclusionProof.TreeSize)
	}
	if got, want := strings.Join(entry.InclusionProof.Hashes, ","), "h1,h2"; got != want {
		t.Errorf("Hashes = %q, want %q", got, want)
	}
}

// TestRekorLogger_LogServerError verifies non-2xx responses surface
// as errors with the upstream body included.
func TestRekorLogger_LogServerError(t *testing.T) {
	env, pem := signTestEnvelope(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":500,"message":"oops"}`))
	}))
	defer srv.Close()

	rl, err := logger.NewRekorLogger(srv.URL, pem)
	if err != nil {
		t.Fatalf("NewRekorLogger: %v", err)
	}

	_, err = rl.Log(context.Background(), env)
	if err == nil {
		t.Fatal("Log accepted a 500 response, want error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want it to mention 500 status", err)
	}
}

// TestRekorLogger_NewRejectsEmptyPEM verifies missing public key fails
// at constructor time.
func TestRekorLogger_NewRejectsEmptyPEM(t *testing.T) {
	if _, err := logger.NewRekorLogger("https://example", nil); err == nil {
		t.Fatal("NewRekorLogger(nil PEM) accepted, want error")
	}
}

// TestRekorLogger_DefaultURL verifies an empty URL falls back to the
// public Sigstore Rekor instance.
func TestRekorLogger_DefaultURL(t *testing.T) {
	_, pem := signTestEnvelope(t)
	rl, err := logger.NewRekorLogger("", pem)
	if err != nil {
		t.Fatalf("NewRekorLogger: %v", err)
	}
	if rl.Endpoint() != logger.DefaultRekorURL {
		t.Errorf("Endpoint = %q, want %q", rl.Endpoint(), logger.DefaultRekorURL)
	}
}

// TestRekorLogger_LogMalformedResponse verifies invalid JSON in the
// 200 response surfaces as a clear error.
func TestRekorLogger_LogMalformedResponse(t *testing.T) {
	env, pem := signTestEnvelope(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	rl, err := logger.NewRekorLogger(srv.URL, pem)
	if err != nil {
		t.Fatalf("NewRekorLogger: %v", err)
	}
	if _, err := rl.Log(context.Background(), env); err == nil {
		t.Fatal("Log accepted malformed JSON, want error")
	}
}
