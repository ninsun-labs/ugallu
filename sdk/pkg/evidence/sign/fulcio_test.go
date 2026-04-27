// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

// fakeFulcio is a minimal /api/v2/signingCert mock that issues real
// short-lived certs from a self-signed CA. The CA + signing logic is
// realistic enough for verifiers to parse / verify the chain end to
// end.
type fakeFulcio struct {
	srv          *httptest.Server
	caCert       *x509.Certificate
	caKey        *ecdsa.PrivateKey
	calls        atomic.Int32
	popMustMatch string // when non-empty, requests with a non-matching PoP get rejected
	notAfter     time.Time
}

func newFakeFulcio(t *testing.T) *fakeFulcio {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca keygen: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake-fulcio-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca self-sign: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	f := &fakeFulcio{caCert: caCert, caKey: caKey, notAfter: time.Now().Add(10 * time.Minute)}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeFulcio) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v2/signingCert" || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	f.calls.Add(1)
	var req struct {
		Credentials struct {
			OIDCIdentityToken string `json:"oidcIdentityToken"`
		} `json:"credentials"`
		PublicKeyRequest struct {
			PublicKey struct {
				Algorithm string `json:"algorithm"`
				Content   string `json:"content"`
			} `json:"publicKey"`
			ProofOfPossession string `json:"proofOfPossession"`
		} `json:"publicKeyRequest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Decode the supplied ED25519 public key.
	block, _ := pem.Decode([]byte(req.PublicKeyRequest.PublicKey.Content))
	if block == nil {
		http.Error(w, "public key not PEM-encoded", http.StatusBadRequest)
		return
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		http.Error(w, "parse public key: "+err.Error(), http.StatusBadRequest)
		return
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		http.Error(w, "expected ed25519 public key", http.StatusBadRequest)
		return
	}
	// Verify proof of possession against the OIDC subject claim.
	parts := strings.Split(req.Credentials.OIDCIdentityToken, ".")
	if len(parts) < 2 {
		http.Error(w, "OIDC token is not a JWT", http.StatusBadRequest)
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		http.Error(w, "decode JWT payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	if uErr := json.Unmarshal(payload, &claims); uErr != nil {
		http.Error(w, "decode claims: "+uErr.Error(), http.StatusBadRequest)
		return
	}
	subj := claims.Email
	if subj == "" {
		subj = claims.Sub
	}
	popSig, err := base64.StdEncoding.DecodeString(req.PublicKeyRequest.ProofOfPossession)
	if err != nil {
		http.Error(w, "decode pop: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !ed25519.Verify(pub, []byte(subj), popSig) {
		http.Error(w, "proof of possession failed", http.StatusForbidden)
		return
	}
	if f.popMustMatch != "" && !strings.Contains(string(popSig), f.popMustMatch) {
		http.Error(w, "test gate", http.StatusForbidden)
		return
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ugallu-attestor"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     f.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		EmailAddresses: func() []string {
			if claims.Email != "" {
				return []string{claims.Email}
			}
			return nil
		}(),
		URIs: nil,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, f.caCert, pub, f.caKey)
	if err != nil {
		http.Error(w, "issue cert: "+err.Error(), http.StatusInternalServerError)
		return
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw})
	resp := map[string]any{
		"signedCertificateEmbeddedSct": map[string]any{
			"chain": map[string]any{
				"certificates": []string{string(leafPEM), string(caPEM)},
			},
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// makeFakeOIDCToken returns an unsigned JWT carrying the given subject
// + email claims. Fulcio (real) verifies signatures upstream; the fake
// only inspects payload claims so an unsigned token is sufficient.
func makeFakeOIDCToken(t *testing.T, sub, email string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	body, err := json.Marshal(map[string]any{
		"iss":   "https://kubernetes.default.svc.cluster.local",
		"sub":   sub,
		"email": email,
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
}

// writeOIDCToken persists an OIDC token to a temp file and returns its
// path; mirrors writeSAToken from openbao_test.go.
func writeOIDCToken(t *testing.T, jwt string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oidc-token")
	if err := os.WriteFile(path, []byte(jwt+"\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return path
}

// TestFulcioSigner_SignVerifyRoundtrip exercises the full path: ephemeral
// keypair → Fulcio signingCert → DSSE sign → VerifyDSSE.
func TestFulcioSigner_SignVerifyRoundtrip(t *testing.T) {
	f := newFakeFulcio(t)
	jwt := makeFakeOIDCToken(t, "system:serviceaccount:ugallu-system:attestor", "attestor@ugallu.io")
	tokenPath := writeOIDCToken(t, jwt)

	signer, err := sign.NewFulcioSigner(context.Background(), &sign.FulcioSignerOptions{
		FulcioURL:     f.srv.URL,
		OIDCTokenPath: tokenPath,
	})
	if err != nil {
		t.Fatalf("NewFulcioSigner: %v", err)
	}
	if signer.Mode() != securityv1alpha1.SigningModeFulcioKeyless {
		t.Errorf("Mode = %q, want fulcio-keyless", signer.Mode())
	}
	payload := []byte(`{"hello":"world"}`)
	env, err := signer.Sign(context.Background(), payload, sign.StatementMediaType)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	leafPEM, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		t.Fatal("leaf is not PEM-encoded")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("leaf carries %T, want ed25519.PublicKey", cert.PublicKey)
	}
	if err := sign.VerifyDSSE(pub, env, signer.KeyID()); err != nil {
		t.Errorf("VerifyDSSE: %v", err)
	}
	if !strings.HasPrefix(signer.KeyID(), "fulcio:attestor@ugallu.io:") {
		t.Errorf("KeyID = %q, want fulcio:attestor@ugallu.io:* prefix", signer.KeyID())
	}
}

// TestFulcioSigner_CertCachedAcrossSigns asserts that a sequence of
// Sign() calls reuses the same cert when valid.
func TestFulcioSigner_CertCachedAcrossSigns(t *testing.T) {
	f := newFakeFulcio(t)
	jwt := makeFakeOIDCToken(t, "system:serviceaccount:ugallu-system:attestor", "attestor@ugallu.io")
	tokenPath := writeOIDCToken(t, jwt)

	signer, err := sign.NewFulcioSigner(context.Background(), &sign.FulcioSignerOptions{
		FulcioURL:     f.srv.URL,
		OIDCTokenPath: tokenPath,
	})
	if err != nil {
		t.Fatalf("NewFulcioSigner: %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, err := signer.Sign(context.Background(), []byte("payload"), "application/test"); err != nil {
			t.Fatalf("Sign #%d: %v", i, err)
		}
	}
	if got := f.calls.Load(); got != 1 {
		t.Errorf("signingCert calls = %d, want 1 (cert must be cached)", got)
	}
}

// TestFulcioSigner_RefreshesNearExpiry verifies the cert is re-issued
// once we cross the refresh-before threshold.
func TestFulcioSigner_RefreshesNearExpiry(t *testing.T) {
	f := newFakeFulcio(t)
	f.notAfter = time.Now().Add(100 * time.Millisecond) // tiny TTL
	jwt := makeFakeOIDCToken(t, "system:serviceaccount:ugallu-system:attestor", "")
	tokenPath := writeOIDCToken(t, jwt)

	signer, err := sign.NewFulcioSigner(context.Background(), &sign.FulcioSignerOptions{
		FulcioURL:         f.srv.URL,
		OIDCTokenPath:     tokenPath,
		CertRefreshBefore: 5 * time.Second, // refresh window > issued TTL
	})
	if err != nil {
		t.Fatalf("NewFulcioSigner: %v", err)
	}
	if _, err := signer.Sign(context.Background(), []byte("p"), "t"); err != nil {
		t.Fatalf("first sign: %v", err)
	}
	// Second sign immediately: cert is within refresh window so
	// signer reissues.
	if _, err := signer.Sign(context.Background(), []byte("p"), "t"); err != nil {
		t.Fatalf("second sign: %v", err)
	}
	if got := f.calls.Load(); got < 2 {
		t.Errorf("signingCert calls = %d, want >= 2", got)
	}
}

// TestFulcioSigner_NewRejectsMissingFields validates constructor guards.
func TestFulcioSigner_NewRejectsMissingFields(t *testing.T) {
	cases := []struct {
		name string
		opts *sign.FulcioSignerOptions
	}{
		{"nil opts", nil},
		{"empty url", &sign.FulcioSignerOptions{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sign.NewFulcioSigner(context.Background(), tc.opts); err == nil {
				t.Errorf("NewFulcioSigner accepted invalid opts %+v", tc.opts)
			}
		})
	}
}

// TestFulcioSigner_FactoryWiring asserts NewSigner dispatches correctly.
func TestFulcioSigner_FactoryWiring(t *testing.T) {
	f := newFakeFulcio(t)
	jwt := makeFakeOIDCToken(t, "system:serviceaccount:ugallu-system:attestor", "")
	tokenPath := writeOIDCToken(t, jwt)
	signer, err := sign.NewSigner(
		context.Background(),
		securityv1alpha1.SigningModeFulcioKeyless,
		&sign.FactoryOptions{
			Fulcio: &sign.FulcioSignerOptions{
				FulcioURL:     f.srv.URL,
				OIDCTokenPath: tokenPath,
			},
		},
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if signer.Mode() != securityv1alpha1.SigningModeFulcioKeyless {
		t.Errorf("mode = %q, want fulcio-keyless", signer.Mode())
	}
}

// TestFulcioSigner_FactoryRejectsMissingOpts asserts the factory fails
// fast when the Fulcio mode is requested without options.
func TestFulcioSigner_FactoryRejectsMissingOpts(t *testing.T) {
	if _, err := sign.NewSigner(
		context.Background(),
		securityv1alpha1.SigningModeFulcioKeyless,
		nil,
	); err == nil {
		t.Fatal("factory accepted fulcio-keyless without opts")
	}
}
