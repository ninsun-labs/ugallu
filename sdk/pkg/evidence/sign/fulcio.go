// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// DefaultFulcioOIDCTokenPath is the conventional projected SA token
// mount used as the OIDC identity when running under K8s workload
// identity. Operators that exchange a different token (SPIFFE, Auth0,
// etc.) override this via FulcioConfig.oidcTokenPath.
const DefaultFulcioOIDCTokenPath = "/var/run/secrets/ugallu/fulcio/token" //nolint:gosec // mount path, not a credential

// DefaultFulcioCertTTL is the upper bound on how long we'll reuse a
// Fulcio-issued certificate before re-requesting one. Public Sigstore
// issues 10-minute certs; we refresh well below that to leave headroom
// for clock skew and request latency.
const DefaultFulcioCertTTL = 5 * time.Minute

// fulcioMaxBodyBytes caps response bodies we'll fully read.
const fulcioMaxBodyBytes = 256 * 1024

// FulcioSignerOptions configures a FulcioSigner.
type FulcioSignerOptions struct {
	// FulcioURL is the v2 API base URL — e.g. https://fulcio.sigstore.dev.
	// Required.
	FulcioURL string

	// OIDCTokenPath points at a file holding the OIDC identity token
	// presented to Fulcio. Defaults to DefaultFulcioOIDCTokenPath.
	OIDCTokenPath string

	// HTTPClient is reused across requests when set. nil triggers a
	// default client honouring CABundle / InsecureSkipVerify.
	HTTPClient *http.Client

	// CABundle is PEM-encoded; empty uses the system trust store.
	CABundle []byte

	// InsecureSkipVerify disables TLS verification — dev only.
	InsecureSkipVerify bool

	// CertRefreshBefore is the lead time before cert NotAfter at which
	// we proactively refresh. Defaults to 60s.
	CertRefreshBefore time.Duration

	// MaxCertReuse caps how long a cert is reused regardless of its
	// NotAfter (defends against an issuer mistakenly returning very
	// long-lived certs). Defaults to DefaultFulcioCertTTL.
	MaxCertReuse time.Duration
}

// FulcioSigner produces DSSE envelopes using an ephemeral Ed25519
// keypair certified by Fulcio. The certificate (containing the OIDC
// subject as a SAN) is the verifier material consumers need to trust
// the signature; PublicKeyPEM returns the leaf cert in PEM form so
// downstream Rekor entries can embed it.
//
// One signer instance maintains a single keypair + cert pair, refreshed
// on demand. The keypair is rotated every refresh so each Fulcio cert
// carries a fresh public key (matching the Sigstore default behaviour).
type FulcioSigner struct {
	opts FulcioSignerOptions

	mu       sync.Mutex
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	leafPEM  []byte
	chainPEM []byte
	notAfter time.Time
	subject  string
	mode     securityv1alpha1.SigningMode
}

// NewFulcioSigner builds a FulcioSigner. The constructor does not
// perform any network IO — the first Sign call obtains the cert lazily.
func NewFulcioSigner(_ context.Context, opts *FulcioSignerOptions) (*FulcioSigner, error) {
	if opts == nil {
		return nil, errors.New("opts is required")
	}
	if opts.FulcioURL == "" {
		return nil, errors.New("FulcioURL is required")
	}
	if opts.OIDCTokenPath == "" {
		opts.OIDCTokenPath = DefaultFulcioOIDCTokenPath
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = newFulcioHTTPClient(opts.CABundle, opts.InsecureSkipVerify)
	}
	if opts.CertRefreshBefore <= 0 {
		opts.CertRefreshBefore = 60 * time.Second
	}
	if opts.MaxCertReuse <= 0 {
		opts.MaxCertReuse = DefaultFulcioCertTTL
	}
	opts.FulcioURL = strings.TrimRight(opts.FulcioURL, "/")
	return &FulcioSigner{
		opts: *opts,
		mode: securityv1alpha1.SigningModeFulcioKeyless,
	}, nil
}

// Sign produces a DSSE envelope signed with the ephemeral private key
// bound to the latest Fulcio certificate.
func (s *FulcioSigner) Sign(ctx context.Context, payload []byte, payloadType string) (*SignedEnvelope, error) {
	if err := s.ensureCert(ctx); err != nil {
		return nil, fmt.Errorf("fulcio: %w", err)
	}
	pae := PAE(payloadType, payload)
	s.mu.Lock()
	priv := s.priv
	keyID := s.keyIDLocked()
	s.mu.Unlock()
	sig := ed25519.Sign(priv, pae)
	return &SignedEnvelope{
		PayloadType: payloadType,
		Payload:     payload,
		Signatures: []EnvelopeSignature{
			{KeyID: keyID, Sig: sig},
		},
	}, nil
}

// KeyID returns a stable identifier for the current Fulcio cert. The
// subject (sub/email claim of the OIDC token) is included so consumers
// can reason about the signer identity without parsing the cert.
func (s *FulcioSigner) KeyID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyIDLocked()
}

// Mode reports fulcio-keyless.
func (s *FulcioSigner) Mode() securityv1alpha1.SigningMode { return s.mode }

// PublicKeyPEM returns the leaf cert in PEM form. Rekor will embed
// this verbatim in the proposed log entry's signature object so
// verifiers see the X509 chain that binds the public key to the OIDC
// identity.
func (s *FulcioSigner) PublicKeyPEM() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.leafPEM) == 0 {
		return nil, errors.New("public key not loaded; call Sign first")
	}
	out := make([]byte, len(s.leafPEM))
	copy(out, s.leafPEM)
	return out, nil
}

// ChainPEM returns the full Fulcio cert chain (leaf + intermediates)
// in PEM form. Used by callers that want to attach the chain alongside
// the bare leaf.
func (s *FulcioSigner) ChainPEM() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.chainPEM) == 0 {
		return nil, errors.New("cert chain not loaded; call Sign first")
	}
	out := make([]byte, len(s.chainPEM))
	copy(out, s.chainPEM)
	return out, nil
}

// --- internal helpers -------------------------------------------------------

// keyIDLocked builds the stable signer identifier. Caller holds s.mu.
func (s *FulcioSigner) keyIDLocked() string {
	if len(s.leafPEM) == 0 {
		return "fulcio:pending"
	}
	sum := sha256.Sum256(s.leafPEM)
	subj := s.subject
	if subj == "" {
		subj = "unknown"
	}
	return "fulcio:" + subj + ":" + hex.EncodeToString(sum[:8])
}

// ensureCert obtains a fresh certificate when the cached one is missing
// or near expiry.
func (s *FulcioSigner) ensureCert(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.leafPEM) > 0 && time.Until(s.notAfter) > s.opts.CertRefreshBefore {
		return nil
	}

	jwt, err := os.ReadFile(s.opts.OIDCTokenPath) //nolint:gosec // operator-controlled path
	if err != nil {
		return fmt.Errorf("read OIDC token %s: %w", s.opts.OIDCTokenPath, err)
	}
	tokStr := strings.TrimSpace(string(jwt))
	subj, err := extractJWTSubject(tokStr)
	if err != nil {
		return fmt.Errorf("parse OIDC token subject: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ephemeral keypair: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	// Proof of possession: sign the OIDC subject string with the
	// freshly generated ephemeral key. Fulcio replays this against the
	// public key to confirm the requester holds the matching private
	// key before issuing a cert that binds the two.
	pop := ed25519.Sign(priv, []byte(subj))

	leafPEM, chainPEM, notAfter, err := s.requestCert(ctx, tokStr, pubPEM, pop)
	if err != nil {
		return fmt.Errorf("fulcio signingCert: %w", err)
	}
	if hardCap := time.Now().Add(s.opts.MaxCertReuse); notAfter.After(hardCap) {
		notAfter = hardCap
	}

	s.priv = priv
	s.pub = pub
	s.leafPEM = leafPEM
	s.chainPEM = chainPEM
	s.notAfter = notAfter
	s.subject = subj
	return nil
}

// fulcioCertRequest is the v2 /api/v2/signingCert request payload.
type fulcioCertRequest struct {
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

// fulcioCertResponse covers both response shapes the v2 API may use
// (with or without a detached SCT). We only consume the cert chain.
type fulcioCertResponse struct {
	SignedCertificateEmbeddedSct *struct {
		Chain struct {
			Certificates []string `json:"certificates"`
		} `json:"chain"`
	} `json:"signedCertificateEmbeddedSct,omitempty"`
	SignedCertificateDetachedSct *struct {
		Chain struct {
			Certificates []string `json:"certificates"`
		} `json:"chain"`
	} `json:"signedCertificateDetachedSct,omitempty"`
}

func (s *FulcioSigner) requestCert(ctx context.Context, jwt string, pubPEM, pop []byte) (leaf, chain []byte, notAfter time.Time, err error) {
	body := fulcioCertRequest{}
	body.Credentials.OIDCIdentityToken = jwt
	body.PublicKeyRequest.PublicKey.Algorithm = "ED25519"
	body.PublicKeyRequest.PublicKey.Content = string(pubPEM)
	body.PublicKeyRequest.ProofOfPossession = base64.StdEncoding.EncodeToString(pop)

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.opts.FulcioURL+"/api/v2/signingCert", bytes.NewReader(buf))
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := s.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("HTTP POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, rErr := io.ReadAll(io.LimitReader(resp.Body, fulcioMaxBodyBytes))
	if rErr != nil {
		return nil, nil, time.Time{}, fmt.Errorf("read response: %w", rErr)
	}
	if resp.StatusCode/100 != 2 {
		return nil, nil, time.Time{}, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out fulcioCertResponse
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("decode response: %w", err)
	}
	certs := pickChain(&out)
	if len(certs) == 0 {
		return nil, nil, time.Time{}, errors.New("no certificate returned")
	}

	leafPEM := []byte(certs[0])
	if !strings.HasSuffix(string(leafPEM), "\n") {
		leafPEM = append(leafPEM, '\n')
	}
	var chainBuf bytes.Buffer
	for _, c := range certs {
		chainBuf.WriteString(c)
		if !strings.HasSuffix(c, "\n") {
			chainBuf.WriteByte('\n')
		}
	}

	leafBlock, _ := pem.Decode(leafPEM)
	if leafBlock == nil {
		return nil, nil, time.Time{}, errors.New("leaf certificate is not PEM-encoded")
	}
	parsed, pErr := x509.ParseCertificate(leafBlock.Bytes)
	if pErr != nil {
		return nil, nil, time.Time{}, fmt.Errorf("parse leaf certificate: %w", pErr)
	}
	return leafPEM, chainBuf.Bytes(), parsed.NotAfter, nil
}

// pickChain returns the first non-nil chain in a fulcioCertResponse.
func pickChain(r *fulcioCertResponse) []string {
	if r.SignedCertificateEmbeddedSct != nil {
		return r.SignedCertificateEmbeddedSct.Chain.Certificates
	}
	if r.SignedCertificateDetachedSct != nil {
		return r.SignedCertificateDetachedSct.Chain.Certificates
	}
	return nil
}

// extractJWTSubject decodes a JWT payload (header.payload.signature)
// and returns the canonical signer identity. Fulcio binds whichever of
// `email` / `sub` the OIDC issuer treats as authoritative; we prefer
// email when present and fall back to sub.
func extractJWTSubject(jwt string) (string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return "", errors.New("token is not a JWT (missing payload)")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some issuers add padding; try the standard variant too.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", fmt.Errorf("decode payload: %w", err)
		}
	}
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("decode claims: %w", err)
	}
	if claims.Email != "" {
		return claims.Email, nil
	}
	if claims.Sub != "" {
		return claims.Sub, nil
	}
	return "", errors.New("OIDC token has neither sub nor email claim")
}

// newFulcioHTTPClient returns an http.Client tuned for Fulcio.
func newFulcioHTTPClient(caBundle []byte, insecure bool) *http.Client {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // caller may opt into InsecureSkipVerify in dev
	if insecure {
		tlsCfg.InsecureSkipVerify = true
	}
	if len(caBundle) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caBundle) {
			tlsCfg.RootCAs = pool
		}
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsCfg,
			MaxIdleConns:          5,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// Compile-time assertion: FulcioSigner satisfies Signer + PublicKeyExporter.
var (
	_ Signer            = (*FulcioSigner)(nil)
	_ PublicKeyExporter = (*FulcioSigner)(nil)
)
