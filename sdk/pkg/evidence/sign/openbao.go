// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// DefaultOpenBaoSATokenPath is where Kubernetes mounts the projected
// service-account token by default. The OpenBao transit signer uses
// this token to authenticate against the K8s auth method.
const DefaultOpenBaoSATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // mount path, not a credential

// DefaultOpenBaoAuthMount is the conventional path of the Kubernetes
// auth method on a fresh OpenBao install.
const DefaultOpenBaoAuthMount = "auth/kubernetes"

// DefaultOpenBaoTransitMount is the conventional mount of the transit
// secrets engine.
const DefaultOpenBaoTransitMount = "transit"

// openBaoMaxBodyBytes caps response bodies we'll fully read — guards
// against runaway upstream errors / hostile servers.
const openBaoMaxBodyBytes = 64 * 1024

// OpenBaoSignerOptions configures an OpenBaoSigner.
type OpenBaoSignerOptions struct {
	// Address is the OpenBao base URL (no trailing slash), e.g.
	// "https://openbao.openbao.svc.cluster.local:8200". Required.
	Address string

	// TransitMount is the transit secrets engine path. Empty defaults
	// to DefaultOpenBaoTransitMount.
	TransitMount string

	// KeyName is the transit key. Required.
	KeyName string

	// KeyType selects the signature algorithm. "ed25519" is the
	// default; other values delegate to OpenBao defaults.
	KeyType string

	// AuthMount is the Kubernetes auth method path. Empty defaults
	// to DefaultOpenBaoAuthMount.
	AuthMount string

	// AuthRole is the OpenBao role bound to the SA. Required.
	AuthRole string

	// SATokenPath overrides where the projected SA token file lives.
	// Empty defaults to DefaultOpenBaoSATokenPath.
	SATokenPath string

	// HTTPClient is reused across requests (TLS cache + connection
	// pool). nil triggers an http.Client with sensible timeouts and
	// optional CABundle / InsecureSkipVerify behaviour.
	HTTPClient *http.Client

	// CABundle is PEM-encoded CA used to verify the OpenBao TLS
	// server cert. Empty uses the system trust store.
	CABundle []byte

	// InsecureSkipVerify disables TLS server cert verification.
	// dev/lab only — never in production.
	InsecureSkipVerify bool
}

// OpenBaoSigner signs DSSE PAE bytes via the OpenBao transit secrets
// engine. Authentication uses the Kubernetes auth method with the
// pod's projected ServiceAccount token. The vault token returned by
// login is cached + auto-renewed before expiry.
type OpenBaoSigner struct {
	opts      *OpenBaoSignerOptions
	keyID     string
	publicKey []byte // PEM

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// NewOpenBaoSigner constructs an OpenBaoSigner and pre-fetches the
// transit key's public material. Token is acquired lazily on the
// first Sign() call so the signer can be constructed at boot even
// while OpenBao is still warming up.
func NewOpenBaoSigner(ctx context.Context, opts *OpenBaoSignerOptions) (*OpenBaoSigner, error) {
	if opts == nil {
		return nil, errors.New("opts is required")
	}
	if opts.Address == "" {
		return nil, errors.New("address is required")
	}
	if opts.KeyName == "" {
		return nil, errors.New("KeyName is required")
	}
	if opts.AuthRole == "" {
		return nil, errors.New("AuthRole is required")
	}

	if opts.TransitMount == "" {
		opts.TransitMount = DefaultOpenBaoTransitMount
	}
	if opts.AuthMount == "" {
		opts.AuthMount = DefaultOpenBaoAuthMount
	}
	if opts.SATokenPath == "" {
		opts.SATokenPath = DefaultOpenBaoSATokenPath
	}
	if opts.KeyType == "" {
		opts.KeyType = "ed25519"
	}
	opts.Address = strings.TrimRight(opts.Address, "/")
	opts.TransitMount = strings.Trim(opts.TransitMount, "/")
	opts.AuthMount = strings.Trim(opts.AuthMount, "/")

	if opts.HTTPClient == nil {
		opts.HTTPClient = newOpenBaoHTTPClient(opts.CABundle, opts.InsecureSkipVerify)
	}

	s := &OpenBaoSigner{opts: opts}

	pem, err := s.fetchPublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch transit public key: %w", err)
	}
	s.publicKey = pem

	sum := sha256.Sum256(pem)
	s.keyID = "openbao:" + opts.TransitMount + "/" + opts.KeyName + ":" + hex.EncodeToString(sum[:8])

	return s, nil
}

// Sign produces a DSSE envelope signed by the transit key.
func (s *OpenBaoSigner) Sign(ctx context.Context, payload []byte, payloadType string) (*SignedEnvelope, error) {
	pae := PAE(payloadType, payload)
	sig, err := s.signPAE(ctx, pae)
	if err != nil {
		return nil, err
	}
	return &SignedEnvelope{
		PayloadType: payloadType,
		Payload:     payload,
		Signatures: []EnvelopeSignature{
			{KeyID: s.keyID, Sig: sig},
		},
	}, nil
}

// KeyID returns the stable identifier of the transit key.
func (s *OpenBaoSigner) KeyID() string { return s.keyID }

// Mode reports openbao-transit.
func (s *OpenBaoSigner) Mode() securityv1alpha1.SigningMode {
	return securityv1alpha1.SigningModeOpenBaoTransit
}

// PublicKeyPEM returns the PEM-encoded public key material for the
// transit key (used by the Rekor logger to embed `publicKey` in each
// signature object of the proposed entry).
func (s *OpenBaoSigner) PublicKeyPEM() ([]byte, error) {
	if len(s.publicKey) == 0 {
		return nil, errors.New("public key not loaded")
	}
	return append([]byte(nil), s.publicKey...), nil
}

// --- internal helpers -------------------------------------------------------

// signPAE invokes /v1/<mount>/sign/<key> with the PAE bytes. Returns
// the raw signature bytes (without the "vault:v1:" prefix or any
// base64 wrapper).
func (s *OpenBaoSigner) signPAE(ctx context.Context, pae []byte) ([]byte, error) {
	if err := s.ensureToken(ctx); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	body := map[string]any{
		"input": base64.StdEncoding.EncodeToString(pae),
	}
	// Ed25519 in OpenBao transit doesn't accept hash_algorithm; the
	// engine signs the raw input. RSA-PSS / ECDSA do; pass sha256 for
	// those (the actual hash is computed server-side).
	if s.opts.KeyType != "ed25519" {
		body["hash_algorithm"] = "sha256"
		body["prehashed"] = false
	}

	url := fmt.Sprintf("%s/v1/%s/sign/%s", s.opts.Address, s.opts.TransitMount, s.opts.KeyName)
	resp, err := s.do(ctx, http.MethodPost, url, body, true)
	if err != nil {
		return nil, err
	}

	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err = json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("decode sign response: %w", err)
	}

	// vault:v1:<base64>
	parts := strings.SplitN(out.Data.Signature, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, fmt.Errorf("unexpected signature format %q", out.Data.Signature)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature base64: %w", err)
	}
	return raw, nil
}

// fetchPublicKey reads the transit key metadata and returns the PEM
// for the latest version. No auth token required: read on the
// transit/keys path is gated by policy associated with the role login
// token, but the metadata endpoint is also exposed unauthenticated for
// some configurations. We try authenticated first, fall back to
// anonymous if the server config permits.
func (s *OpenBaoSigner) fetchPublicKey(ctx context.Context) ([]byte, error) {
	if err := s.ensureToken(ctx); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	url := fmt.Sprintf("%s/v1/%s/keys/%s", s.opts.Address, s.opts.TransitMount, s.opts.KeyName)
	resp, err := s.do(ctx, http.MethodGet, url, nil, true)
	if err != nil {
		return nil, err
	}

	var meta struct {
		Data struct {
			LatestVersion int `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &meta); err != nil {
		return nil, fmt.Errorf("decode key metadata: %w", err)
	}

	versionKey := fmt.Sprintf("%d", meta.Data.LatestVersion)
	v, ok := meta.Data.Keys[versionKey]
	if !ok || v.PublicKey == "" {
		return nil, fmt.Errorf("transit key %q has no version %s", s.opts.KeyName, versionKey)
	}
	return []byte(v.PublicKey), nil
}

// ensureToken acquires (or renews) the OpenBao client token via the
// Kubernetes auth method. Token is renewed when within 30s of the
// configured TTL.
func (s *OpenBaoSigner) ensureToken(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Until(s.tokenExp) > 30*time.Second {
		return nil
	}

	jwt, err := os.ReadFile(s.opts.SATokenPath) //nolint:gosec // path is operator-controlled config
	if err != nil {
		return fmt.Errorf("read SA token %s: %w", s.opts.SATokenPath, err)
	}
	body := map[string]any{
		"role": s.opts.AuthRole,
		"jwt":  strings.TrimSpace(string(jwt)),
	}
	url := fmt.Sprintf("%s/v1/%s/login", s.opts.Address, s.opts.AuthMount)
	resp, err := s.do(ctx, http.MethodPost, url, body, false)
	if err != nil {
		return err
	}

	var login struct {
		Auth struct {
			ClientToken string `json:"client_token"`
			LeaseTTL    int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(resp, &login); err != nil {
		return fmt.Errorf("decode login response: %w", err)
	}
	if login.Auth.ClientToken == "" {
		return errors.New("openbao login returned empty client_token")
	}
	ttl := time.Duration(login.Auth.LeaseTTL) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute // safe default if OpenBao omits TTL
	}
	s.token = login.Auth.ClientToken
	s.tokenExp = time.Now().Add(ttl)
	return nil
}

// do performs the HTTP call and returns the raw body. The caller is
// responsible for parsing into the expected struct. authed=true sets
// the X-Vault-Token header when a token is currently held.
func (s *OpenBaoSigner) do(ctx context.Context, method, url string, body any, authed bool) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authed && s.token != "" {
		req.Header.Set("X-Vault-Token", s.token)
	}
	resp, err := s.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP %s %s: %w", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, openBaoMaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("openbao %s %s status %d: %s", method, url, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

// newOpenBaoHTTPClient returns a tuned http.Client for OpenBao.
// CABundle (when non-empty) is added to a fresh root pool; the system
// pool is used otherwise.
func newOpenBaoHTTPClient(caBundle []byte, insecure bool) *http.Client {
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
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// Compile-time assertion: OpenBaoSigner satisfies Signer + PublicKeyExporter.
var (
	_ Signer            = (*OpenBaoSigner)(nil)
	_ PublicKeyExporter = (*OpenBaoSigner)(nil)
)
