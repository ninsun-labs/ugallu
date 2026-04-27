// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// tokenSource is the abstraction the GitHubProvider uses to obtain a
// Bearer token for every request. Two implementations exist:
//   - staticTokenSource: returns the same PAT/installation token for
//     every call (used in unit tests and when the operator is wired
//     against a fine-grained PAT).
//   - appTokenSource: signs a short-lived JWT with the GitHub App
//     private key, exchanges it for an installation access token,
//     caches the token, and refreshes it ~5min before expiry.
type tokenSource interface {
	Token(ctx context.Context) (string, error)
}

// --- static -----------------------------------------------------------------

type staticTokenSource struct{ value string }

func (s staticTokenSource) Token(_ context.Context) (string, error) {
	if s.value == "" {
		return "", errors.New("static token source: empty token")
	}
	return s.value, nil
}

// --- GitHub App -------------------------------------------------------------

// GitHubAppCreds carries the credentials needed to authenticate as a
// GitHub App installation: the AppID (or Client ID), the
// InstallationID returned after install, and the RSA private key
// downloaded from the App settings as a PEM blob.
//
//nolint:revive // GitHub*-prefixed names mirror the upstream API.
type GitHubAppCreds struct {
	AppID          string
	InstallationID string
	PrivateKeyPEM  []byte

	// APIBase optionally overrides the GitHub API base URL (for GHES).
	// Empty falls back to whatever the parent provider uses.
	APIBase string
}

// appTokenSource signs JWTs with the App private key and caches the
// returned installation access token. It is safe for concurrent use:
// the cached token is protected by a mutex so multiple goroutines
// never trigger more than one refresh at a time.
type appTokenSource struct {
	creds   GitHubAppCreds
	apiBase string
	signer  *rsa.PrivateKey
	cli     *http.Client

	mu       sync.Mutex
	current  string
	expires  time.Time
	jwtTTL   time.Duration
	leadTime time.Duration
}

// newAppTokenSource validates and parses creds, returning a source
// ready to mint installation tokens on demand.
func newAppTokenSource(creds GitHubAppCreds, apiBase string, cli *http.Client) (*appTokenSource, error) {
	if strings.TrimSpace(creds.AppID) == "" {
		return nil, errors.New("github app creds: AppID is required")
	}
	if strings.TrimSpace(creds.InstallationID) == "" {
		return nil, errors.New("github app creds: InstallationID is required")
	}
	if len(creds.PrivateKeyPEM) == 0 {
		return nil, errors.New("github app creds: PrivateKeyPEM is required")
	}
	key, err := parseRSAPrivateKey(creds.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	if creds.APIBase != "" {
		apiBase = strings.TrimRight(creds.APIBase, "/")
	}
	if cli == nil {
		cli = &http.Client{Timeout: 30 * time.Second}
	}
	return &appTokenSource{
		creds:    creds,
		apiBase:  apiBase,
		signer:   key,
		cli:      cli,
		jwtTTL:   9 * time.Minute, // GitHub max is 10min; leave headroom
		leadTime: 5 * time.Minute, // refresh 5min before expiry
	}, nil
}

// Token returns the cached installation access token, refreshing it
// when within leadTime of expiry. The returned string is the raw
// token (the caller adds it as a Bearer header).
func (s *appTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.current != "" && time.Until(s.expires) > s.leadTime {
		return s.current, nil
	}

	signed, err := s.signJWT()
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	tok, exp, err := s.exchange(ctx, signed)
	if err != nil {
		return "", fmt.Errorf("exchange JWT for installation token: %w", err)
	}
	s.current = tok
	s.expires = exp
	return tok, nil
}

// signJWT mints the short-lived assertion that GitHub accepts as the
// caller-side proof of App identity.
func (s *appTokenSource) signJWT() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    s.creds.AppID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)), // clock-skew tolerant
		ExpiresAt: jwt.NewNumericDate(now.Add(s.jwtTTL)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return tok.SignedString(s.signer)
}

// exchange POSTs the JWT to the access-tokens endpoint and parses the
// installation token + expiry. apiBase is required.
func (s *appTokenSource) exchange(ctx context.Context, jwtSigned string) (string, time.Time, error) {
	if s.apiBase == "" {
		return "", time.Time{}, errors.New("apiBase is required")
	}
	url := fmt.Sprintf("%s/app/installations/%s/access_tokens", s.apiBase, s.creds.InstallationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtSigned)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := s.cli.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("HTTP POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return "", time.Time{}, fmt.Errorf("status %d: %s", resp.StatusCode, snippet(body))
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if uErr := json.Unmarshal(body, &out); uErr != nil {
		return "", time.Time{}, fmt.Errorf("decode response: %w", uErr)
	}
	if out.Token == "" {
		return "", time.Time{}, errors.New("empty installation token in response")
	}
	if out.ExpiresAt.IsZero() {
		out.ExpiresAt = time.Now().Add(time.Hour)
	}
	return out.Token, out.ExpiresAt, nil
}

// parseRSAPrivateKey accepts either a PKCS#1 ("RSA PRIVATE KEY") or
// PKCS#8 ("PRIVATE KEY") PEM block. The format GitHub ships is
// PKCS#1 RSA but operators sometimes re-export under PKCS#8.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is %T, want *rsa.PrivateKey", parsed)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q (want RSA PRIVATE KEY or PRIVATE KEY)", block.Type)
	}
}
