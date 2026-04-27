// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

// DefaultRekorURL is the public Sigstore Rekor instance.
const DefaultRekorURL = "https://rekor.sigstore.dev"

// rekorMaxErrorBody caps the response body size read on non-2xx
// responses. Protects against runaway upstream errors filling the log.
const rekorMaxErrorBody = 4 * 1024

// RekorLogger publishes DSSE envelopes to a Rekor v1 transparency log
// (design 06 V2). Entries use the intoto/v0.0.2 schema, which embeds
// the signer's public key in each signature object so the log can
// independently verify the envelope.
type RekorLogger struct {
	// URL is the Rekor base URL (no trailing slash, e.g.
	// "https://rekor.sigstore.dev"). Defaults to DefaultRekorURL.
	URL string

	// HTTPClient is the client used for log API calls. Defaults to a
	// 30s-timeout client.
	HTTPClient *http.Client

	// PublicKeyPEM is the PEM-encoded SubjectPublicKeyInfo embedded in
	// each signature object proposed to Rekor. It must match the public
	// half of the keypair used by the Signer that produced the envelope.
	PublicKeyPEM []byte

	// UserAgent overrides the User-Agent header sent to Rekor.
	UserAgent string
}

// NewRekorLogger constructs a RekorLogger. URL defaults to the public
// Sigstore Rekor instance when empty. publicKeyPEM is required and
// must be the PKIX SubjectPublicKeyInfo PEM matching the Signer.
func NewRekorLogger(url string, publicKeyPEM []byte) (*RekorLogger, error) {
	if len(publicKeyPEM) == 0 {
		return nil, errors.New("publicKeyPEM is required")
	}
	if url == "" {
		url = DefaultRekorURL
	}
	return &RekorLogger{
		URL:          strings.TrimRight(url, "/"),
		HTTPClient:   &http.Client{Timeout: 30 * time.Second},
		PublicKeyPEM: publicKeyPEM,
		UserAgent:    "ugallu-attestor/v0.0.1-alpha.1",
	}, nil
}

// Endpoint returns the configured Rekor URL.
func (r *RekorLogger) Endpoint() string { return r.URL }

// Log publishes the envelope to Rekor and returns the resulting entry.
//
// 409 Conflict (entry already present) is surfaced as an error: the
// AttestationBundleReconciler is idempotent on Sealed bundles, so a
// 409 typically means a stale retry that should not silently re-use
// an existing entry without verifying it.
func (r *RekorLogger) Log(ctx context.Context, env *sign.SignedEnvelope) (*LogEntry, error) {
	if r.HTTPClient == nil {
		r.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if env == nil {
		return nil, errors.New("nil envelope")
	}
	if len(env.Signatures) == 0 {
		return nil, errors.New("envelope has no signatures")
	}

	proposed, err := r.buildProposedEntry(env)
	if err != nil {
		return nil, fmt.Errorf("build rekor entry: %w", err)
	}

	body, err := json.Marshal(proposed)
	if err != nil {
		return nil, fmt.Errorf("marshal proposed entry: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		r.URL+"/api/v1/log/entries", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build rekor request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if r.UserAgent != "" {
		req.Header.Set("User-Agent", r.UserAgent)
	}

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rekor request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, rekorMaxErrorBody))
		return nil, fmt.Errorf("rekor status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var raw map[string]rekorLogEntryAnon
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode rekor response: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("empty rekor response")
	}
	for uuid, entry := range raw {
		out := &LogEntry{
			UUID:           uuid,
			LogIndex:       entry.LogIndex,
			IntegratedTime: entry.IntegratedTime,
		}
		if entry.Verification != nil && entry.Verification.InclusionProof != nil {
			ip := entry.Verification.InclusionProof
			out.InclusionProof = &InclusionProof{
				LogIndex: ip.LogIndex,
				TreeSize: ip.TreeSize,
				RootHash: ip.RootHash,
				Hashes:   ip.Hashes,
			}
		}
		return out, nil
	}
	return nil, errors.New("unreachable")
}

// buildProposedEntry constructs the JSON body for POST /api/v1/log/entries.
// Schema: rekor intoto/v0.0.2 with the DSSE envelope inlined.
func (r *RekorLogger) buildProposedEntry(env *sign.SignedEnvelope) (*rekorProposedEntry, error) {
	// payloadHash: sha256 of the raw in-toto Statement bytes (not PAE).
	pSum := sha256.Sum256(env.Payload)
	payloadHash := hex.EncodeToString(pSum[:])

	// envelope hash: sha256 of the canonical JSON of the envelope itself.
	canonEnv, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	eSum := sha256.Sum256(canonEnv)
	envHash := hex.EncodeToString(eSum[:])

	// Rekor's intoto/v0.0.2 schema applies base64 decoding twice on
	// the wire fields `payload` and `sig`: once by `DecodeEntry` (the
	// schema declares them format=byte), and once by the downstream
	// DSSE verifier (which treats the post-decode bytes as a
	// base64-encoded string per dsse.Envelope semantics). The
	// `publicKey` field is decoded only once because the PEM bytes
	// are passed directly to the x509 parser. Matching this on the
	// wire requires *double*-encoding payload and sig and
	// single-encoding pubkey.
	stdEnc := base64.StdEncoding
	pubKeyB64 := stdEnc.EncodeToString(r.PublicKeyPEM)
	payloadB64 := stdEnc.EncodeToString([]byte(stdEnc.EncodeToString(env.Payload)))

	sigs := make([]rekorEnvelopeSig, len(env.Signatures))
	for i, s := range env.Signatures {
		sigs[i] = rekorEnvelopeSig{
			KeyID:     s.KeyID,
			Sig:       stdEnc.EncodeToString([]byte(stdEnc.EncodeToString(s.Sig))),
			PublicKey: pubKeyB64,
		}
	}

	return &rekorProposedEntry{
		Kind:       "intoto",
		APIVersion: "0.0.2",
		Spec: rekorIntotoSpec{
			Content: rekorIntotoContent{
				Envelope: rekorEnvelope{
					PayloadType: env.PayloadType,
					Payload:     payloadB64,
					Signatures:  sigs,
				},
				Hash:        rekorHashRef{Algorithm: "sha256", Value: envHash},
				PayloadHash: rekorHashRef{Algorithm: "sha256", Value: payloadHash},
			},
		},
	}, nil
}

// --- Rekor v1 wire types (subset; see openapi/swagger spec). -------------------

type rekorProposedEntry struct {
	Kind       string          `json:"kind"`
	APIVersion string          `json:"apiVersion"`
	Spec       rekorIntotoSpec `json:"spec"`
}

type rekorIntotoSpec struct {
	Content rekorIntotoContent `json:"content"`
}

type rekorIntotoContent struct {
	Envelope    rekorEnvelope `json:"envelope"`
	Hash        rekorHashRef  `json:"hash"`
	PayloadHash rekorHashRef  `json:"payloadHash"`
}

type rekorEnvelope struct {
	PayloadType string             `json:"payloadType"`
	Payload     string             `json:"payload"`
	Signatures  []rekorEnvelopeSig `json:"signatures"`
}

type rekorEnvelopeSig struct {
	KeyID     string `json:"keyid"`
	Sig       string `json:"sig"`
	PublicKey string `json:"publicKey"`
}

type rekorHashRef struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// rekorLogEntryAnon mirrors the swagger LogEntryAnon definition.
type rekorLogEntryAnon struct {
	LogIndex       int64              `json:"logIndex"`
	LogID          string             `json:"logID"`
	IntegratedTime int64              `json:"integratedTime"`
	Body           string             `json:"body"`
	Verification   *rekorVerification `json:"verification,omitempty"`
}

type rekorVerification struct {
	InclusionProof       *rekorInclusionProof `json:"inclusionProof,omitempty"`
	SignedEntryTimestamp string               `json:"signedEntryTimestamp,omitempty"`
}

type rekorInclusionProof struct {
	LogIndex int64    `json:"logIndex"`
	TreeSize int64    `json:"treeSize"`
	RootHash string   `json:"rootHash"`
	Hashes   []string `json:"hashes"`
}
