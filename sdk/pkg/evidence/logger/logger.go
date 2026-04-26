// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"context"

	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

// Logger publishes a signed DSSE envelope to a transparency log and
// returns the resulting log entry (UUID + logIndex + optional inclusion
// proof). Implementations:
//   - StubLogger     dev/test, returns deterministic synthetic entries
//   - RekorLogger    (next iteration) Rekor v1 HTTP client
type Logger interface {
	// Log publishes the envelope and returns the log entry.
	Log(ctx context.Context, envelope *sign.SignedEnvelope) (*LogEntry, error)

	// Endpoint returns a stable identifier of the underlying log
	// (e.g., "https://rekor.sigstore.dev" or "stub:dev").
	Endpoint() string
}

// LogEntry is the transparency-log result of publishing one envelope.
type LogEntry struct {
	// LogIndex is the monotonic position in the log.
	LogIndex int64

	// UUID is the entry's unique identifier in the log.
	UUID string

	// IntegratedTime is the wall-clock time the log integrated the entry,
	// as Unix epoch seconds.
	IntegratedTime int64

	// InclusionProof is an optional Merkle proof of inclusion. Implementations
	// may leave it nil if the proof is fetched lazily.
	InclusionProof *InclusionProof
}

// InclusionProof is the Merkle inclusion proof returned by some logs.
type InclusionProof struct {
	TreeSize int64
	LogIndex int64
	RootHash string
	Hashes   []string
}
