// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// CorrelationBucket is the time-window granularity used to derive the
// CorrelationID hash. Two events with identical (class, type, subject)
// inside the same bucket share a CorrelationID; events in different
// buckets fall on distinct CorrelationIDs even when otherwise
// identical, capturing recurrence.
const CorrelationBucket = 60 * time.Second

// deriveCorrelationID produces the auto CorrelationID for an
// EmitOpts. It is deterministic given the same (class, type,
// subjectUID, bucket) tuple and is truncated to 32 hex chars to keep
// the SE.metadata.name short while still uniqueness-safe.
func deriveCorrelationID(opts *EmitOpts, now time.Time) string {
	bucket := now.UTC().Truncate(CorrelationBucket).Unix()
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%d", opts.Class, opts.Type, opts.SubjectUID, bucket)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// deterministicSEName derives the SecurityEvent.metadata.name from a
// CorrelationID. Idempotent emit: a second Emit with the same
// CorrelationID produces the same SE name → AlreadyExists is treated
// as success.
func deterministicSEName(correlationID string) string {
	h := sha256.Sum256([]byte(correlationID))
	// 16 hex chars = 8 bytes ≈ 64 bits collision space, plenty for
	// the SE namespace (cluster-scoped, low cardinality).
	return "se-" + strings.ToLower(hex.EncodeToString(h[:8]))
}
