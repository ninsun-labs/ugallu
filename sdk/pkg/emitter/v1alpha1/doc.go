// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package v1alpha1 implements the events emitter - the single source
// of truth used by detection sources to publish SecurityEvent CRs.
// It centralises five
// concerns that every operator otherwise reimplements badly:
//
//  1. Type catalog validation - Emit fails fast on an unknown
//     SecurityEvent.spec.type before reaching admission policy 5.
//  2. CorrelationID derivation - sha256-truncated hash over
//     (class, type, subjectUID, minute-bucket) keeps repeated matches
//     within a 60s window correlated to a single SE name.
//  3. Idempotent SE name - sha256(correlationID)[:16] makes Emit a
//     no-op when the SE already exists.
//  4. Token-bucket rate limit - global throttle plus a bounded retry
//     buffer so a brief apiserver outage doesn't lose events.
//  5. Optional resolver enrichment - short-circuit on cache hit, fall
//     back to the bare Subject from EmitOpts on resolver failure.
//
// audit-detection and forensics consume this package directly.
// The attestor and TTL operators emit their own SE via the
// controller-runtime client because they predate the emitter and
// don't need rate-limit or correlation; future iterations may
// migrate them.
package v1alpha1
