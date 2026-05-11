// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import "errors"

// ErrInvalidType means the EmitOpts.Type is not present in the
// catalog snapshot baked into this SDK build. The caller fails fast
// with this error before any apiserver round-trip so admission policy
// 5 doesn't even see the request.
var ErrInvalidType = errors.New("emitter: type is not in the catalog (run go generate to refresh)")

// ErrSubjectMissing means EmitOpts has neither a populated Subject
// (Kind/Name/UID/IP) nor an EnrichVia hint. A SecurityEvent must
// always carry a Subject - admission rejects the absence anyway.
var ErrSubjectMissing = errors.New("emitter: at least one Subject identity field or EnrichVia is required")

// ErrBufferFull means the retry buffer overflowed: the apiserver has
// been unreachable long enough that the bounded ring is at capacity.
// The Emitter still records a SourceRateLimited SE (deduplicated 1/min)
// so the SOC sees the drop rather than only Prometheus counters.
var ErrBufferFull = errors.New("emitter: retry buffer is full")
