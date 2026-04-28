// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package source contains the DNS event source backends consumed by
// dns-detect: the CoreDNS plugin gRPC stream (primary) and the
// Tetragon kprobe fallback (degraded). Both backends emit
// dnsevent.DNSEvent on the channel returned by Run.
package source

import (
	"context"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsevent"
)

// Source is the abstraction the dispatcher subscribes to. The
// implementation is responsible for re-connecting on transient
// errors; Run returns when ctx is cancelled OR the backend has
// hit a non-recoverable failure.
type Source interface {
	// Name returns the source kind (used in metrics + status).
	Name() string

	// Run connects to the backend and forwards DNSEvent over the
	// returned channel. The channel closes when the source stops.
	// Permanent errors flow through err; transient ones are
	// retried internally.
	Run(ctx context.Context) (<-chan *dnsevent.DNSEvent, error)
}
