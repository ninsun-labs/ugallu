// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package source contains the event source backends consumed by
// tenant-escape: the audit-detection event-bus gRPC stream (primary,
// drives the 3 audit-based detectors) and the Tetragon process_exec
// stream (drives the CrossTenantExec detector).
//
// Backends emit detector.AuditInput / detector.ExecInput on the
// channel returned by Run; the dispatcher fans every event through
// the registered detectors.
package source

import (
	"context"

	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/detector"
)

// AuditSource produces a stream of normalised audit events that drive
// the SecretAccess / HostPathOverlap / NetworkPolicy detectors.
type AuditSource interface {
	// Name returns the source kind (used in metrics + status labels).
	Name() string

	// Run dials the backend and forwards events on the returned
	// channel. The channel closes when the source stops (ctx
	// cancellation or fatal error). Transient errors are retried
	// internally - Run returns nil on graceful shutdown, error on
	// unrecoverable misconfiguration only.
	Run(ctx context.Context) (<-chan *detector.AuditInput, error)
}

// ExecSource produces a stream of normalised exec events that drive
// the CrossTenantExec detector. The current implementation ships a
// stub; the real Tetragon-bridge consumer lands in the satellite repo.
type ExecSource interface {
	Name() string
	Run(ctx context.Context) (<-chan *detector.ExecInput, error)
}
