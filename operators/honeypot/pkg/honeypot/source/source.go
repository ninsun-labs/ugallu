// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package source contains the audit-bus event source consumed by
// honeypot. The source dials the audit-detection event bus, receives
// the AuditEvent stream, and translates it into the
// detector.AuditInput shape the dispatcher fans through the
// detector chain.
package source

import (
	"context"

	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/detector"
)

// AuditSource produces a stream of normalised audit events.
type AuditSource interface {
	Name() string
	Run(ctx context.Context) (<-chan *detector.AuditInput, error)
}
