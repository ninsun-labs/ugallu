// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"

	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/detector"
)

// TetragonStubSource is a no-op ExecSource placeholder. The real
// Tetragon-bridge consumer (kprobe `do_execveat_common` events
// translated into ExecInput) lives in the satellite repo
// `ninsun-labs/tetragon-bridge` and lands in Wave 4 §T8. Until then
// the operator runs the audit-bus detectors only and the
// CrossTenantExec pipeline is dormant.
type TetragonStubSource struct{}

// NewTetragonStubSource returns a stub.
func NewTetragonStubSource() *TetragonStubSource { return &TetragonStubSource{} }

// Name implements ExecSource.
func (s *TetragonStubSource) Name() string { return "tetragon_stub" }

// Run returns a closed channel — no exec events flow through. The
// channel close signals the dispatcher loop to exit gracefully.
func (s *TetragonStubSource) Run(_ context.Context) (<-chan *detector.ExecInput, error) {
	out := make(chan *detector.ExecInput)
	close(out)
	return out, nil
}
