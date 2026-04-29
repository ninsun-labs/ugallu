// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"

	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/detector"
)

// TetragonStubSource is a no-op ExecSource used when the operator
// runs without a tetragon-bridge endpoint configured. CrossTenantExec
// is dormant in that mode; the audit-bus detectors still run.
type TetragonStubSource struct{}

// NewTetragonStubSource returns a stub.
func NewTetragonStubSource() *TetragonStubSource { return &TetragonStubSource{} }

// Name implements ExecSource.
func (s *TetragonStubSource) Name() string { return "tetragon_stub" }

// Run returns a closed channel so the dispatcher loop exits cleanly.
func (s *TetragonStubSource) Run(_ context.Context) (<-chan *detector.ExecInput, error) {
	out := make(chan *detector.ExecInput)
	close(out)
	return out, nil
}
