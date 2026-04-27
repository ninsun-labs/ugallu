// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package serverv1

import (
	"context"
	"errors"
	"log/slog"
)

// errEbpfUnsupported is returned by every eBPF entry point on a
// non-Linux build. Bootstrap inspects the error type and falls back
// to rescan-only mode.
var errEbpfUnsupported = errors.New("eBPF tracker requires Linux")

// CgroupTracker is a no-op stub on non-Linux platforms.
type CgroupTracker struct{}

// LoadCgroupTracker returns errEbpfUnsupported on non-Linux.
func LoadCgroupTracker(_ *Cache, _ *slog.Logger) (*CgroupTracker, error) {
	return nil, errEbpfUnsupported
}

// Run is a no-op on non-Linux.
func (*CgroupTracker) Run(_ context.Context) {}

// Close is a no-op on non-Linux.
func (*CgroupTracker) Close() error { return nil }

// IsBPFSupported reports the platform mismatch on non-Linux builds.
func IsBPFSupported() error { return errEbpfUnsupported }
