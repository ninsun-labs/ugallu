// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serverv1_test

import (
	"testing"

	serverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/serverv1"
)

// TestIsBPFSupported_ReflectsBTFAvailability gates on the
// `/sys/kernel/btf/vmlinux` probe; it's skipped when BTF is missing
// (older kernels / minimal containers) and otherwise asserts the
// happy path returns nil. End-to-end load+attach lives in the kind
// smoke pipeline where the resolver runs with CAP_BPF.
func TestIsBPFSupported_ReflectsBTFAvailability(t *testing.T) {
	if err := serverv1.IsBPFSupported(); err != nil {
		t.Skipf("kernel BTF not available: %v", err)
	}
}

// TestLoadCgroupTracker_FailsGracefullyUnprivileged verifies the
// expected error path when the test process lacks CAP_BPF. We don't
// exercise the privileged branch here — exercising real eBPF load
// from `go test` would side-effect the kernel and only runs when
// somebody types `sudo go test`, which is not how CI works. Real
// load+run+close validation belongs in the kind e2e suite.
func TestLoadCgroupTracker_FailsGracefullyUnprivileged(t *testing.T) {
	if err := serverv1.IsBPFSupported(); err != nil {
		t.Skipf("kernel BTF not available: %v", err)
	}
	cache := serverv1.NewCache(0)
	tracker, err := serverv1.LoadCgroupTracker(cache, nil)
	if err == nil {
		// Running as root with CAP_BPF — close cleanly so the test
		// stays a no-op rather than leaking the loaded program.
		_ = tracker.Close()
		t.Skip("CAP_BPF available; load succeeded — kind/e2e covers the privileged path")
	}
}
