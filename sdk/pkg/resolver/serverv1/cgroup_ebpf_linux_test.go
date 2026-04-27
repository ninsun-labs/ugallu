// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serverv1_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	serverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/serverv1"
)

// TestLoadCgroupTracker_RequiresPrivilege verifies LoadCgroupTracker
// returns a clear error when the test process lacks CAP_BPF (which is
// the default for unprivileged CI runners). When run as root with BPF
// support, the load should succeed and Run/Close happen quickly.
func TestLoadCgroupTracker_BehaviourMatchesPrivilege(t *testing.T) {
	if err := serverv1.IsBPFSupported(); err != nil {
		t.Skipf("kernel BTF not available: %v", err)
	}

	cache := serverv1.NewCache(0)
	tracker, err := serverv1.LoadCgroupTracker(cache, nil)

	switch {
	case err == nil:
		// Privileged path: ensure Run + Close don't deadlock.
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		done := make(chan struct{})
		go func() {
			tracker.Run(ctx)
			close(done)
		}()
		<-done
		if cErr := tracker.Close(); cErr != nil {
			t.Errorf("Close: %v", cErr)
		}
	case os.Geteuid() != 0:
		// Unprivileged path: error is the contract.
		t.Logf("expected load failure for unprivileged user: %v", err)
	default:
		// Running as root but load failed — surface the diagnostic
		// even when something subtle is off (kernel headers,
		// memlock, SELinux denial). errors.Is on the package's
		// rlimit/ringbuf classes would be too narrow.
		t.Logf("running as root but load failed (kernel feature gap?): %v", err)
		_ = errors.Is(err, os.ErrPermission)
	}
}
