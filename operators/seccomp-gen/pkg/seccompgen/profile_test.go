// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package seccompgen

import (
	"encoding/json"
	"testing"
)

// TestBuildSeccompProfile_StableShape pins the JSON layout the
// downstream applier expects.
func TestBuildSeccompProfile_StableShape(t *testing.T) {
	capture := &Capture{Syscalls: []string{"openat", "read", "write"}}
	out, err := BuildSeccompProfile(capture, "SCMP_ACT_ERRNO")
	if err != nil {
		t.Fatalf("BuildSeccompProfile: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got["defaultAction"] != "SCMP_ACT_ERRNO" {
		t.Errorf("defaultAction = %v", got["defaultAction"])
	}
	syscalls, ok := got["syscalls"].([]any)
	if !ok || len(syscalls) != 1 {
		t.Fatalf("syscalls = %v", got["syscalls"])
	}
	first := syscalls[0].(map[string]any)
	if first["action"] != "SCMP_ACT_ALLOW" {
		t.Errorf("first.action = %v", first["action"])
	}
	names := first["names"].([]any)
	if len(names) != 3 || names[0] != "openat" {
		t.Errorf("names = %v", names)
	}
}

// TestBuildSeccompProfile_NilCapture rejects a nil capture rather
// than producing an empty profile that would deny every syscall.
func TestBuildSeccompProfile_NilCapture(t *testing.T) {
	if _, err := BuildSeccompProfile(nil, "SCMP_ACT_ERRNO"); err == nil {
		t.Fatal("expected error on nil capture")
	}
}
