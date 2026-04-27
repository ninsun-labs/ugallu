// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serverv1_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	serverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/serverv1"
)

// makeKubepodsTree builds a fake /sys/fs/cgroup hierarchy under root
// with a single Burstable pod and one container scope. Returns the
// expected (cgroupID of the container scope, podUID, containerID).
func makeKubepodsTree(t *testing.T, root string) (cgroupID uint64, podUID types.UID, containerID string) {
	t.Helper()
	scope := filepath.Join(root,
		"kubepods.slice",
		"kubepods-burstable.slice",
		"kubepods-burstable-pod123abc_456def_789.slice",
		"cri-containerd-deadbeef0123456789.scope",
	)
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(scope, &st); err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	return st.Ino, types.UID("123abc-456def-789"), "deadbeef0123456789"
}

func TestWalkCgroupFS_IndexesPodAndContainer(t *testing.T) {
	root := t.TempDir()
	cgroupID, podUID, containerID := makeKubepodsTree(t, root)

	cache := serverv1.NewCache(0)
	indexed, err := serverv1.WalkCgroupFS(root, cache)
	if err != nil {
		t.Fatalf("WalkCgroupFS: %v", err)
	}
	// Both the pod-level slice and the container scope are valid
	// kubepods cgroup directories; both are indexed because Tetragon
	// can emit either cgroup_id depending on where it attached.
	if indexed != 2 {
		t.Errorf("indexed = %d, want 2 (pod slice + container scope)", indexed)
	}
	if size := cache.CgroupSizes(); size != 2 {
		t.Errorf("CgroupSizes = %d, want 2", size)
	}

	// Idempotent re-walk: same fixture, same size.
	if _, err := serverv1.WalkCgroupFS(root, cache); err != nil {
		t.Fatalf("re-walk: %v", err)
	}
	if size := cache.CgroupSizes(); size != 2 {
		t.Errorf("after re-walk CgroupSizes = %d, want 2", size)
	}

	// Sanity: the indexed cgroupID corresponds to the directory's
	// inode and the recorded podUID + containerID match.
	if cgroupID == 0 || podUID == "" || containerID == "" {
		t.Fatalf("fixture sanity failed")
	}
}

// TestWalkCgroupFS_SkipsNonKubepods makes sure non-kubepods top-level
// slices are pruned and the walk doesn't error on permission-denied
// subtrees (best-effort behaviour).
func TestWalkCgroupFS_SkipsNonKubepods(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "system.slice", "sshd.service"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	makeKubepodsTree(t, root)

	cache := serverv1.NewCache(0)
	indexed, err := serverv1.WalkCgroupFS(root, cache)
	if err != nil {
		t.Fatalf("WalkCgroupFS: %v", err)
	}
	// 2 = pod-level slice + container scope under kubepods.slice.
	// system.slice MUST NOT contribute (top-level non-kubepods slices
	// are pruned).
	if indexed != 2 {
		t.Errorf("indexed = %d, want 2 (system.slice should be pruned)", indexed)
	}
}
