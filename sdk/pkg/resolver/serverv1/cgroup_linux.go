// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serverv1

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"k8s.io/apimachinery/pkg/types"
)

// DefaultSysFsCgroup is the canonical cgroup v2 mountpoint inside a
// container that bind-mounts the host's hierarchy read-only.
const DefaultSysFsCgroup = "/sys/fs/cgroup"

// DefaultProcRoot mirrors the host's /proc; the resolver DaemonSet
// mounts it at /host/proc to avoid colliding with the container's own
// /proc.
const DefaultProcRoot = "/host/proc"

// errNotKubepods signals that a path does not belong to the kubepods
// hierarchy. Used internally for control flow during walks; never
// surfaced to callers.
var errNotKubepods = errors.New("not a kubepods cgroup path")

// WalkCgroupFS scans the cgroup v2 hierarchy under sysfsRoot and feeds
// every kubepods slice it finds into c.IndexCgroup. The cgroup ID is
// the inode of the directory; the pod UID and container ID are
// extracted from the directory name. Errors on individual entries are
// not fatal — Walk continues so a single weird path can't blind the
// whole index.
//
// Returns the number of entries indexed and any walk error.
func WalkCgroupFS(sysfsRoot string, c *Cache) (int, error) {
	if sysfsRoot == "" {
		sysfsRoot = DefaultSysFsCgroup
	}
	indexed := 0
	walkErr := filepath.WalkDir(sysfsRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrPermission) {
				// Skip unreadable subtrees (cgroup namespaces or MAC
				// isolation). Returning nil keeps the walk going.
				return nil
			}
			return walkErr
		}
		if !d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(path, sysfsRoot)
		if !strings.Contains(rel, "/kubepods") {
			// Don't descend into siblings of kubepods.slice.
			if rel == "" || rel == "/" {
				return nil
			}
			// A non-kubepods top-level slice; prune.
			return fs.SkipDir
		}
		info, ok := ParseCgroupPath(rel)
		if !ok {
			return nil
		}
		var st syscall.Stat_t
		if err := syscall.Stat(path, &st); err != nil {
			return nil // skip, can't stat
		}
		c.IndexCgroup(st.Ino, types.UID(info.PodUID), info.ContainerID)
		indexed++
		return nil
	})
	if walkErr != nil {
		return indexed, fmt.Errorf("walk cgroup fs %q: %w", sysfsRoot, walkErr)
	}
	return indexed, nil
}

// CgroupIDForPID reads /proc/<pid>/cgroup and returns the kernel
// cgroup ID for the unified (cgroup v2) hierarchy along with the
// cgroup path string. Cgroup v1 hosts are not supported by Phase 2.
//
// procRoot defaults to DefaultProcRoot when empty; sysfsRoot defaults
// to DefaultSysFsCgroup.
func CgroupIDForPID(procRoot, sysfsRoot string, pid int32) (cgroupID uint64, cgroupPath string, err error) {
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}
	if sysfsRoot == "" {
		sysfsRoot = DefaultSysFsCgroup
	}
	cgroupPath, err = readUnifiedCgroupLine(procRoot, pid)
	if err != nil {
		return 0, "", err
	}
	full := filepath.Join(sysfsRoot, cgroupPath)
	var st syscall.Stat_t
	if err := syscall.Stat(full, &st); err != nil {
		return 0, cgroupPath, fmt.Errorf("stat %s: %w", full, err)
	}
	return st.Ino, cgroupPath, nil
}

// PodInfoForPID reads /proc/<pid>/cgroup and parses the unified cgroup
// path directly into a CgroupPathInfo (no /sys/fs/cgroup access). When
// the PID belongs to a kubepods cgroup this is enough to resolve the
// pod without the cgroup ID index — useful when the index hasn't seen
// the cgroup yet (e.g. pod started after cold-walk and Phase 3 eBPF
// isn't running).
func PodInfoForPID(procRoot string, pid int32) (CgroupPathInfo, error) {
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}
	cgPath, err := readUnifiedCgroupLine(procRoot, pid)
	if err != nil {
		return CgroupPathInfo{}, err
	}
	info, ok := ParseCgroupPath(cgPath)
	if !ok {
		return CgroupPathInfo{}, errNotKubepods
	}
	return info, nil
}

// readUnifiedCgroupLine returns the cgroup v2 path for pid, e.g.
// "/kubepods.slice/.../cri-containerd-<id>.scope".
//
// On a cgroup v2 host the file contains a single line "0::<path>".
// On a hybrid host, the same "0::" line exists for the unified
// hierarchy alongside legacy controllers. We pick that line and
// ignore the rest.
func readUnifiedCgroupLine(procRoot string, pid int32) (string, error) {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(int(pid)), "cgroup")) //nolint:gosec // path components are validated upstream
	if err != nil {
		return "", fmt.Errorf("open /proc/%d/cgroup: %w", pid, err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return rest, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no unified cgroup line for pid %d", pid)
}
