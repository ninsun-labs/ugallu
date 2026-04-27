// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package serverv1

import "errors"

// DefaultSysFsCgroup mirrors the Linux constant for cross-platform
// compilation; it has no functional meaning off Linux.
const DefaultSysFsCgroup = "/sys/fs/cgroup"

// DefaultProcRoot mirrors the Linux constant for cross-platform
// compilation.
const DefaultProcRoot = "/host/proc"

// errCgroupUnsupported is the canonical error returned by every
// cgroup helper when built on a non-Linux platform. Server methods
// surface it as Unresolved with a diagnostic so consumers don't
// crash on developer laptops running the unit suite.
var errCgroupUnsupported = errors.New("cgroup operations require Linux")

// WalkCgroupFS is a no-op stub on non-Linux platforms.
func WalkCgroupFS(_ string, _ *Cache) (int, error) {
	return 0, errCgroupUnsupported
}

// CgroupIDForPID is a no-op stub on non-Linux platforms.
func CgroupIDForPID(_, _ string, _ int32) (cgroupID uint64, cgroupPath string, err error) {
	return 0, "", errCgroupUnsupported
}

// PodInfoForPID is a no-op stub on non-Linux platforms.
func PodInfoForPID(_ string, _ int32) (CgroupPathInfo, error) {
	return CgroupPathInfo{}, errCgroupUnsupported
}
