// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package auditdetection

import "os"

// sameInode falls back to size+modtime on non-Linux. The
// audit-detection runtime target is Linux DaemonSets; this exists
// only so the package builds on developer macOS workstations.
func sameInode(a, b os.FileInfo) bool {
	return a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
