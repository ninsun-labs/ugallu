// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package auditdetection

import (
	"os"
	"syscall"
)

// sameInode reports whether two FileInfo values reference the same
// underlying inode. Used by FileSource.detectRotation to spot a
// logrotate that swapped the file under the open fd — the fd keeps
// pointing at the old (renamed) inode while the path now resolves
// to a new one.
func sameInode(a, b os.FileInfo) bool {
	sa, oka := a.Sys().(*syscall.Stat_t)
	sb, okb := b.Sys().(*syscall.Stat_t)
	if !oka || !okb {
		// Without inode access fall back to size+modtime — coarser
		// but still catches the common case (kubelet recreating the
		// log file after rotation).
		return a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
	}
	return sa.Ino == sb.Ino && sa.Dev == sb.Dev
}
