// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1

import (
	"context"
	"log/slog"
	"time"
)

// DefaultCgroupRescanInterval is the period at which RunCgroupRescan
// re-walks /sys/fs/cgroup to pick up pods created after bootstrap.
// 60s is a sensible default until the Phase 3 eBPF tracer obsoletes
// the polling loop entirely.
const DefaultCgroupRescanInterval = 60 * time.Second

// RunCgroupRescan re-runs the cgroup walker periodically until ctx is
// cancelled. Each pass refreshes podByCgroupID for newly-started pods
// (the index is additive — old entries survive until the pod is
// tombstoned and PurgeExpired evicts them via cgroupIDsByPod).
//
// interval <= 0 disables the loop entirely so callers can opt out.
func RunCgroupRescan(ctx context.Context, c *Cache, sysfsRoot string, interval time.Duration, log *slog.Logger) {
	if interval <= 0 {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := WalkCgroupFS(sysfsRoot, c)
			if err != nil {
				log.Warn("cgroup rescan failed", "err", err.Error())
				continue
			}
			updateCgroupIndexSize(c)
			log.Debug("cgroup rescan", "indexed", n)
		}
	}
}
