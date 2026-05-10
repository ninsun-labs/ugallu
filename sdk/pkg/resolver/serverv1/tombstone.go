// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1

import (
	"context"
	"log/slog"
	"time"
)

// DefaultTombstoneInterval is how often the GC loop scans for expired
// tombstones (30s: a half of the 60s grace).
const DefaultTombstoneInterval = 30 * time.Second

// RunTombstoneGC blocks until ctx is cancelled, periodically purging
// tombstoned Pod entries past their grace window. Index gauges are
// refreshed on every tick so monitoring picks up the eviction.
func RunTombstoneGC(ctx context.Context, c *Cache, interval time.Duration, log *slog.Logger) {
	if interval <= 0 {
		interval = DefaultTombstoneInterval
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
		case now := <-t.C:
			n := c.PurgeExpired(now)
			updateIndexSizes(c)
			if n > 0 {
				metricTombstonePurged.Add(float64(n))
				log.Debug("tombstone GC", "purged", n)
			}
		}
	}
}
