// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"k8s.io/client-go/kubernetes"

	resolverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/clientv1"
	"google.golang.org/grpc"
)

// Options configure resolver bootstrap.
type Options struct {
	// Client is the kube client backing the informers. Required.
	Client kubernetes.Interface

	// Log is the structured logger. nil falls back to slog.Default.
	Log *slog.Logger

	// InformerResync overrides the periodic full re-list interval
	// (default 10m).
	InformerResync time.Duration

	// TombstoneGrace overrides the Pod tombstone retention (default
	// 60s per design 03).
	TombstoneGrace time.Duration

	// TombstoneInterval overrides the GC scan period (default 30s).
	TombstoneInterval time.Duration

	// SysFsCgroupRoot overrides the cgroup v2 mountpoint
	// (DefaultSysFsCgroup when empty).
	SysFsCgroupRoot string

	// ProcRoot overrides /proc (DefaultProcRoot when empty).
	ProcRoot string

	// CgroupRescanInterval is the period at which the cgroup walker
	// re-runs to pick up pods created after bootstrap. Zero or
	// negative values disable the rescan loop. Defaults to
	// DefaultCgroupRescanInterval. Phase 3's eBPF tracer will obsolete
	// this in favour of live updates.
	CgroupRescanInterval time.Duration

	// SkipCgroupWalk disables the cold-walk + rescan entirely (used
	// in unit tests where /sys/fs/cgroup isn't a kubepods hierarchy).
	SkipCgroupWalk bool
}

// Bootstrap builds the Cache, attaches informer event handlers, waits
// for cache sync, registers metrics, and returns the gRPC server
// implementation ready to be installed on a *grpc.Server. The
// tombstone GC runs in a goroutine bound to ctx.
func Bootstrap(ctx context.Context, opts *Options) (*Server, error) {
	if opts == nil {
		return nil, fmt.Errorf("opts is required")
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("Options.Client is required")
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	MustRegisterMetrics()

	cache := NewCache(opts.TombstoneGrace)
	factory := NewSharedInformerFactory(opts.Client, opts.InformerResync)
	if err := AttachInformers(cache, factory); err != nil {
		return nil, fmt.Errorf("attach informers: %w", err)
	}
	if err := WaitForCacheSync(ctx, factory); err != nil {
		return nil, fmt.Errorf("informer sync: %w", err)
	}
	updateIndexSizes(cache)

	go RunTombstoneGC(ctx, cache, opts.TombstoneInterval, log)

	if !opts.SkipCgroupWalk {
		// Cold-walk seeds the cgroup-ID index for every pod that
		// existed at startup. New pods after bootstrap are picked up
		// by the rescan loop (until Phase 3 eBPF replaces it with
		// live updates).
		n, err := WalkCgroupFS(opts.SysFsCgroupRoot, cache)
		if err != nil {
			// Permission errors and missing /sys/fs/cgroup on dev
			// machines are common; log and continue rather than
			// failing the binary.
			log.Warn("cgroup cold-walk failed (continuing without cgroup index)", "err", err.Error())
		} else {
			log.Info("cgroup cold-walk complete", "indexed", n)
			updateCgroupIndexSize(cache)
		}
		go RunCgroupRescan(ctx, cache, opts.SysFsCgroupRoot, opts.CgroupRescanInterval, log)
	}

	srv := NewServer(cache, log)
	srv.SysFsCgroupRoot = opts.SysFsCgroupRoot
	srv.ProcRoot = opts.ProcRoot
	return srv, nil
}

// Register installs s on the given gRPC server (just a thin wrapper
// over the generated Register that callers will reach for from
// main.go).
func Register(grpcSrv *grpc.Server, s *Server) {
	resolverv1.RegisterResolverServer(grpcSrv, s)
}
