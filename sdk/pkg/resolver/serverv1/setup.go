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
}

// Bootstrap builds the Cache, attaches informer event handlers, waits
// for cache sync, registers metrics, and returns the gRPC server
// implementation ready to be installed on a *grpc.Server. The
// tombstone GC runs in a goroutine bound to ctx.
func Bootstrap(ctx context.Context, opts Options) (*Server, error) {
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

	return NewServer(cache, log), nil
}

// Register installs s on the given gRPC server (just a thin wrapper
// over the generated Register that callers will reach for from
// main.go).
func Register(grpcSrv *grpc.Server, s *Server) {
	resolverv1.RegisterResolverServer(grpcSrv, s)
}
