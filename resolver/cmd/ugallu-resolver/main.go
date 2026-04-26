// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-resolver is the DaemonSet binary providing subject lookup
// to detection sources, reasoners, and responders.
//
// This is a pre-alpha skeleton: the gRPC server registers all RPCs from
// the v1 proto contract, but every lookup returns Unresolved=true with a
// diagnostic. The eBPF cgroup tracker, informer cache, indices, and
// tombstone GC are pending.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"google.golang.org/grpc"

	resolverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/clientv1"
)

const version = "v0.0.1-alpha.1"

func main() {
	if err := runMain(); err != nil {
		slog.Default().Error("fatal", "err", err)
		os.Exit(1)
	}
}

func runMain() error {
	var (
		grpcAddr   string
		unixSocket string
	)
	flag.StringVar(&grpcAddr, "grpc-addr", ":9000", "TCP address for cross-node gRPC server")
	flag.StringVar(&unixSocket, "unix-socket", "/var/run/ugallu/resolver.sock", "Unix socket path for local-node gRPC")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With(
		"component", "ugallu-resolver",
		"version", version,
	)
	log.Info("starting")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, log, grpcAddr, unixSocket); err != nil {
		return err
	}
	log.Info("shutdown complete")
	return nil
}

func run(ctx context.Context, log *slog.Logger, grpcAddr, unixSocket string) error {
	server := grpc.NewServer()
	resolverv1.RegisterResolverServer(server, &skeletonServer{log: log})

	tcpListener, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", grpcAddr, err)
	}
	log.Info("listening", "transport", "tcp", "addr", grpcAddr)

	var unixListener net.Listener
	if unixSocket != "" {
		if mkdirErr := os.MkdirAll(filepath.Dir(unixSocket), 0o750); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
			log.Warn("unix socket dir mkdir failed (continuing TCP-only)", "path", filepath.Dir(unixSocket), "err", mkdirErr)
		} else {
			_ = os.Remove(unixSocket)
			ul, ulErr := net.Listen("unix", unixSocket)
			if ulErr != nil {
				log.Warn("unix socket listen failed (continuing TCP-only)", "path", unixSocket, "err", ulErr)
			} else {
				unixListener = ul
				log.Info("listening", "transport", "unix", "path", unixSocket)
			}
		}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if serveErr := server.Serve(tcpListener); serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
			errCh <- fmt.Errorf("tcp serve: %w", serveErr)
		}
	}()

	if unixListener != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if serveErr := server.Serve(unixListener); serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
				errCh <- fmt.Errorf("unix serve: %w", serveErr)
			}
		}()
	}

	select {
	case <-ctx.Done():
		log.Info("signal received, draining gRPC")
		server.GracefulStop()
		wg.Wait()
		return nil
	case err := <-errCh:
		server.GracefulStop()
		wg.Wait()
		return err
	}
}

// skeletonServer returns Unresolved=true for every lookup. Replace with the
// real implementation when the eBPF tracker + informer cache land.
type skeletonServer struct {
	resolverv1.UnimplementedResolverServer
	log *slog.Logger
}

func (s *skeletonServer) ResolveByCgroupID(_ context.Context, req *resolverv1.CgroupIDRequest) (*resolverv1.SubjectResponse, error) {
	s.log.Debug("ResolveByCgroupID", "cgroup_id", req.GetCgroupId())
	return unresolved("ResolveByCgroupID skeleton"), nil
}

func (s *skeletonServer) ResolveByPID(_ context.Context, req *resolverv1.PIDRequest) (*resolverv1.SubjectResponse, error) {
	s.log.Debug("ResolveByPID", "pid", req.GetPid())
	return unresolved("ResolveByPID skeleton"), nil
}

func (s *skeletonServer) ResolveByPodIP(_ context.Context, req *resolverv1.PodIPRequest) (*resolverv1.SubjectResponse, error) {
	s.log.Debug("ResolveByPodIP", "ip", req.GetIp())
	return unresolved("ResolveByPodIP skeleton"), nil
}

func (s *skeletonServer) ResolveByPodUID(_ context.Context, req *resolverv1.PodUIDRequest) (*resolverv1.SubjectResponse, error) {
	s.log.Debug("ResolveByPodUID", "uid", req.GetUid())
	return unresolved("ResolveByPodUID skeleton"), nil
}

func (s *skeletonServer) ResolveByContainerID(_ context.Context, req *resolverv1.ContainerIDRequest) (*resolverv1.SubjectResponse, error) {
	s.log.Debug("ResolveByContainerID", "id", req.GetContainerId())
	return unresolved("ResolveByContainerID skeleton"), nil
}

func (s *skeletonServer) ResolveBySAUsername(_ context.Context, req *resolverv1.SAUsernameRequest) (*resolverv1.SubjectResponse, error) {
	s.log.Debug("ResolveBySAUsername", "username", req.GetUsername())
	return unresolved("ResolveBySAUsername skeleton"), nil
}

func (s *skeletonServer) Watch(_ *resolverv1.WatchRequest, _ resolverv1.Resolver_WatchServer) error {
	// Skeleton: close stream immediately. Real implementation will stream
	// SubjectChange events from the informer cache.
	return nil
}

func unresolved(diag string) *resolverv1.SubjectResponse {
	return &resolverv1.SubjectResponse{
		Unresolved: true,
		Diagnostic: diag,
	}
}
