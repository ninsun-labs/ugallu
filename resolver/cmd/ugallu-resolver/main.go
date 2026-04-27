// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-resolver is the DaemonSet binary providing subject
// lookup to detection sources, reasoners, and responders.
//
// Phase 1: informer-backed cache + four working RPCs (PodIP, PodUID,
// ContainerID, SAUsername). The eBPF cgroup tracker (ResolveByCgroupID)
// and /proc walker (ResolveByPID) are stubbed Unresolved and land in
// follow-up commits per the resolver phasing plan in design 03.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	serverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/serverv1"
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
		grpcAddr             string
		unixSocket           string
		metricsAddr          string
		kubeconfig           string
		informerResync       time.Duration
		tombstoneGrace       time.Duration
		tombstoneInterval    time.Duration
		sysFsCgroupRoot      string
		procRoot             string
		cgroupRescanInterval time.Duration
		enableEBPFTracker    bool
	)
	flag.StringVar(&grpcAddr, "grpc-addr", ":9000", "TCP address for cross-node gRPC server")
	flag.StringVar(&unixSocket, "unix-socket", "/var/run/ugallu/resolver.sock", "Unix socket path for local-node gRPC")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus metrics bind address")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig file (empty uses in-cluster config)")
	flag.DurationVar(&informerResync, "informer-resync", 10*time.Minute, "Shared informer full re-list interval")
	flag.DurationVar(&tombstoneGrace, "tombstone-grace", 60*time.Second, "Pod tombstone retention window")
	flag.DurationVar(&tombstoneInterval, "tombstone-interval", 30*time.Second, "Tombstone GC scan period")
	flag.StringVar(&sysFsCgroupRoot, "sysfs-cgroup-root", serverv1.DefaultSysFsCgroup, "cgroup v2 mountpoint (host path or container bind-mount)")
	flag.StringVar(&procRoot, "proc-root", serverv1.DefaultProcRoot, "/proc root (mount the host /proc at /host/proc inside the DaemonSet)")
	flag.DurationVar(&cgroupRescanInterval, "cgroup-rescan-interval", serverv1.DefaultCgroupRescanInterval, "Cgroup index rescan period (0 disables; eBPF tracker preferred when available)")
	flag.BoolVar(&enableEBPFTracker, "enable-ebpf-tracker", false, "Opt-in to the live eBPF cgroup_mkdir/cgroup_rmdir tracker (Phase 3). Requires CAP_BPF + kernel BTF; falls back to rescan on failure.")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With(
		"component", "ugallu-resolver",
		"version", version,
	)
	log.Info("starting")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := loadKubeConfig(kubeconfig)
	if err != nil {
		return fmt.Errorf("kube config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("kube client: %w", err)
	}

	srv, err := serverv1.Bootstrap(ctx, &serverv1.Options{
		Client:               client,
		Log:                  log,
		InformerResync:       informerResync,
		TombstoneGrace:       tombstoneGrace,
		TombstoneInterval:    tombstoneInterval,
		SysFsCgroupRoot:      sysFsCgroupRoot,
		ProcRoot:             procRoot,
		CgroupRescanInterval: cgroupRescanInterval,
		EnableEBPFTracker:    enableEBPFTracker,
	})
	if err != nil {
		return fmt.Errorf("resolver bootstrap: %w", err)
	}
	log.Info("resolver bootstrap complete", "cache", srv.Cache.String())

	return run(ctx, log, grpcAddr, unixSocket, metricsAddr, srv)
}

func loadKubeConfig(path string) (*rest.Config, error) {
	if path != "" {
		return clientcmd.BuildConfigFromFlags("", path)
	}
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	if errors.Is(err, rest.ErrNotInCluster) {
		return clientcmd.BuildConfigFromFlags("",
			clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename())
	}
	return nil, err
}

func run(ctx context.Context, log *slog.Logger, grpcAddr, unixSocket, metricsAddr string, srv *serverv1.Server) error {
	grpcSrv := grpc.NewServer()
	serverv1.Register(grpcSrv, srv)

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

	metricsSrv := &http.Server{
		Addr:              metricsAddr,
		Handler:           promhttp.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if serveErr := grpcSrv.Serve(tcpListener); serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
			errCh <- fmt.Errorf("tcp serve: %w", serveErr)
		}
	}()

	if unixListener != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if serveErr := grpcSrv.Serve(unixListener); serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
				errCh <- fmt.Errorf("unix serve: %w", serveErr)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("listening", "transport", "metrics", "addr", metricsAddr)
		if serveErr := metricsSrv.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("metrics serve: %w", serveErr)
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("signal received, draining gRPC")
		grpcSrv.GracefulStop()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = metricsSrv.Shutdown(shutCtx)
		shutCancel()
		wg.Wait()
		log.Info("shutdown complete")
		return nil
	case err := <-errCh:
		grpcSrv.GracefulStop()
		_ = metricsSrv.Close()
		wg.Wait()
		return err
	}
}
