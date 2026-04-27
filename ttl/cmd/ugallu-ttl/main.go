// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-ttl is the leader-elected Deployment that GCs SE/ER/AB
// CRs at TTL expiry (after WORM snapshot) and acts as the attestor
// watchdog (T13 — next iteration).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/worm"
	ttlrt "github.com/ninsun-labs/ugallu/sdk/pkg/runtime/ttl"
)

const version = "v0.0.1-alpha.1"

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
}

func main() {
	if err := runMain(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runMain() error {
	var (
		metricsAddr        string
		probeAddr          string
		leaderElectionNS   string
		wormBackend        string
		wormStubDir        string
		s3Bucket           string
		s3Region           string
		s3Endpoint         string
		s3PathStyle        bool
		s3KeyPrefix        string
		s3LockMode         string
		s3AccessKey        string
		s3SecretKey        string
		s3SecretKeyFile    string
		postpone           time.Duration
		bundleGrace        time.Duration
		ttlConfigNamespace string
		enableWatchdog     bool
		watchdogStale      time.Duration
		watchdogDedup      time.Duration
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "ugallu-system", "Leader election Lease namespace")

	flag.StringVar(&wormBackend, "worm-backend", "stub", "WORM backend: stub|s3")
	flag.StringVar(&wormStubDir, "worm-stub-dir", "/tmp/ugallu-ttl-worm", "Filesystem WORM stub base directory (worm-backend=stub)")
	flag.StringVar(&s3Bucket, "worm-s3-bucket", "", "S3 bucket for evidence (worm-backend=s3)")
	flag.StringVar(&s3Region, "worm-s3-region", "us-east-1", "S3 region")
	flag.StringVar(&s3Endpoint, "worm-s3-endpoint", "", "S3 endpoint URL (e.g. http://seaweedfs-s3:8333). Empty uses AWS S3.")
	flag.BoolVar(&s3PathStyle, "worm-s3-path-style", true, "Use path-style S3 addressing (required for SeaweedFS/MinIO)")
	flag.StringVar(&s3KeyPrefix, "worm-s3-key-prefix", "", "Key prefix prepended to every WORM object")
	flag.StringVar(&s3LockMode, "worm-s3-lock-mode", "COMPLIANCE", "Object Lock mode: COMPLIANCE|GOVERNANCE|NONE")
	flag.StringVar(&s3AccessKey, "worm-s3-access-key", "", "S3 access key (use credential chain when empty)")
	flag.StringVar(&s3SecretKey, "worm-s3-secret-key", "", "S3 secret key (prefer worm-s3-secret-key-file)")
	flag.StringVar(&s3SecretKeyFile, "worm-s3-secret-key-file", "", "Path to a file containing the S3 secret key")

	flag.DurationVar(&postpone, "postpone-on-missing-bundle", time.Hour, "Requeue interval when parent bundle is not yet Sealed")
	flag.DurationVar(&bundleGrace, "bundle-grace", 0, "AttestationBundle sealed-to-archive grace override (0 = use TTLConfig)")
	flag.StringVar(&ttlConfigNamespace, "ttl-config-namespace", "ugallu-system", "Namespace of the TTLConfig singleton")
	flag.BoolVar(&enableWatchdog, "enable-attestor-watchdog", true, "Emit anomaly SEs when the attestor Lease is stale")
	flag.DurationVar(&watchdogStale, "watchdog-stale-after", 5*time.Minute, "Lease staleness threshold for attestor watchdog")
	flag.DurationVar(&watchdogDedup, "watchdog-dedup-window", 5*time.Minute, "Watchdog SE emission dedup window")
	var (
		maxConcurrent int
		queueQPS      float64
	)
	flag.IntVar(&maxConcurrent, "max-concurrent-reconciles", 0, "Per-reconciler worker pool size; 0 consults TTLConfig.spec.worker.poolSize")
	flag.Float64Var(&queueQPS, "queue-qps", 0, "Workqueue token-bucket fill rate (events/sec); 0 consults TTLConfig.spec.worker.queueRateLimit")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log := ctrl.Log.WithName("ugallu-ttl")
	log.Info("starting", "version", version)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          true,
		LeaderElectionID:        "ugallu-ttl-leader",
		LeaderElectionNamespace: leaderElectionNS,
	})
	if err != nil {
		return fmt.Errorf("manager creation failed: %w", err)
	}

	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("healthz check setup: %w", err)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("readyz check setup: %w", err)
	}

	wormUploader, err := buildWormUploader(wormBackend, s3Bucket, s3Region, s3Endpoint, s3PathStyle, s3KeyPrefix, s3LockMode, s3AccessKey, s3SecretKey, s3SecretKeyFile)
	if err != nil {
		return fmt.Errorf("worm uploader: %w", err)
	}

	if err = ttlrt.SetupReconcilers(mgr, &ttlrt.Options{
		WormUploader:            wormUploader,
		WormStubDir:             wormStubDir,
		PostponeOnMissingBundle: postpone,
		BundleGrace:             bundleGrace,
		TTLConfigNamespace:      ttlConfigNamespace,
		EnableWatchdog:          &enableWatchdog,
		WatchdogStaleAfter:      watchdogStale,
		WatchdogDedupWindow:     watchdogDedup,
		MaxConcurrentReconciles: maxConcurrent,
		QueueQPS:                queueQPS,
	}); err != nil {
		return fmt.Errorf("setup ttl reconcilers: %w", err)
	}

	log.Info("running manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited with error: %w", err)
	}
	return nil
}

// buildWormUploader returns the configured WORM uploader, or nil when
// the stub backend is selected (ttlrt.SetupReconcilers will create a
// StubUploader rooted at WormStubDir in that case).
func buildWormUploader(backend, bucket, region, endpoint string, pathStyle bool, keyPrefix, lockMode, accessKey, secretKey, secretKeyFile string) (worm.Uploader, error) {
	switch backend {
	case "", "stub":
		return nil, nil
	case "s3":
		if bucket == "" {
			return nil, fmt.Errorf("--worm-s3-bucket is required when --worm-backend=s3")
		}
		if secretKey == "" && secretKeyFile != "" {
			b, err := os.ReadFile(secretKeyFile) //nolint:gosec // path comes from operator-controlled flag
			if err != nil {
				return nil, fmt.Errorf("read secret-key-file %q: %w", secretKeyFile, err)
			}
			secretKey = string(b)
		}
		return worm.NewS3Uploader(context.Background(), &worm.S3UploaderOptions{
			Bucket:         bucket,
			Region:         region,
			EndpointURL:    endpoint,
			UsePathStyle:   pathStyle,
			KeyPrefix:      keyPrefix,
			ObjectLockMode: lockMode,
			AccessKey:      accessKey,
			SecretKey:      secretKey,
		})
	default:
		return nil, fmt.Errorf("unknown --worm-backend %q (want stub|s3)", backend)
	}
}
