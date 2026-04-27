// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-attestor is the leader-elected Deployment that signs
// SecurityEvent and EventResponse facts as in-toto attestations and
// stores them on Rekor + WORM.
//
// Pre-alpha (iter 2): three reconcilers from sdk/pkg/evidence/attestor are
// wired (SecurityEvent watcher, EventResponse watcher, AttestationBundle
// pipeline). Bundles are signed via the in-process Ed25519 Signer (the
// default in this build). Real Fulcio keyless / OpenBao transit signing
// + Rekor logging + WORM archival arrive in subsequent commits.
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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/attestor"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/logger"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/worm"
)

const version = "v0.0.1-alpha.1"

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
}

func main() {
	if err := runMain(); err != nil {
		// Logger already set up by runMain; fall back to stderr if not.
		ctrl.Log.Error(err, "fatal")
		os.Exit(1)
	}
}

func runMain() error {
	var (
		metricsAddr      string
		probeAddr        string
		leaderElectionNS string
		signingMode      string
		instanceName     string
		rekorURL         string
		attestorConfigNS string

		wormBackend     string
		wormStubDir     string
		s3Bucket        string
		s3Region        string
		s3Endpoint      string
		s3PathStyle     bool
		s3KeyPrefix     string
		s3LockMode      string
		s3AccessKey     string
		s3SecretKey     string
		s3SecretKeyFile string
		wormRetention   time.Duration
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "ugallu-system", "Leader election Lease namespace")
	flag.StringVar(&signingMode, "signing-mode", "", "Signing mode override (ed25519-dev | fulcio-keyless | openbao-transit | dual). Empty consults AttestorConfig, then falls back to ed25519-dev.")
	flag.StringVar(&instanceName, "instance", os.Getenv("HOSTNAME"), "Attestor instance identifier (recorded in the in-toto Statement; defaults to $HOSTNAME)")
	flag.StringVar(&rekorURL, "rekor-url", "", "Rekor v1 base URL override. Empty consults AttestorConfig (rekor.enabled+rekor.url); a missing/disabled config falls back to the StubLogger.")
	flag.StringVar(&attestorConfigNS, "attestor-config-namespace", "ugallu-system", "Namespace of the AttestorConfig singleton")

	flag.StringVar(&wormBackend, "worm-backend", "stub", "WORM backend: stub|s3")
	flag.StringVar(&wormStubDir, "worm-stub-dir", "/tmp/ugallu-worm", "Filesystem WORM stub base directory (worm-backend=stub)")
	flag.StringVar(&s3Bucket, "worm-s3-bucket", "", "S3 bucket for evidence (worm-backend=s3)")
	flag.StringVar(&s3Region, "worm-s3-region", "us-east-1", "S3 region")
	flag.StringVar(&s3Endpoint, "worm-s3-endpoint", "", "S3 endpoint URL (e.g. http://seaweedfs-s3:8333). Empty uses AWS S3.")
	flag.BoolVar(&s3PathStyle, "worm-s3-path-style", true, "Use path-style S3 addressing (required for SeaweedFS/MinIO)")
	flag.StringVar(&s3KeyPrefix, "worm-s3-key-prefix", "", "Key prefix prepended to every WORM object")
	flag.StringVar(&s3LockMode, "worm-s3-lock-mode", "COMPLIANCE", "Object Lock mode: COMPLIANCE|GOVERNANCE|NONE")
	flag.StringVar(&s3AccessKey, "worm-s3-access-key", "", "S3 access key (use credential chain when empty)")
	flag.StringVar(&s3SecretKey, "worm-s3-secret-key", "", "S3 secret key (prefer worm-s3-secret-key-file)")
	flag.StringVar(&s3SecretKeyFile, "worm-s3-secret-key-file", "", "Path to a file containing the S3 secret key")
	flag.DurationVar(&wormRetention, "worm-retention", 0, "Object Lock retain-until duration applied to archived DSSE envelopes (0 disables)")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log := ctrl.Log.WithName("ugallu-attestor")
	log.Info("starting", "version", version)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          true,
		LeaderElectionID:        "ugallu-attestor-leader",
		LeaderElectionNamespace: leaderElectionNS,
	})
	if err != nil {
		return fmt.Errorf("manager creation: %w", err)
	}

	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("healthz check setup: %w", err)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("readyz check setup: %w", err)
	}

	// Resolve effective signing mode + Rekor URL: CLI flag wins; absent
	// flags consult the AttestorConfig CR; absent CR falls back to
	// baked-in defaults (ed25519-dev, no Rekor).
	effSigningMode, effRekorURL := signingMode, rekorURL
	if effSigningMode == "" || effRekorURL == "" {
		bootClient, bcErr := client.New(mgr.GetConfig(), client.Options{Scheme: scheme})
		if bcErr != nil {
			return fmt.Errorf("bootstrap client: %w", bcErr)
		}
		spec, lcErr := attestor.LoadAttestorConfig(context.Background(), bootClient, attestorConfigNS)
		if lcErr != nil {
			log.Info("AttestorConfig load failed; falling back to defaults", "error", lcErr.Error())
		} else if spec != nil {
			if effSigningMode == "" && spec.SigningMode != "" {
				effSigningMode = string(spec.SigningMode)
			}
			if effRekorURL == "" && spec.Rekor.Enabled {
				effRekorURL = spec.Rekor.URL
			}
		}
	}
	if effSigningMode == "" {
		effSigningMode = string(securityv1alpha1.SigningModeEd25519Dev)
	}

	signer, err := sign.NewSigner(securityv1alpha1.SigningMode(effSigningMode))
	if err != nil {
		return fmt.Errorf("signer setup (mode=%s): %w", effSigningMode, err)
	}
	log.Info("signer ready", "mode", signer.Mode(), "keyID", signer.KeyID())

	var transparencyLogger logger.Logger
	if effRekorURL != "" {
		exporter, ok := signer.(sign.PublicKeyExporter)
		if !ok {
			return fmt.Errorf("rekor logging requires a signer that implements PublicKeyExporter; got %T", signer)
		}
		pem, pemErr := exporter.PublicKeyPEM()
		if pemErr != nil {
			return fmt.Errorf("export signer public key: %w", pemErr)
		}
		rl, rlErr := logger.NewRekorLogger(effRekorURL, pem)
		if rlErr != nil {
			return fmt.Errorf("rekor logger setup: %w", rlErr)
		}
		transparencyLogger = rl
		log.Info("rekor logger ready", "url", effRekorURL)
	}

	wormUploader, err := buildWormUploader(wormBackend, s3Bucket, s3Region, s3Endpoint, s3PathStyle, s3KeyPrefix, s3LockMode, s3AccessKey, s3SecretKey, s3SecretKeyFile)
	if err != nil {
		return fmt.Errorf("worm uploader: %w", err)
	}
	if wormUploader != nil {
		log.Info("worm uploader ready", "endpoint", wormUploader.Endpoint())
	}

	if err = attestor.SetupReconcilers(mgr, &attestor.Options{
		Signer:        signer,
		Logger:        transparencyLogger,
		WormUploader:  wormUploader,
		WormStubDir:   wormStubDir,
		WormRetention: wormRetention,
		Attestor: sign.AttestorMeta{
			Name:     "ugallu-attestor",
			Version:  version,
			Instance: instanceName,
		},
	}); err != nil {
		return fmt.Errorf("attestor reconcilers setup: %w", err)
	}

	log.Info("running manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}

// buildWormUploader returns the configured WORM uploader, or nil to
// have attestor.SetupReconcilers build a default StubUploader at
// WormStubDir.
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
