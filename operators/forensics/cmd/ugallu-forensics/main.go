// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-forensics is the leader-elected Deployment that
// runs the SE-triggered IR-as-code pipeline: predicate-filter
// SecurityEvents, freeze the suspect Pod via (Cilium)NetworkPolicy
// + label, inject the forensics-snapshot ephemeral container, and
// emit the IncidentCaptureCompleted SE that closes the loop. The
// manual-unfreeze controller reverses the freeze when an authorized
// SA acknowledges the incident SE.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"

	"github.com/ninsun-labs/ugallu/operators/forensics/pkg/forensics"
)

const version = "v0.0.1-alpha.1"

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
}

func main() {
	if err := runMain(); err != nil {
		ctrl.Log.Error(err, "fatal")
		os.Exit(1)
	}
}

func runMain() error {
	var (
		metricsAddr        string
		probeAddr          string
		leaderElectionNS   string
		clusterID          string
		snapshotImage      string
		snapshotImagePull  string
		wormBucket         string
		wormEndpoint       string
		wormRegion         string
		wormSecretName     string
		wormSecretNS       string
		wormUsePathStyle   bool
		wormLockMode       string
		wormLockUntil      time.Duration
		forensicsNamespace string
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "ugallu-system-privileged", "Leader election Lease namespace")
	flag.StringVar(&clusterID, "cluster-id", "", "ClusterIdentity stamped on emitted SecurityEvents")
	flag.StringVar(&snapshotImage, "snapshot-image", "", "Multi-binary runtime image carrying /bin/ugallu-forensics-snapshot")
	flag.StringVar(&snapshotImagePull, "snapshot-image-pull-policy", "IfNotPresent", "Pull policy for the snapshot image")
	flag.StringVar(&wormBucket, "worm-bucket", "ugallu", "Destination S3 bucket for snapshots")
	flag.StringVar(&wormEndpoint, "worm-endpoint", "", "S3 endpoint URL (empty uses AWS S3)")
	flag.StringVar(&wormRegion, "worm-region", "us-east-1", "S3 region header")
	flag.BoolVar(&wormUsePathStyle, "worm-path-style", true, "Force path-style S3 addressing (SeaweedFS / MinIO)")
	flag.StringVar(&wormSecretName, "worm-secret-name", forensics.DefaultWORMSecretName, "Secret name carrying access-key + secret-key")
	flag.StringVar(&wormSecretNS, "worm-secret-namespace", forensics.DefaultWORMSecretNamespace, "Namespace where the master WORM Secret lives")
	flag.StringVar(&wormLockMode, "worm-lock-mode", "COMPLIANCE", "Object Lock mode (COMPLIANCE/GOVERNANCE/NONE)")
	flag.DurationVar(&wormLockUntil, "worm-lock-until", 168*time.Hour, "Object Lock retention duration")
	flag.StringVar(&forensicsNamespace, "forensics-namespace", "ugallu-system-privileged", "Namespace where the forensics workload runs (used as egress target in the freeze policy)")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log := ctrl.Log.WithName("ugallu-forensics")
	log.Info("starting", "version", version)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          true,
		LeaderElectionID:        "ugallu-forensics-leader",
		LeaderElectionNamespace: leaderElectionNS,
		// Disable the controller-runtime cache for Secrets - the
		// CredentialsMirror does direct Get/Create only, and a
		// cluster-wide Secret list/watch would require excessive
		// RBAC + leak data through the in-memory cache.
		Client: client.Options{
			Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}},
		},
	})
	if err != nil {
		return fmt.Errorf("manager: %w", err)
	}
	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("healthz: %w", err)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("readyz: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("clientset: %w", err)
	}
	disco, err := discovery.NewDiscoveryClientForConfig(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}

	cni, err := forensics.NewCNIDetector(disco, 10*time.Minute)
	if err != nil {
		return fmt.Errorf("cni detector: %w", err)
	}

	freezer, err := forensics.NewFreezer(&forensics.FreezerOptions{
		Client:             mgr.GetClient(),
		Backend:            cni.Backend(),
		ForensicsNamespace: forensicsNamespace,
		ForensicsAppLabel:  "ugallu-forensics",
	})
	if err != nil {
		return fmt.Errorf("freezer: %w", err)
	}

	em, err := emitterv1alpha1.NewEmitter(&emitterv1alpha1.EmitterOpts{
		Client:       mgr.GetClient(),
		AttestorMeta: sign.AttestorMeta{Name: "ugallu-forensics", Version: version},
	})
	if err != nil {
		return fmt.Errorf("emitter: %w", err)
	}

	snap, err := forensics.NewSnapshotter(&forensics.SnapshotterOptions{
		Client:           mgr.GetClient(),
		Clientset:        clientset,
		Image:            snapshotImage,
		ImagePullPolicy:  parsePullPolicy(snapshotImagePull),
		WORMEndpoint:     wormEndpoint,
		WORMBucket:       wormBucket,
		WORMRegion:       wormRegion,
		WORMUsePathStyle: wormUsePathStyle,
		WORMSecretName:   wormSecretName,
		LockMode:         wormLockMode,
		LockUntil:        wormLockUntil,
	})
	if err != nil {
		return fmt.Errorf("snapshotter: %w", err)
	}

	mirror := &forensics.CredentialsMirror{
		Client:     mgr.GetClient(),
		SourceName: wormSecretName,
		SourceNS:   wormSecretNS,
		TargetName: wormSecretName,
	}

	clusterIdentity := securityv1alpha1.ClusterIdentity{ClusterID: clusterID, ClusterName: clusterID}
	stepRunner, err := forensics.NewStepRunner(mgr.GetClient(), clusterIdentity)
	if err != nil {
		return fmt.Errorf("step runner: %w", err)
	}

	wormCreds, err := readWORMCredsFromEnv()
	if err != nil {
		return err
	}
	evidenceUploader, err := forensics.NewEvidenceUploader(context.Background(), &forensics.EvidenceUploaderOptions{
		Bucket:       wormBucket,
		Endpoint:     wormEndpoint,
		Region:       wormRegion,
		UsePathStyle: wormUsePathStyle,
		AccessKey:    wormCreds.AccessKey,
		SecretKey:    wormCreds.SecretKey,
		LockMode:     wormLockMode,
		LockUntil:    wormLockUntil,
	})
	if err != nil {
		return fmt.Errorf("evidence uploader: %w", err)
	}

	pipe, err := forensics.NewPipeline(&forensics.PipelineOptions{
		Client:            mgr.GetClient(),
		Emitter:           em,
		Freezer:           freezer,
		Snapshotter:       snap,
		CredentialsMirror: mirror,
		StepRunner:        stepRunner,
		EvidenceUploader:  evidenceUploader,
		ClusterIdentity:   clusterIdentity,
		Log:               slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
	})
	if err != nil {
		return fmt.Errorf("pipeline: %w", err)
	}

	if err = (&forensics.SecurityEventReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Pipeline: pipe,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup SE reconciler: %w", err)
	}
	if err = (&forensics.UnfreezeReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Freezer:    freezer,
		StepRunner: stepRunner,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup unfreeze reconciler: %w", err)
	}
	if err = (&forensics.ConfigReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		CNI:      cni,
		Pipeline: pipe,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup ForensicsConfig reconciler: %w", err)
	}

	if addErr := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		em.Start(ctx)
		defer em.Close()
		go cni.Run(ctx)
		<-ctx.Done()
		return nil
	})); addErr != nil {
		return fmt.Errorf("add runnable: %w", addErr)
	}

	// Crash-recovery sweep: at boot (after the cache is hydrated)
	// list every Pending/Running ER managed by forensics and apply
	// the per-step recovery policy (idempotent retry where
	// possible, mark Permanent where the step is non-recoverable).
	// Runs once and exits - the live reconcilers take over from
	// there.
	recoverer, err := forensics.NewRecoverer(mgr.GetClient(), clientset, freezer, snap, evidenceUploader, stepRunner)
	if err != nil {
		return fmt.Errorf("recoverer: %w", err)
	}
	if addErr := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		// Wait briefly for the controller-runtime cache to start.
		// The recoverer uses client.List which goes through the
		// cache; calling before it's synced returns empty.
		if !mgr.GetCache().WaitForCacheSync(ctx) {
			return fmt.Errorf("recoverer: cache sync failed")
		}
		if recErr := recoverer.Recover(ctx); recErr != nil {
			ctrl.Log.WithName("recoverer").Error(recErr, "recovery sweep failed; live reconcilers continue")
		}
		<-ctx.Done()
		return nil
	})); addErr != nil {
		return fmt.Errorf("add recoverer: %w", addErr)
	}

	log.Info("running manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}

func parsePullPolicy(p string) corev1.PullPolicy {
	switch strings.ToLower(p) {
	case "always":
		return corev1.PullAlways
	case "never":
		return corev1.PullNever
	default:
		return corev1.PullIfNotPresent
	}
}

// wormCreds carries the access/secret pair the operator side
// needs to write the manifest blob through the same WORM bucket
// the snapshot ephemeral container uploads to. The values come
// from env (mounted via the chart's WORM secret) so the operator
// pod inherits the existing rotation cadence rather than reading
// the Secret cluster-wide each reconcile.
type wormCreds struct {
	AccessKey string
	SecretKey string
}

// readWORMCredsFromEnv reads WORM_ACCESS_KEY + WORM_SECRET_KEY off
// the operator pod's env. The chart wires these from the same
// `ugallu-worm-creds` Secret the snapshot ephemeral container
// uses (mirrored into the suspect Pod namespace at injection time).
func readWORMCredsFromEnv() (*wormCreds, error) {
	a := strings.TrimSpace(os.Getenv("WORM_ACCESS_KEY"))
	s := strings.TrimSpace(os.Getenv("WORM_SECRET_KEY"))
	if a == "" || s == "" {
		return nil, fmt.Errorf("WORM credentials missing: env WORM_ACCESS_KEY + WORM_SECRET_KEY must both be set")
	}
	return &wormCreds{AccessKey: a, SecretKey: s}, nil
}
