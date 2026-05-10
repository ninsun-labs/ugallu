// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package ttl

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/time/rate"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/worm"
)

// Options configures the TTL reconcilers.
type Options struct {
	// WormUploader persists CR YAML snapshots before delete. If nil, a
	// filesystem-backed StubUploader rooted at WormStubDir is used
	// (or /tmp/ugallu-ttl-worm when WormStubDir is empty). Production
	// deployments should inject a real S3-backed uploader.
	WormUploader worm.Uploader

	// WormStubDir overrides the StubUploader base directory when
	// WormUploader is nil. Empty falls back to /tmp/ugallu-ttl-worm.
	WormStubDir string

	// PostponeOnMissingBundle is the requeue interval applied when an
	// SE/ER's parent AttestationBundle is not yet Sealed. Defaults to 1h.
	PostponeOnMissingBundle time.Duration

	// BundleGrace overrides the AttestationBundle sealed-to-archive
	// grace window. When zero, the loaded TTLConfig drives this with
	// a hardcoded 7d fallback.
	BundleGrace time.Duration

	// TTLConfigNamespace is the namespace consulted for the TTLConfig
	// singleton. Defaults to "ugallu-system".
	TTLConfigNamespace string

	// EnableWatchdog opts in to the AttestorWatchdogReconciler that
	// emits anomaly SEs when the attestor Lease falls behind. Defaults
	// to true.
	EnableWatchdog *bool

	// WatchdogStaleAfter overrides the Lease staleness threshold.
	WatchdogStaleAfter time.Duration

	// WatchdogDedupWindow overrides the anomaly emission dedup window.
	WatchdogDedupWindow time.Duration

	// MaxConcurrentReconciles caps per-reconciler parallelism. Zero
	// consults the TTLConfig CR's spec.worker.poolSize (or
	// DefaultWorkerPoolSize when the CR is absent or unset).
	MaxConcurrentReconciles int

	// QueueQPS optionally throttles the global rate at which items
	// are pulled off the workqueue (events/sec). Zero consults the
	// TTLConfig CR's spec.worker.queueRateLimit; zero on both sides
	// means "no global throttle" — only the per-item exponential
	// backoff applies.
	QueueQPS float64
}

// SetupReconcilers wires the three TTL reconcilers
// (SecurityEvent, EventResponse, AttestationBundle) into the manager.
//
// Call this from ugallu-ttl's main() before mgr.Start().
func SetupReconcilers(mgr ctrl.Manager, opts *Options) error {
	if opts == nil {
		opts = &Options{}
	}
	if opts.WormUploader == nil {
		dir := opts.WormStubDir
		if dir == "" {
			dir = "/tmp/ugallu-ttl-worm"
		}
		u, err := worm.NewStubUploader(dir)
		if err != nil {
			return fmt.Errorf("default WORM stub uploader: %w", err)
		}
		opts.WormUploader = u
	}

	// Resolve the worker tunables: explicit Options field wins; absent
	// fields consult the TTLConfig CR; absent CR yields baked defaults.
	ns := opts.TTLConfigNamespace
	if ns == "" {
		ns = DefaultTTLConfigNamespace
	}
	cfg, err := loadEffectiveTTLConfig(context.Background(), mgr.GetClient(), ns)
	if err != nil {
		// Treat lookup failure as "no CR": preserves bootability when
		// the CRD or RBAC is mid-deploy. Reconcilers themselves load
		// the CR per-reconcile so live updates still take effect.
		cfg = effectiveTTLConfig{}
	}
	maxConcurrent := opts.MaxConcurrentReconciles
	if maxConcurrent <= 0 {
		maxConcurrent = cfg.workerPoolSize()
	}
	queueQPS := opts.QueueQPS
	if queueQPS <= 0 {
		queueQPS = cfg.queueQPS()
	}
	ctrlOpts := controller.Options{MaxConcurrentReconciles: maxConcurrent}
	if queueQPS > 0 {
		ctrlOpts.RateLimiter = newTunedRateLimiter(queueQPS)
	}

	if err := (&SecurityEventTTLReconciler{
		Client:                  mgr.GetClient(),
		Scheme:                  mgr.GetScheme(),
		WormUploader:            opts.WormUploader,
		PostponeOnMissingBundle: opts.PostponeOnMissingBundle,
		TTLConfigNamespace:      opts.TTLConfigNamespace,
	}).SetupWithManagerAndOptions(mgr, ctrlOpts); err != nil {
		return fmt.Errorf("setup SecurityEventTTLReconciler: %w", err)
	}
	if err := (&EventResponseTTLReconciler{
		Client:                  mgr.GetClient(),
		Scheme:                  mgr.GetScheme(),
		WormUploader:            opts.WormUploader,
		PostponeOnMissingBundle: opts.PostponeOnMissingBundle,
		TTLConfigNamespace:      opts.TTLConfigNamespace,
	}).SetupWithManagerAndOptions(mgr, ctrlOpts); err != nil {
		return fmt.Errorf("setup EventResponseTTLReconciler: %w", err)
	}
	if err := (&AttestationBundleTTLReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		WormUploader:       opts.WormUploader,
		Grace:              opts.BundleGrace,
		TTLConfigNamespace: opts.TTLConfigNamespace,
	}).SetupWithManagerAndOptions(mgr, ctrlOpts); err != nil {
		return fmt.Errorf("setup AttestationBundleTTLReconciler: %w", err)
	}

	enableWatchdog := true
	if opts.EnableWatchdog != nil {
		enableWatchdog = *opts.EnableWatchdog
	}
	if enableWatchdog {
		if err := (&AttestorWatchdogReconciler{
			Client:         mgr.GetClient(),
			Scheme:         mgr.GetScheme(),
			LeaseNamespace: ns,
			StaleAfter:     opts.WatchdogStaleAfter,
			DedupWindow:    opts.WatchdogDedupWindow,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("setup AttestorWatchdogReconciler: %w", err)
		}
	}
	return nil
}

// newTunedRateLimiter combines the standard per-item exponential
// failure backoff with a global token bucket so a hot reconciler can't
// drown the apiserver. qps is the bucket fill rate; burst is fixed at
// 2x qps to absorb minor spikes.
func newTunedRateLimiter(qps float64) workqueue.TypedRateLimiter[reconcile.Request] {
	burst := int(qps * 2)
	if burst < 1 {
		burst = 1
	}
	return workqueue.NewTypedMaxOfRateLimiter(
		workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](5*time.Millisecond, 1000*time.Second),
		&workqueue.TypedBucketRateLimiter[reconcile.Request]{Limiter: rate.NewLimiter(rate.Limit(qps), burst)},
	)
}
