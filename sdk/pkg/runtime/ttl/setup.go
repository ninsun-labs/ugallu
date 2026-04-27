// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package ttl

import (
	"fmt"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"

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
	// SE/ER's parent AttestationBundle is not yet Sealed. Defaults to
	// 1h (design 09 T5).
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

	if err := (&SecurityEventTTLReconciler{
		Client:                  mgr.GetClient(),
		Scheme:                  mgr.GetScheme(),
		WormUploader:            opts.WormUploader,
		PostponeOnMissingBundle: opts.PostponeOnMissingBundle,
		TTLConfigNamespace:      opts.TTLConfigNamespace,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup SecurityEventTTLReconciler: %w", err)
	}
	if err := (&EventResponseTTLReconciler{
		Client:                  mgr.GetClient(),
		Scheme:                  mgr.GetScheme(),
		WormUploader:            opts.WormUploader,
		PostponeOnMissingBundle: opts.PostponeOnMissingBundle,
		TTLConfigNamespace:      opts.TTLConfigNamespace,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup EventResponseTTLReconciler: %w", err)
	}
	if err := (&AttestationBundleTTLReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		WormUploader:       opts.WormUploader,
		Grace:              opts.BundleGrace,
		TTLConfigNamespace: opts.TTLConfigNamespace,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup AttestationBundleTTLReconciler: %w", err)
	}

	enableWatchdog := true
	if opts.EnableWatchdog != nil {
		enableWatchdog = *opts.EnableWatchdog
	}
	if enableWatchdog {
		ns := opts.TTLConfigNamespace
		if ns == "" {
			ns = DefaultTTLConfigNamespace
		}
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
