// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	"fmt"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/logger"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/worm"
)

// Options configures the attestor reconcilers.
type Options struct {
	// Signer is used by AttestationBundleReconciler to produce DSSE-signed
	// in-toto Statements. If nil, an in-process Ed25519 signer is created
	// (see sign.NewEd25519Signer). Production deployments should inject
	// a Fulcio or OpenBao-backed Signer.
	Signer sign.Signer

	// Logger publishes the signed envelope to a transparency log. If nil,
	// an in-process StubLogger is used (dev/test). Production deployments
	// should inject a real RekorLogger.
	Logger logger.Logger

	// WormUploader persists the signed envelope to immutable storage. If
	// nil, a filesystem-backed StubUploader rooted at WormStubDir (or
	// /tmp/ugallu-worm by default) is used. Production deployments
	// should inject an S3Uploader.
	WormUploader worm.Uploader

	// WormStubDir overrides the StubUploader base directory when
	// WormUploader is nil. Empty falls back to /tmp/ugallu-worm.
	WormStubDir string

	// Attestor identifies the running attestor instance; recorded in the
	// in-toto Statement predicate. If empty Name is set, defaults are used.
	Attestor sign.AttestorMeta

	// WormRetention is the Object Lock retain-until duration applied to
	// archived DSSE envelopes. Zero disables the lock header.
	WormRetention time.Duration
}

// SetupReconcilers wires the three attestor reconcilers
// (SecurityEventBundle, EventResponseBundle, AttestationBundle) into the
// given controller-runtime manager.
//
// Call this from the attestor binary's main() before mgr.Start().
func SetupReconcilers(mgr ctrl.Manager, opts *Options) error {
	if opts == nil {
		opts = &Options{}
	}
	if opts.Signer == nil {
		s, err := sign.NewEd25519Signer()
		if err != nil {
			return fmt.Errorf("default Ed25519 signer: %w", err)
		}
		opts.Signer = s
	}
	if opts.Logger == nil {
		opts.Logger = logger.NewStubLogger()
	}
	if opts.WormUploader == nil {
		dir := opts.WormStubDir
		if dir == "" {
			dir = "/tmp/ugallu-worm"
		}
		u, err := worm.NewStubUploader(dir)
		if err != nil {
			return fmt.Errorf("default WORM stub uploader: %w", err)
		}
		opts.WormUploader = u
	}
	if opts.Attestor.Name == "" {
		opts.Attestor.Name = "ugallu-attestor"
	}
	if opts.Attestor.Version == "" {
		opts.Attestor.Version = "v0.0.1-alpha.1"
	}

	if err := (&SecurityEventBundleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup SecurityEventBundleReconciler: %w", err)
	}
	if err := (&EventResponseBundleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup EventResponseBundleReconciler: %w", err)
	}
	if err := (&AttestationBundleReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Signer:        opts.Signer,
		Logger:        opts.Logger,
		WormUploader:  opts.WormUploader,
		AttestorMeta:  opts.Attestor,
		WormRetention: opts.WormRetention,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup AttestationBundleReconciler: %w", err)
	}
	return nil
}
