// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

// Options configures the attestor reconcilers.
type Options struct {
	// Signer is used by AttestationBundleReconciler to produce DSSE-signed
	// in-toto Statements. If nil, an in-process Ed25519 signer is created
	// (see sign.NewEd25519Signer). Production deployments should inject
	// a Fulcio or OpenBao-backed Signer.
	Signer sign.Signer

	// Attestor identifies the running attestor instance; recorded in the
	// in-toto Statement predicate. If empty Name is set, defaults are used.
	Attestor sign.AttestorMeta
}

// SetupReconcilers wires the three attestor reconcilers
// (SecurityEventBundle, EventResponseBundle, AttestationBundle) into the
// given controller-runtime manager.
//
// Call this from the attestor binary's main() before mgr.Start().
func SetupReconcilers(mgr ctrl.Manager, opts Options) error {
	if opts.Signer == nil {
		s, err := sign.NewEd25519Signer()
		if err != nil {
			return fmt.Errorf("default Ed25519 signer: %w", err)
		}
		opts.Signer = s
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
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		Signer:       opts.Signer,
		AttestorMeta: opts.Attestor,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup AttestationBundleReconciler: %w", err)
	}
	return nil
}
