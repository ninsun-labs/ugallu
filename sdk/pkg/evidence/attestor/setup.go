// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
)

// SetupReconcilers wires the three attestor reconcilers
// (SecurityEventBundle, EventResponseBundle, AttestationBundle) into the
// given controller-runtime manager.
//
// Call this from the attestor binary's main() before mgr.Start().
func SetupReconcilers(mgr ctrl.Manager) error {
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
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup AttestationBundleReconciler: %w", err)
	}
	return nil
}
