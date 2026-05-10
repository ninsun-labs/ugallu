// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package attestor provides controller-runtime reconcilers for the
// AttestationBundle pipeline.
//
// Three reconcilers wire together:
//
//   - SecurityEventBundleReconciler    SE (Active or unset phase) -> create Pending Bundle
//   - EventResponseBundleReconciler    ER (terminal phase)        -> create Pending Bundle
//   - AttestationBundleReconciler      Pending Bundle             -> Signed -> Logged -> Sealed,
//     then patch parent SE/ER
//     Status.Phase = Attested
//
// Real signing (Fulcio / OpenBao transit), Rekor logging, and WORM
// archival are pending. The current AttestationBundleReconciler
// promotes Pending bundles directly to Sealed with a digest derived
// from the parent CR JSON; the StatementDigest is a placeholder until
// the real in-toto Statement builder + Signer interface land.
//
// Wire all three into a controller-runtime manager via SetupReconcilers.
package attestor
