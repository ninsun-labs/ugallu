// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package logger abstracts the transparency log used by the attestor
// (Rekor in production, a stub in dev). Design 05 + 06.
//
// Current implementations:
//   - StubLogger     in-memory; returns synthetic log entries (dev/test).
//   - RekorLogger    (next iteration) HTTP client to Rekor v1 API.
//
// The Logger is invoked by AttestationBundleReconciler after signing,
// to publish the DSSE envelope to a transparency log. The result
// (LogEntry) is stored on the bundle's Status.RekorEntry and is used by
// verifiers to confirm inclusion via the log root.
package logger
