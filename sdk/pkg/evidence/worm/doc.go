// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package worm abstracts WORM (write-once-read-many) storage of
// evidence blobs (design 07).
//
// Current implementations:
//   - StubUploader   filesystem-backed; dev/test default.
//   - S3Uploader     (next iteration) S3-compatible (SeaweedFS / AWS S3
//     / RustFS) via aws-sdk-go-v2 with Object Lock in
//     Compliance mode.
//
// The Uploader is invoked by AttestationBundleReconciler (and, in the
// future, by detection sources for Tier-2 subject snapshots and by
// forensics for fs/mem snapshots) to persist blobs whose retention is
// driven by the parent bundle TTL plus a configurable grace.
package worm
