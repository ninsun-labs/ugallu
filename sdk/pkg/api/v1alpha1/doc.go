// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package v1alpha1 contains API Schema definitions for the security.ugallu.io
// v1alpha1 API group, the spine of the ugallu Kubernetes security platform.
//
// CRDs in this package:
//   - SecurityEvent          — primary detection/audit/forensic fact (cluster-scoped)
//   - EventResponse          — record of a responder action against a SecurityEvent
//   - AttestationBundle      — signed in-toto attestation of a SecurityEvent or EventResponse
//   - AttestorConfig         — runtime config for the attestor (signing mode, Rekor, OpenBao)
//   - WORMConfig             — runtime config for the WORM backend (S3 endpoint, retention)
//   - TTLConfig              — runtime config for the TTL controller (per-severity windows)
//   - GitOpsResponderConfig  — runtime config for the GitOps responder (multi-host providers)
//
// See the design vault (docs 01-18) for the locked architecture.
package v1alpha1
