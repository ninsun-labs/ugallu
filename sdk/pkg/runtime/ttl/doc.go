// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package ttl implements the lifecycle GC for ugallu CRs.
//
// Three reconcilers, one per Kind, run in the ugallu-ttl Deployment
// (cluster-scoped, leader-elected):
//
//   - SecurityEventTTLReconciler      - archives + deletes SE at TTL
//   - EventResponseTTLReconciler      - archives + deletes ER at TTL
//   - AttestationBundleTTLReconciler  - archives + deletes AB at TTL+grace
//
// Each reconciler:
//  1. Computes the expiry from ObjectMeta.CreationTimestamp + the
//     TTL policy (severity-based for SE; parent-derived for ER/AB).
//  2. Honours `ugallu.io/ttl`, `ugallu.io/ttl-frozen`, and
//     `ugallu.io/ttl-postpone-until` annotations.
//  3. Checks preconditions (SE/ER require a Sealed parent
//     AttestationBundle; AB requires its own Phase=Sealed).
//  4. Snapshots the CR YAML to WORM via the injected worm.Uploader.
//  5. Deletes the CR via the K8s API (idempotent).
//
// TTLConfig CRD-driven configuration and the attestor watchdog land in
// the next iteration; severity-based defaults are baked in for now.
package ttl
