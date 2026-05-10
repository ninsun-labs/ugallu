// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package serverv1 implements ugallu-resolver's gRPC server.
// It maintains client-go informer caches for Pod, Node,
// ServiceAccount, and Namespace, plus secondary indices on Pod IP /
// UID / containerID, and exposes the Resolver service from the v1
// proto contract over Unix socket and TCP.
//
// Phase 1 (this iteration) wires four of the six lookup RPCs:
//
//   - ResolveByPodIP        — secondary index podByIP
//   - ResolveByPodUID       — primary index podByUID
//   - ResolveByContainerID  — secondary index podByContainerID
//   - ResolveBySAUsername   intelligent parsing of K8s SA usernames
//
// ResolveByCgroupID and ResolveByPID are kept as Unresolved fallbacks
// in this phase; they require the eBPF cgroup tracker (Phase 3) and
// /proc walker (Phase 2) which land in follow-up commits. Watch is
// also a Phase 4 deferral.
//
// Cache invalidation uses a tombstone GC (60s grace):
// late events from detection sources can still resolve to the
// last-known snapshot with `tombstone=true` set; entries are purged
// once the grace window elapses.
package serverv1
