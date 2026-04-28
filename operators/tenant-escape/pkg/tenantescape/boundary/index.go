// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package boundary holds the in-memory snapshot of the active
// TenantBoundary CRs that the detectors query through the
// detector.BoundarySet interface.
//
// The reconciler refreshes the snapshot on every Add/Update/Delete
// event. Snapshot reads are cheap (RWMutex.RLock) so each detector
// call hits a fresh, consistent view without coordinating with the
// reconciler.
package boundary

import (
	"strings"
	"sync"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// Index is the thread-safe BoundarySet implementation. The detector
// package consumes only the read methods exposed via
// detector.BoundarySet; the Refresh write path is private to the
// reconciler.
type Index struct {
	mu sync.RWMutex
	// nsToTenant maps an exact namespace name to the owning
	// TenantBoundary.Name (= tenant identity). Built from each CR's
	// Status.MatchedNamespaces (computed by the reconciler from
	// Spec.NamespaceSelector).
	nsToTenant map[string]string
	// hostPathPrefixes maps a HostPathPolicy.Allow entry to the
	// owning tenant. Lookup uses HasPrefix to resolve a Pod's
	// hostPath value against the longest-matching declared prefix.
	hostPathPrefixes map[string]string
	// saAllowlist[tenant][saUsername] = true.
	saAllowlist map[string]map[string]bool
	// trustedNamespaces[tenant][sourceNamespace] = true.
	trustedNamespaces map[string]map[string]bool
}

// NewIndex returns an empty index.
func NewIndex() *Index {
	return &Index{
		nsToTenant:        map[string]string{},
		hostPathPrefixes:  map[string]string{},
		saAllowlist:       map[string]map[string]bool{},
		trustedNamespaces: map[string]map[string]bool{},
	}
}

// Refresh rebuilds the index from the supplied list of TenantBoundary
// CRs. Atomic in the sense that detectors never observe a
// partially-built snapshot. Overlapping namespaces (the same
// namespace claimed by two CRs) resolve to the lexicographically
// first tenant name and are surfaced via the OverlappingNamespaces
// return value so the caller can emit a TenantBoundaryOverlap
// anomaly. Empty boundaries (no MatchedNamespaces) are surfaced via
// EmptyBoundaries so the caller can emit TenantBoundaryEmpty.
func (i *Index) Refresh(boundaries []securityv1alpha1.TenantBoundary) (overlapping, empty []string) {
	ns := map[string]string{}
	hp := map[string]string{}
	sa := map[string]map[string]bool{}
	tn := map[string]map[string]bool{}

	overlapSet := map[string]struct{}{}
	emptySet := []string{}

	for ix := range boundaries {
		b := &boundaries[ix]
		tenant := b.Name
		if tenant == "" {
			continue
		}
		if len(b.Status.MatchedNamespaces) == 0 {
			emptySet = append(emptySet, tenant)
		}
		for _, n := range b.Status.MatchedNamespaces {
			if existing, ok := ns[n]; ok && existing != tenant {
				overlapSet[n] = struct{}{}
				// Stable winner: lexicographic min.
				if tenant < existing {
					ns[n] = tenant
				}
				continue
			}
			ns[n] = tenant
		}
		for _, p := range b.Spec.HostPathPolicy.Allow {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			hp[p] = tenant
		}
		if len(b.Spec.ServiceAccountAllowlist) > 0 {
			sa[tenant] = map[string]bool{}
			for _, u := range b.Spec.ServiceAccountAllowlist {
				sa[tenant][u] = true
			}
		}
		if len(b.Spec.TrustedNamespaces) > 0 {
			tn[tenant] = map[string]bool{}
			for _, n := range b.Spec.TrustedNamespaces {
				tn[tenant][n] = true
			}
		}
	}

	overlapping = make([]string, 0, len(overlapSet))
	for n := range overlapSet {
		overlapping = append(overlapping, n)
	}

	i.mu.Lock()
	i.nsToTenant = ns
	i.hostPathPrefixes = hp
	i.saAllowlist = sa
	i.trustedNamespaces = tn
	i.mu.Unlock()

	return overlapping, emptySet
}

// TenantOf implements detector.BoundarySet.
func (i *Index) TenantOf(namespace string) string {
	if namespace == "" {
		return ""
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.nsToTenant[namespace]
}

// HostPathTenantOf implements detector.BoundarySet. Walks every
// declared prefix and returns the owning tenant of the
// longest-matching one (so overlapping prefixes "/var/lib/" and
// "/var/lib/team-a/" resolve to the more specific declaration).
func (i *Index) HostPathTenantOf(path string) string {
	if path == "" {
		return ""
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	bestPrefix := ""
	bestTenant := ""
	for prefix, tenant := range i.hostPathPrefixes {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		if len(prefix) > len(bestPrefix) {
			bestPrefix = prefix
			bestTenant = tenant
		}
	}
	return bestTenant
}

// SAAllowedFor implements detector.BoundarySet.
func (i *Index) SAAllowedFor(actorSA, targetTenant string) bool {
	if actorSA == "" || targetTenant == "" {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.saAllowlist[targetTenant][actorSA]
}

// NamespaceTrustedBy implements detector.BoundarySet.
func (i *Index) NamespaceTrustedBy(sourceNS, targetTenant string) bool {
	if sourceNS == "" || targetTenant == "" {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.trustedNamespaces[targetTenant][sourceNS]
}

// Tenants returns the sorted set of known tenant names. Used by
// status reporters and tests; not on the detector hot path.
func (i *Index) Tenants() []string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	seen := map[string]struct{}{}
	for _, t := range i.nsToTenant {
		seen[t] = struct{}{}
	}
	for t := range i.saAllowlist {
		seen[t] = struct{}{}
	}
	for t := range i.trustedNamespaces {
		seen[t] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	return out
}
