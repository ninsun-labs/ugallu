// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

// DefaultTombstoneGrace is how long a deleted Pod's snapshot survives
// in the secondary indices so late detection events can still resolve
// to the last-known subject (design 03).
const DefaultTombstoneGrace = 60 * time.Second

// PodSnapshot carries everything we keep about a Pod for resolver
// lookups: the raw corev1.Pod (read-only) plus tombstone metadata.
//
// Pod is a pointer to the object stored in the informer cache. It
// MUST NOT be mutated; downstream callers receive the snapshot via
// Subject builders that produce fresh copies.
type PodSnapshot struct {
	Pod       *corev1.Pod
	Tombstone bool
	DeletedAt time.Time
}

// Cache holds the resolver's secondary indices on top of client-go
// informer caches. The struct is safe for concurrent use; the Get*
// methods take an RLock and return a snapshot pointer (callers should
// treat it as immutable).
type Cache struct {
	mu               sync.RWMutex
	podByUID         map[types.UID]*PodSnapshot
	podByIP          map[string]types.UID
	podByContainerID map[string]types.UID

	// SaLister and NodeLister are populated by the informer factory.
	// They are exported so the gRPC server can do direct ns/name
	// lookups against the standard client-go listers without us
	// duplicating their indices.
	SaLister   corev1listers.ServiceAccountLister
	NodeLister corev1listers.NodeLister

	tombstoneGrace time.Duration
}

// NewCache returns an empty Cache. Indices are populated by the
// informer event handlers wired in informers.go.
func NewCache(tombstoneGrace time.Duration) *Cache {
	if tombstoneGrace <= 0 {
		tombstoneGrace = DefaultTombstoneGrace
	}
	return &Cache{
		podByUID:         make(map[types.UID]*PodSnapshot),
		podByIP:          make(map[string]types.UID),
		podByContainerID: make(map[string]types.UID),
		tombstoneGrace:   tombstoneGrace,
	}
}

// PodByUID returns the snapshot for uid (including tombstoned entries
// within the grace window) or (nil, false) when not present.
func (c *Cache) PodByUID(uid types.UID) (*PodSnapshot, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.podByUID[uid]
	return s, ok
}

// PodByIP returns the snapshot for the given pod IP (v4 or v6, in
// canonical string form). Tombstoned entries are returned as long as
// the grace window has not elapsed.
func (c *Cache) PodByIP(ip string) (*PodSnapshot, bool) {
	key, ok := normalizeIP(ip)
	if !ok {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	uid, ok := c.podByIP[key]
	if !ok {
		return nil, false
	}
	s, ok := c.podByUID[uid]
	return s, ok
}

// PodByContainerID returns the snapshot owning the given CRI container
// ID (e.g. "containerd://abc..."). The lookup also accepts the bare
// hex form (no scheme prefix); it is normalized internally.
func (c *Cache) PodByContainerID(id string) (*PodSnapshot, bool) {
	key := normalizeContainerID(id)
	if key == "" {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	uid, ok := c.podByContainerID[key]
	if !ok {
		return nil, false
	}
	s, ok := c.podByUID[uid]
	return s, ok
}

// upsertPod is called from the Add/Update event handlers. It refreshes
// the primary snapshot and reindexes secondary keys. Old IPs and
// container IDs that no longer appear in the new Pod are evicted.
func (c *Cache) upsertPod(p *corev1.Pod) {
	if p == nil || p.UID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if old, ok := c.podByUID[p.UID]; ok && old.Pod != nil {
		c.removeIPLocked(old.Pod, p.UID)
		c.removeContainerLocked(old.Pod, p.UID)
	}
	c.podByUID[p.UID] = &PodSnapshot{Pod: p}
	c.indexIPLocked(p)
	c.indexContainerLocked(p)
}

// markTombstoneLocked transitions an entry to the tombstoned state.
// Caller must hold the write lock.
func (c *Cache) markTombstoneLocked(uid types.UID, now time.Time) {
	if s, ok := c.podByUID[uid]; ok {
		s.Tombstone = true
		s.DeletedAt = now
	}
}

// MarkTombstone is the public entry point used by the informer DELETE
// handler.
func (c *Cache) MarkTombstone(uid types.UID, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.markTombstoneLocked(uid, now)
}

// PurgeExpired removes tombstoned entries whose grace window has
// elapsed. Returns the number purged for metrics.
func (c *Cache) PurgeExpired(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	purged := 0
	for uid, snap := range c.podByUID {
		if !snap.Tombstone {
			continue
		}
		if now.Sub(snap.DeletedAt) < c.tombstoneGrace {
			continue
		}
		c.removeIPLocked(snap.Pod, uid)
		c.removeContainerLocked(snap.Pod, uid)
		delete(c.podByUID, uid)
		purged++
	}
	return purged
}

// Sizes returns current index sizes for metrics.
func (c *Cache) Sizes() (pods, ips, containers int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.podByUID), len(c.podByIP), len(c.podByContainerID)
}

func (c *Cache) indexIPLocked(p *corev1.Pod) {
	for _, pip := range allPodIPs(p) {
		key, ok := normalizeIP(pip)
		if !ok {
			continue
		}
		c.podByIP[key] = p.UID
	}
}

func (c *Cache) removeIPLocked(p *corev1.Pod, owner types.UID) {
	if p == nil {
		return
	}
	for _, pip := range allPodIPs(p) {
		key, ok := normalizeIP(pip)
		if !ok {
			continue
		}
		if cur, exists := c.podByIP[key]; exists && cur == owner {
			delete(c.podByIP, key)
		}
	}
}

func (c *Cache) indexContainerLocked(p *corev1.Pod) {
	for _, group := range [][]corev1.ContainerStatus{p.Status.ContainerStatuses, p.Status.InitContainerStatuses} {
		for i := range group {
			if id := normalizeContainerID(group[i].ContainerID); id != "" {
				c.podByContainerID[id] = p.UID
			}
		}
	}
}

func (c *Cache) removeContainerLocked(p *corev1.Pod, owner types.UID) {
	if p == nil {
		return
	}
	for _, group := range [][]corev1.ContainerStatus{p.Status.ContainerStatuses, p.Status.InitContainerStatuses} {
		for i := range group {
			id := normalizeContainerID(group[i].ContainerID)
			if id == "" {
				continue
			}
			if cur, exists := c.podByContainerID[id]; exists && cur == owner {
				delete(c.podByContainerID, id)
			}
		}
	}
}

// allPodIPs returns every PodIP recorded in status (covers dual-stack).
func allPodIPs(p *corev1.Pod) []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, 1+len(p.Status.PodIPs))
	if p.Status.PodIP != "" {
		out = append(out, p.Status.PodIP)
	}
	for _, ip := range p.Status.PodIPs {
		if ip.IP != "" {
			out = append(out, ip.IP)
		}
	}
	return out
}

// normalizeIP returns the canonical string form of a v4 or v6 address
// suitable as a map key. Empty / invalid inputs return ("", false).
func normalizeIP(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	addr := net.ParseIP(s)
	if addr == nil {
		return "", false
	}
	return addr.String(), true
}

// normalizeContainerID strips the CRI scheme prefix
// ("containerd://", "cri-o://", "docker://") and lowercases the hex.
// Empty input maps to empty output.
func normalizeContainerID(id string) string {
	if id == "" {
		return ""
	}
	if i := strings.Index(id, "://"); i >= 0 {
		id = id[i+3:]
	}
	return strings.ToLower(id)
}

// String returns a debug-only summary of cache sizes.
func (c *Cache) String() string {
	pods, ips, ctrs := c.Sizes()
	return fmt.Sprintf("Cache{pods=%d ips=%d containers=%d grace=%s}",
		pods, ips, ctrs, c.tombstoneGrace)
}
