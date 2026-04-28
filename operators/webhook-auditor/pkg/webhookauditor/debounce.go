// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// debouncedEntry caches the last evaluation of a webhook configuration
// so cosmetic edits (label/annotation churn) do not re-emit. See
// design 21 §W6.
type debouncedEntry struct {
	score    int
	specHash string
	lastSeen time.Time
}

// debounceCache is a tiny in-memory LRU-ish map keyed on UID. No TTL
// expiry sweep — entries are evicted on Forget(uid) at delete time
// and on package shutdown. A 24h-cap is enforced via Touch.
type debounceCache struct {
	mu sync.Mutex
	m  map[types.UID]debouncedEntry
}

func newDebounceCache() *debounceCache {
	return &debounceCache{m: make(map[types.UID]debouncedEntry, 64)}
}

// Decide returns (emit bool, firstObserved bool). emit is true when
// the (score, specHash) tuple differs from the cached entry — first
// reconcile of a UID always emits. The cache is updated atomically.
func (c *debounceCache) Decide(uid types.UID, score int, specHash string) (emit, firstObserved bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, ok := c.m[uid]
	now := time.Now()
	if !ok {
		c.m[uid] = debouncedEntry{score: score, specHash: specHash, lastSeen: now}
		return true, true
	}
	if prev.score != score || prev.specHash != specHash {
		c.m[uid] = debouncedEntry{score: score, specHash: specHash, lastSeen: now}
		return true, false
	}
	// Touch lastSeen so a long-lived unchanged entry doesn't race a
	// future TTL sweep.
	prev.lastSeen = now
	c.m[uid] = prev
	return false, false
}

// Forget drops the cache entry for uid. Called on MWC/VWC delete.
func (c *debounceCache) Forget(uid types.UID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, uid)
}

// Hash returns the canonical sha256-hex of the JSON-marshalled value.
// Stable iff json.Marshal is stable for v's concrete type — true for
// admissionregistrationv1 webhook structs because they have no maps
// in user-visible spec fields.
func Hash(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
