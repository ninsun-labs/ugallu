// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package index holds the in-memory snapshot of every materialised
// decoy. The detector queries it on every audit-bus event to
// distinguish honeypots from regular cluster state without
// round-tripping the apiserver.
package index

import (
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/types"
)

// Key uniquely identifies a decoy by (resource, namespace, name).
type Key struct {
	Resource  string // pluralised: "secrets" / "serviceaccounts"
	Namespace string
	Name      string
}

// Entry is one decoy's metadata as the detector sees it.
type Entry struct {
	Key
	UID            types.UID
	HoneypotConfig string // owning CR name
	AllowedActors  map[string]bool
	EmitOnRead     bool
}

// Index is the thread-safe decoy snapshot.
type Index struct {
	mu     sync.RWMutex
	byKey  map[Key]*Entry
	byUID  map[types.UID]*Entry
	actors map[string]map[string]bool // honeypotConfig → SA username → true
}

// New returns an empty index.
func New() *Index {
	return &Index{
		byKey:  map[Key]*Entry{},
		byUID:  map[types.UID]*Entry{},
		actors: map[string]map[string]bool{},
	}
}

// Set replaces the snapshot atomically with the supplied entry list.
// Used by the reconciler after a HoneypotConfig change.
func (i *Index) Set(entries []*Entry) {
	byKey := make(map[Key]*Entry, len(entries))
	byUID := make(map[types.UID]*Entry, len(entries))
	actors := map[string]map[string]bool{}
	for _, e := range entries {
		if e == nil || e.Resource == "" || e.Name == "" {
			continue
		}
		byKey[e.Key] = e
		if e.UID != "" {
			byUID[e.UID] = e
		}
		if len(e.AllowedActors) > 0 {
			actors[e.HoneypotConfig] = e.AllowedActors
		}
	}
	i.mu.Lock()
	i.byKey = byKey
	i.byUID = byUID
	i.actors = actors
	i.mu.Unlock()
}

// Lookup returns the entry matching the (resource, namespace, name)
// triple, or nil when the target is not a decoy.
func (i *Index) Lookup(resource, namespace, name string) *Entry {
	if name == "" {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.byKey[Key{Resource: strings.ToLower(resource), Namespace: namespace, Name: name}]
}

// LookupUID returns the entry whose materialised resource has the
// given UID. Used when the audit event carries `objectRef.uid` —
// more reliable than name-based matching when an actor races to
// recreate the same name.
func (i *Index) LookupUID(uid types.UID) *Entry {
	if uid == "" {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.byUID[uid]
}

// IsAllowedActor reports whether the SA username is on the
// HoneypotConfig's allowlist (e.g. backup operator). The detector
// skips firing for allowlisted accesses.
func (i *Index) IsAllowedActor(honeypotConfig, saUsername string) bool {
	if honeypotConfig == "" || saUsername == "" {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.actors[honeypotConfig][saUsername]
}

// Size returns the number of indexed decoys. Cheap read-side helper
// used by status reconciler + tests.
func (i *Index) Size() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.byKey)
}
