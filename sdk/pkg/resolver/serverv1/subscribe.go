// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1

import (
	"sync"
	"sync/atomic"
)

// ChangeType mirrors resolverv1.SubjectChange_ChangeType. We expose a
// package-local enum so the cache doesn't have to import the proto
// types.
type ChangeType int

// Change values match the proto-side ordering one-to-one.
const (
	ChangeUnknown     ChangeType = 0
	ChangeAdded       ChangeType = 1
	ChangeUpdated     ChangeType = 2
	ChangeDeleted     ChangeType = 3
	ChangeTombstoneGC ChangeType = 4
)

// Change is one event delivered to a subscriber. Snapshot is shared
// (read-only) with the cache; consumers must not mutate it. For
// DELETED / TOMBSTONE_GC the Snapshot still carries the last-known
// Pod so subscribers can build a final SubjectResponse with
// tombstone=true.
type Change struct {
	Type     ChangeType
	Snapshot *PodSnapshot
}

// Filter narrows what a subscriber receives. Empty strings match any
// value; today only Pod-kind events are produced so a non-empty
// non-"Pod" Kind filter simply yields nothing.
type Filter struct {
	Kind      string
	Namespace string
}

// DefaultSubscriberBuffer caps a subscriber's event channel. A slow
// consumer that lets it fill triggers a non-blocking drop semantics:
// the publisher closes the channel and the Server.Watch loop returns
// a Resource_Exhausted error so the gRPC client knows to reconnect.
const DefaultSubscriberBuffer = 256

// Subscription is the per-watcher handle returned by Cache.Subscribe.
// Callers must Close it when done — the cache holds the subscription
// in a list and drops it on Close.
type Subscription struct {
	id         uint64
	filter     Filter
	cache      *Cache
	ch         chan Change
	closed     atomic.Bool
	overflowed atomic.Bool
}

// Events returns the read-only event channel. The channel is closed
// when the subscription overflows or the caller calls Close.
func (s *Subscription) Events() <-chan Change { return s.ch }

// Overflowed reports whether the publisher gave up on this
// subscription because its buffer filled. The Server.Watch loop reads
// this to decide between an EOF (Close) and a streaming error.
func (s *Subscription) Overflowed() bool { return s.overflowed.Load() }

// Close detaches the subscription from the cache and closes the
// event channel. Idempotent.
func (s *Subscription) Close() {
	if s.closed.Swap(true) {
		return
	}
	s.cache.unsubscribe(s.id)
	close(s.ch)
}

// matches reports whether the change passes the subscription's filter.
func (s *Subscription) matches(_ Change) bool {
	// Today only Pod kinds flow through; namespace match is the only
	// runtime filter. Generic Kind dispatch lands when SA / Node
	// changes start emitting events.
	return true
}

// matchesFilter is the effective predicate used by the cache when
// fanning out — encapsulates filter.Kind / filter.Namespace checks.
func (s *Subscription) matchesFilter(snap *PodSnapshot) bool {
	if s.filter.Kind != "" && s.filter.Kind != "Pod" {
		return false
	}
	if s.filter.Namespace != "" && (snap == nil || snap.Pod == nil || snap.Pod.Namespace != s.filter.Namespace) {
		return false
	}
	return true
}

// --- Cache-side wiring ------------------------------------------------------

// subscribers holds the live subscriptions. Stored on Cache via the
// embedded subscriberRegistry; kept in a separate file to keep cache.go
// focused on the index logic.
type subscriberRegistry struct {
	mu      sync.RWMutex
	nextID  uint64
	entries map[uint64]*Subscription
}

func (r *subscriberRegistry) add(sub *Subscription) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[uint64]*Subscription)
	}
	r.nextID++
	sub.id = r.nextID
	r.entries[sub.id] = sub
}

func (r *subscriberRegistry) remove(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, id)
}

// snapshot copies the current subscribers slice for fan-out without
// holding the registry lock through downstream channel sends.
func (r *subscriberRegistry) snapshot() []*Subscription {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Subscription, 0, len(r.entries))
	for _, s := range r.entries {
		out = append(out, s)
	}
	return out
}

// Subscribe registers a new subscription with the given filter. buffer
// caps the per-subscription event channel; a value <=0 picks
// DefaultSubscriberBuffer. The caller must Close the subscription
// when finished.
func (c *Cache) Subscribe(filter Filter, buffer int) *Subscription {
	if buffer <= 0 {
		buffer = DefaultSubscriberBuffer
	}
	sub := &Subscription{
		filter: filter,
		cache:  c,
		ch:     make(chan Change, buffer),
	}
	c.subscribers.add(sub)
	return sub
}

func (c *Cache) unsubscribe(id uint64) { c.subscribers.remove(id) }

// publish fans out a Change to every subscriber whose filter matches.
// Non-blocking send — if a subscriber's buffer is full the publisher
// flags it as overflowed and closes its channel; the Watch loop
// surfaces this to the gRPC client.
func (c *Cache) publish(change Change) {
	subs := c.subscribers.snapshot()
	for _, sub := range subs {
		if sub.closed.Load() {
			continue
		}
		if !sub.matchesFilter(change.Snapshot) || !sub.matches(change) {
			continue
		}
		select {
		case sub.ch <- change:
		default:
			if sub.overflowed.CompareAndSwap(false, true) {
				sub.Close()
			}
		}
	}
}
