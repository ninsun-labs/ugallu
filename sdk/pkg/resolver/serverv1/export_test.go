// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1

import corev1 "k8s.io/api/core/v1"

// UpsertPodForTest exposes the unexported upsertPod entry point so
// the watch_test suite can drive cache mutations without taking a
// dependency on the informer machinery. Production code paths still
// reach upsertPod via the informer event handlers.
func (c *Cache) UpsertPodForTest(p *corev1.Pod) { c.upsertPod(p) }

// SubscriberCountForTest reports the current number of registered
// Watch subscribers. Used by the watch_test suite to rendezvous on
// the Server.Watch goroutine before driving cache mutations.
func (c *Cache) SubscriberCountForTest() int {
	c.subscribers.mu.RLock()
	defer c.subscribers.mu.RUnlock()
	return len(c.subscribers.entries)
}
