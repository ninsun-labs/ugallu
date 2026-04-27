// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1_test

import (
	"context"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"google.golang.org/grpc/metadata"

	resolverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/clientv1"
	serverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/serverv1"
)

// fakeWatchStream implements resolverv1.Resolver_WatchServer in-memory
// so tests can drive Server.Watch without spinning up a gRPC
// transport.
type fakeWatchStream struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	events []*resolverv1.SubjectChange
}

func newFakeWatchStream(parent context.Context) *fakeWatchStream {
	ctx, cancel := context.WithCancel(parent)
	return &fakeWatchStream{ctx: ctx, cancel: cancel}
}

func (s *fakeWatchStream) Send(change *resolverv1.SubjectChange) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, change)
	return nil
}

func (s *fakeWatchStream) snapshot() []*resolverv1.SubjectChange {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*resolverv1.SubjectChange, len(s.events))
	copy(out, s.events)
	return out
}

// gRPC ServerStream methods that this fake does not exercise — they
// return zero values.
func (s *fakeWatchStream) SetHeader(metadata.MD) error  { return nil }
func (s *fakeWatchStream) SendHeader(metadata.MD) error { return nil }
func (s *fakeWatchStream) SetTrailer(metadata.MD)       {}
func (s *fakeWatchStream) Context() context.Context     { return s.ctx }
func (s *fakeWatchStream) SendMsg(_ any) error          { return nil }
func (s *fakeWatchStream) RecvMsg(_ any) error          { return nil }

// awaitChanges polls until n events have arrived or timeout fires.
func awaitChanges(t *testing.T, s *fakeWatchStream, n int, timeout time.Duration) []*resolverv1.SubjectChange {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := s.snapshot(); len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d events; got %d: %+v", n, len(s.snapshot()), s.snapshot())
	return nil
}

// drainOverflow polls until either the overflow flag flips or the
// deadline lapses. Returns whether overflow was observed.
func drainOverflow(s *serverv1.Subscription, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.Overflowed() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// TestCacheSubscribe_AddDeletePurge exercises the cache fanout
// directly — the server-side gRPC layer is covered separately so this
// test can drive cache mutations without racing the gRPC subscription.
func TestCacheSubscribe_AddDeletePurge(t *testing.T) {
	srv := bootstrap(t)
	sub := srv.Cache.Subscribe(serverv1.Filter{}, 16)
	defer sub.Close()

	pod := fixturePod()
	srv.Cache.UpsertPodForTest(pod)
	srv.Cache.MarkTombstone(types.UID(pod.UID), time.Now())

	// ADDED + DELETED on the same channel — drain in order.
	got := drainEvents(t, sub, 2, time.Second)
	if got[0].Type != serverv1.ChangeAdded {
		t.Errorf("first event = %v, want ADDED", got[0].Type)
	}
	if got[1].Type != serverv1.ChangeDeleted {
		t.Errorf("second event = %v, want DELETED", got[1].Type)
	}
	if !got[1].Snapshot.Tombstone {
		t.Error("DELETED snapshot must be tombstoned")
	}

	// Wait past grace + GC tick (bootstrap uses 2s grace + 500ms tick).
	if purged := waitForPurge(srv.Cache); !purged {
		t.Fatal("tombstoned pod was not purged within budget")
	}
	got = drainEvents(t, sub, 1, time.Second)
	if got[0].Type != serverv1.ChangeTombstoneGC {
		t.Errorf("third event = %v, want TOMBSTONE_GC", got[0].Type)
	}
}

// TestCacheSubscribe_NamespaceFilter asserts the publisher honours
// the per-subscription namespace filter.
func TestCacheSubscribe_NamespaceFilter(t *testing.T) {
	srv := bootstrap(t)
	sub := srv.Cache.Subscribe(serverv1.Filter{Namespace: "kube-system"}, 16)
	defer sub.Close()

	srv.Cache.UpsertPodForTest(podInNamespace("default", "p-default"))
	srv.Cache.UpsertPodForTest(podInNamespace("kube-system", "p-system"))

	got := drainEvents(t, sub, 1, 500*time.Millisecond)
	if got[0].Snapshot.Pod.Namespace != "kube-system" {
		t.Errorf("got namespace %q, want kube-system", got[0].Snapshot.Pod.Namespace)
	}
	// No more events should arrive — give the publisher a beat to fan
	// out and re-check.
	time.Sleep(100 * time.Millisecond)
	if len(drainBufferedEvents(sub)) != 0 {
		t.Error("filter let a non-matching namespace through")
	}
}

// TestCacheSubscribe_OverflowClosesChannel demonstrates the slow-
// consumer story: tiny buffer + no readers => publisher gives up on
// the subscription and closes its channel.
func TestCacheSubscribe_OverflowClosesChannel(t *testing.T) {
	srv := bootstrap(t)
	sub := srv.Cache.Subscribe(serverv1.Filter{}, 1)
	defer sub.Close()

	// Three upserts with buffer=1 → second and third trip overflow.
	srv.Cache.UpsertPodForTest(podInNamespace("a", "one"))
	srv.Cache.UpsertPodForTest(podInNamespace("b", "two"))
	srv.Cache.UpsertPodForTest(podInNamespace("c", "three"))

	if !drainOverflow(sub, time.Second) {
		t.Fatal("expected overflow flag to flip")
	}
	// Channel must be closed.
	select {
	case _, ok := <-sub.Events():
		_ = ok
	case <-time.After(200 * time.Millisecond):
		t.Fatal("subscription channel was not closed after overflow")
	}
}

// TestServerWatch_ForwardsCacheChanges is the gRPC-layer
// integration: a subscription is established BEFORE the cache is
// mutated (the test waits for the goroutine to call Subscribe), then
// drives an UPSERT and asserts the stream observes a SubjectChange.
func TestServerWatch_ForwardsCacheChanges(t *testing.T) {
	srv := bootstrap(t)
	stream := newFakeWatchStream(context.Background())
	t.Cleanup(stream.cancel)

	// Drain whatever subscriber count is currently attached so the
	// rendezvous below isn't fooled by background bookkeeping.
	startSubs := srv.Cache.SubscriberCountForTest()

	done := make(chan error, 1)
	go func() {
		done <- srv.Watch(&resolverv1.WatchRequest{}, stream)
	}()

	// Wait until Server.Watch has called Cache.Subscribe.
	if !waitFor(func() bool { return srv.Cache.SubscriberCountForTest() > startSubs }, time.Second) {
		t.Fatal("Server.Watch never registered a subscription")
	}

	srv.Cache.UpsertPodForTest(fixturePod())
	got := awaitChanges(t, stream, 1, 500*time.Millisecond)
	if got[0].GetType() != resolverv1.SubjectChange_ADDED {
		t.Errorf("type = %v, want ADDED", got[0].GetType())
	}
	stream.cancel()
	<-done
}

// drainEvents drains exactly `n` events from sub.Events() (or fails).
func drainEvents(t *testing.T, sub *serverv1.Subscription, n int, timeout time.Duration) []serverv1.Change {
	t.Helper()
	out := make([]serverv1.Change, 0, n)
	deadline := time.After(timeout)
	for len(out) < n {
		select {
		case ch, ok := <-sub.Events():
			if !ok {
				t.Fatalf("channel closed early; got %d/%d", len(out), n)
			}
			out = append(out, ch)
		case <-deadline:
			t.Fatalf("timed out waiting for %d events; got %d", n, len(out))
		}
	}
	return out
}

// drainBufferedEvents non-blockingly returns any events currently
// queued on the subscription channel.
func drainBufferedEvents(sub *serverv1.Subscription) []serverv1.Change {
	out := []serverv1.Change{}
	for {
		select {
		case ch, ok := <-sub.Events():
			if !ok {
				return out
			}
			out = append(out, ch)
		default:
			return out
		}
	}
}

// waitFor polls cond until true or the deadline elapses.
func waitFor(cond func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// waitForPurge waits until the GC sweeps the tombstoned pod.
// `bootstrap` configures TombstoneGrace=2s, TombstoneInterval=500ms.
func waitForPurge(c *serverv1.Cache) bool {
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		pods, _, _ := c.Sizes()
		if pods == 0 {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// podInNamespace is a slim Pod fixture for namespace / overflow tests.
func podInNamespace(ns, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			UID:       types.UID(ns + "-" + name),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}
