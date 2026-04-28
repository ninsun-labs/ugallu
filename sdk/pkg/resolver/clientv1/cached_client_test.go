// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package resolverv1_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sony/gobreaker/v2"
	"google.golang.org/grpc"

	resolverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/clientv1"
)

// flakyResolver returns failure for the first N calls, then success.
type flakyResolver struct {
	resolverv1.ResolverClient
	failsLeft atomic.Int32
	calls     atomic.Int32
	resp      *resolverv1.SubjectResponse
}

func (f *flakyResolver) ResolveByPodUID(_ context.Context, _ *resolverv1.PodUIDRequest, _ ...grpc.CallOption) (*resolverv1.SubjectResponse, error) {
	f.calls.Add(1)
	if f.failsLeft.Add(-1) >= 0 {
		return nil, errors.New("simulated failure")
	}
	return f.resp, nil
}

func (f *flakyResolver) ResolveByPodIP(_ context.Context, _ *resolverv1.PodIPRequest, _ ...grpc.CallOption) (*resolverv1.SubjectResponse, error) {
	f.calls.Add(1)
	return f.resp, nil
}

func mustCachedClient(t *testing.T, inner resolverv1.ResolverClient, breaker gobreaker.Settings) *resolverv1.CachedClient {
	t.Helper()
	c, err := resolverv1.NewCachedClient(&resolverv1.CachedClientOpts{
		Inner:           inner,
		CacheSize:       16,
		CacheTTL:        500 * time.Millisecond,
		UnresolvedTTL:   100 * time.Millisecond,
		BreakerSettings: breaker,
	})
	if err != nil {
		t.Fatalf("NewCachedClient: %v", err)
	}
	return c
}

func TestCachedClient_HitOnSecondCall(t *testing.T) {
	inner := &flakyResolver{
		resp: &resolverv1.SubjectResponse{Uid: "pod-uid-x"},
	}
	c := mustCachedClient(t, inner, gobreaker.Settings{Name: "x", Timeout: time.Hour, ReadyToTrip: func(_ gobreaker.Counts) bool { return false }})

	for i := 0; i < 5; i++ {
		resp, err := c.ResolveByPodUID(context.Background(), &resolverv1.PodUIDRequest{Uid: "pod-uid-x"})
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if resp.GetUid() != "pod-uid-x" {
			t.Errorf("uid = %q", resp.GetUid())
		}
	}
	// The cache should have served 4 of the 5; only one inner call.
	if got := inner.calls.Load(); got != 1 {
		t.Errorf("inner calls = %d, want 1 (rest must be cache hits)", got)
	}
}

func TestCachedClient_BreakerOpensAfterFailures(t *testing.T) {
	inner := &flakyResolver{}
	inner.failsLeft.Store(100) // always fail

	c := mustCachedClient(t, inner, gobreaker.Settings{
		Name:        "test",
		MaxRequests: 1,
		Timeout:     50 * time.Millisecond,
		ReadyToTrip: func(counts gobreaker.Counts) bool { return counts.ConsecutiveFailures >= 3 },
	})

	// Burn 3 failures to trip the breaker.
	for i := 0; i < 3; i++ {
		if _, err := c.ResolveByPodUID(context.Background(), &resolverv1.PodUIDRequest{Uid: "x"}); err == nil {
			t.Fatalf("call %d: expected error", i)
		}
	}
	// 4th call should hit gobreaker.ErrOpenState without calling
	// inner.
	innerBefore := inner.calls.Load()
	if _, err := c.ResolveByPodUID(context.Background(), &resolverv1.PodUIDRequest{Uid: "x"}); !errors.Is(err, gobreaker.ErrOpenState) {
		t.Errorf("expected ErrOpenState, got %v", err)
	}
	if got := inner.calls.Load(); got != innerBefore {
		t.Errorf("inner calls increased while breaker open: %d -> %d", innerBefore, got)
	}
}

func TestCachedClient_UnresolvedShortTTL(t *testing.T) {
	inner := &flakyResolver{
		resp: &resolverv1.SubjectResponse{Unresolved: true},
	}
	c := mustCachedClient(t, inner, gobreaker.Settings{Name: "x", Timeout: time.Hour, ReadyToTrip: func(_ gobreaker.Counts) bool { return false }})

	if _, err := c.ResolveByPodUID(context.Background(), &resolverv1.PodUIDRequest{Uid: "y"}); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Within unresolvedTTL (100ms): cache hit.
	if _, err := c.ResolveByPodUID(context.Background(), &resolverv1.PodUIDRequest{Uid: "y"}); err != nil {
		t.Fatalf("cached call: %v", err)
	}
	if got := inner.calls.Load(); got != 1 {
		t.Errorf("inner calls = %d, want 1 (cache hit expected)", got)
	}
	// After TTL: should miss again.
	time.Sleep(150 * time.Millisecond)
	if _, err := c.ResolveByPodUID(context.Background(), &resolverv1.PodUIDRequest{Uid: "y"}); err != nil {
		t.Fatalf("post-ttl call: %v", err)
	}
	if got := inner.calls.Load(); got != 2 {
		t.Errorf("inner calls = %d, want 2 (TTL should have expired)", got)
	}
}

func TestCachedClient_PerMethodKeysAreIsolated(t *testing.T) {
	inner := &flakyResolver{
		resp: &resolverv1.SubjectResponse{Uid: "v1"},
	}
	c := mustCachedClient(t, inner, gobreaker.Settings{Name: "x", Timeout: time.Hour, ReadyToTrip: func(_ gobreaker.Counts) bool { return false }})

	_, _ = c.ResolveByPodUID(context.Background(), &resolverv1.PodUIDRequest{Uid: "shared"})
	_, _ = c.ResolveByPodIP(context.Background(), &resolverv1.PodIPRequest{Ip: "shared"})
	if got := inner.calls.Load(); got != 2 {
		t.Errorf("inner calls = %d, want 2 (different methods must not share cache key)", got)
	}
}

func TestNewCachedClient_RejectsNilInner(t *testing.T) {
	if _, err := resolverv1.NewCachedClient(nil); err == nil {
		t.Error("expected error for nil opts")
	}
	if _, err := resolverv1.NewCachedClient(&resolverv1.CachedClientOpts{}); err == nil {
		t.Error("expected error for nil Inner")
	}
}
