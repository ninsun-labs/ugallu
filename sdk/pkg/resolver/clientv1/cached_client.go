// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package resolverv1

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sony/gobreaker/v2"
	"google.golang.org/grpc"
)

// DefaultCacheSize is the LRU capacity used when CachedClientOpts
// leaves CacheSize unset.
const DefaultCacheSize = 5000

// DefaultCacheTTL is the per-entry positive-result lifetime in the LRU.
const DefaultCacheTTL = 5 * time.Minute

// DefaultUnresolvedTTL caps how long Unresolved/Tombstone entries stay
// cached. Short on purpose: a bad lookup is cheap to retry, but a
// long-cached miss hides a real recovery on the resolver side.
const DefaultUnresolvedTTL = 30 * time.Second

// CachedClientOpts configures CachedClient.
type CachedClientOpts struct {
	// Inner is the upstream stub (typically Dialer.Dial result).
	Inner ResolverClient

	// CacheSize defaults to DefaultCacheSize.
	CacheSize int

	// CacheTTL defaults to DefaultCacheTTL.
	CacheTTL time.Duration

	// UnresolvedTTL defaults to DefaultUnresolvedTTL.
	UnresolvedTTL time.Duration

	// BreakerSettings overrides the per-method gobreaker config.
	// Defaults: 5 consecutive failures → open, 30s open duration.
	BreakerSettings gobreaker.Settings
}

// CachedClient wraps a ResolverClient with a hash-bucketed LRU cache
// and a per-method circuit breaker. It implements the same gRPC stub
// interface so consumers (the emitter, the audit-detection enricher)
// can swap it in transparently.
type CachedClient struct {
	inner ResolverClient
	cache *lru.Cache[string, cacheEntry]

	cacheTTL      time.Duration
	unresolvedTTL time.Duration

	mu       sync.Mutex
	breakers map[string]*gobreaker.CircuitBreaker[*SubjectResponse]
	settings gobreaker.Settings
}

type cacheEntry struct {
	resp      *SubjectResponse
	expiresAt time.Time
}

// NewCachedClient validates opts and returns a wrapper.
func NewCachedClient(opts *CachedClientOpts) (*CachedClient, error) {
	if opts == nil || opts.Inner == nil {
		return nil, errors.New("resolver cached client: Inner is required")
	}
	if opts.CacheSize <= 0 {
		opts.CacheSize = DefaultCacheSize
	}
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = DefaultCacheTTL
	}
	if opts.UnresolvedTTL <= 0 {
		opts.UnresolvedTTL = DefaultUnresolvedTTL
	}
	if opts.BreakerSettings.Name == "" {
		opts.BreakerSettings = defaultBreakerSettings()
	}
	cache, err := lru.New[string, cacheEntry](opts.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("lru new: %w", err)
	}
	cacheSize.Set(0)
	return &CachedClient{
		inner:         opts.Inner,
		cache:         cache,
		cacheTTL:      opts.CacheTTL,
		unresolvedTTL: opts.UnresolvedTTL,
		breakers:      map[string]*gobreaker.CircuitBreaker[*SubjectResponse]{},
		settings:      opts.BreakerSettings,
	}, nil
}

// defaultBreakerSettings honours the design 20 §S2 numbers: 5
// consecutive failures trip the breaker, 30s open state duration.
func defaultBreakerSettings() gobreaker.Settings {
	return gobreaker.Settings{
		Name:        "resolver-default",
		MaxRequests: 1,
		Interval:    0,
		Timeout:     30 * time.Second,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 5
		},
	}
}

// breakerFor lazily constructs a per-method breaker so a single
// flaky RPC doesn't blackhole the others.
func (c *CachedClient) breakerFor(method string) *gobreaker.CircuitBreaker[*SubjectResponse] {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, ok := c.breakers[method]; ok {
		return b
	}
	cfg := c.settings
	cfg.Name = method
	b := gobreaker.NewCircuitBreaker[*SubjectResponse](cfg)
	c.breakers[method] = b
	return b
}

// call is the shared path for every ResolveBy* method.
func (c *CachedClient) call(ctx context.Context, method, key string, fn func(ctx context.Context) (*SubjectResponse, error)) (*SubjectResponse, error) {
	cacheKey := method + ":" + key
	if hit, ok := c.cache.Get(cacheKey); ok {
		if time.Now().Before(hit.expiresAt) {
			calls.WithLabelValues(method, "hit").Inc()
			return hit.resp, nil
		}
		c.cache.Remove(cacheKey)
	}
	br := c.breakerFor(method)
	resp, err := br.Execute(func() (*SubjectResponse, error) {
		return fn(ctx)
	})
	if err != nil {
		if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
			calls.WithLabelValues(method, "breaker_open").Inc()
		} else {
			calls.WithLabelValues(method, "error").Inc()
		}
		return nil, err
	}
	calls.WithLabelValues(method, "miss").Inc()
	if resp != nil {
		ttl := c.cacheTTL
		if resp.GetUnresolved() || resp.GetTombstone() {
			ttl = c.unresolvedTTL
		}
		c.cache.Add(cacheKey, cacheEntry{
			resp:      resp,
			expiresAt: time.Now().Add(ttl),
		})
		cacheSize.Set(float64(c.cache.Len()))
	}
	return resp, nil
}

// ResolveByPodIP forwards to the inner client through the cache.
func (c *CachedClient) ResolveByPodIP(ctx context.Context, in *PodIPRequest, opts ...grpc.CallOption) (*SubjectResponse, error) {
	return c.call(ctx, "ResolveByPodIP", in.GetIp(), func(ctx context.Context) (*SubjectResponse, error) {
		return c.inner.ResolveByPodIP(ctx, in, opts...)
	})
}

// ResolveByPodUID forwards to the inner client through the cache.
func (c *CachedClient) ResolveByPodUID(ctx context.Context, in *PodUIDRequest, opts ...grpc.CallOption) (*SubjectResponse, error) {
	return c.call(ctx, "ResolveByPodUID", in.GetUid(), func(ctx context.Context) (*SubjectResponse, error) {
		return c.inner.ResolveByPodUID(ctx, in, opts...)
	})
}

// ResolveByContainerID forwards to the inner client through the cache.
func (c *CachedClient) ResolveByContainerID(ctx context.Context, in *ContainerIDRequest, opts ...grpc.CallOption) (*SubjectResponse, error) {
	return c.call(ctx, "ResolveByContainerID", in.GetContainerId(), func(ctx context.Context) (*SubjectResponse, error) {
		return c.inner.ResolveByContainerID(ctx, in, opts...)
	})
}

// ResolveBySAUsername forwards to the inner client through the cache.
func (c *CachedClient) ResolveBySAUsername(ctx context.Context, in *SAUsernameRequest, opts ...grpc.CallOption) (*SubjectResponse, error) {
	return c.call(ctx, "ResolveBySAUsername", in.GetUsername(), func(ctx context.Context) (*SubjectResponse, error) {
		return c.inner.ResolveBySAUsername(ctx, in, opts...)
	})
}

// ResolveByCgroupID forwards to the inner client through the cache.
func (c *CachedClient) ResolveByCgroupID(ctx context.Context, in *CgroupIDRequest, opts ...grpc.CallOption) (*SubjectResponse, error) {
	return c.call(ctx, "ResolveByCgroupID", strconv.FormatUint(in.GetCgroupId(), 10), func(ctx context.Context) (*SubjectResponse, error) {
		return c.inner.ResolveByCgroupID(ctx, in, opts...)
	})
}

// ResolveByPID forwards to the inner client through the cache.
func (c *CachedClient) ResolveByPID(ctx context.Context, in *PIDRequest, opts ...grpc.CallOption) (*SubjectResponse, error) {
	return c.call(ctx, "ResolveByPID", strconv.FormatInt(int64(in.GetPid()), 10), func(ctx context.Context) (*SubjectResponse, error) {
		return c.inner.ResolveByPID(ctx, in, opts...)
	})
}

// Watch passes through directly: streaming responses are not cached
// (each event is unique by design). The breaker still wraps the call.
func (c *CachedClient) Watch(ctx context.Context, in *WatchRequest, opts ...grpc.CallOption) (Resolver_WatchClient, error) {
	return c.inner.Watch(ctx, in, opts...)
}

// Compile-time check that CachedClient satisfies the gRPC stub.
var _ ResolverClient = (*CachedClient)(nil)
