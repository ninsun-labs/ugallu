// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Resolve outcome label values used by metricResolveTotal.
const (
	outcomeHit        = "hit"
	outcomeMiss       = "miss"
	outcomeTombstone  = "tombstone"
	outcomePartial    = "partial"
	outcomeUnresolved = "unresolved"
	outcomeError      = "error"
)

// Resolver method label values.
const (
	methodPodIP       = "pod_ip"
	methodPodUID      = "pod_uid"
	methodContainerID = "container_id"
	methodSAUsername  = "sa_username"
	methodCgroupID    = "cgroup_id"
	methodPID         = "pid"
)

var (
	metricResolveTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ugallu_resolver_resolve_total",
			Help: "Number of resolve calls grouped by method and outcome.",
		},
		[]string{"method", "outcome"},
	)

	metricResolveDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ugallu_resolver_resolve_duration_seconds",
			Help:    "Latency of resolve calls.",
			Buckets: prometheus.ExponentialBuckets(50e-6, 4, 8),
		},
		[]string{"method"},
	)

	metricIndexSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ugallu_resolver_index_size",
			Help: "Current size of resolver indices (pods, ips, containers).",
		},
		[]string{"index"},
	)

	metricTombstonePurged = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ugallu_resolver_tombstone_purged_total",
			Help: "Number of tombstoned Pod entries purged after grace.",
		},
	)

	metricEbpfEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ugallu_resolver_ebpf_events_total",
			Help: "Number of cgroup tracepoint events seen by the eBPF tracker.",
		},
		[]string{"op", "outcome"},
	)

	metricEbpfDrops = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ugallu_resolver_ebpf_drops_total",
			Help: "Number of eBPF events dropped before reaching the cache (decode/short-record/etc.).",
		},
		[]string{"reason"},
	)
)

// Registerer is the Prometheus registerer the resolver writes to.
// main.go can substitute crmetrics.Registry or a private registry; a
// nil value falls back to the global prometheus.DefaultRegisterer.
var Registerer prometheus.Registerer = prometheus.DefaultRegisterer

// MustRegisterMetrics registers all serverv1 metrics with the
// configured Registerer. Idempotent: an AlreadyRegisteredError is
// swallowed so callers can call this from both library bootstrap and
// dedicated test setup without panic.
func MustRegisterMetrics() {
	for _, c := range []prometheus.Collector{
		metricResolveTotal,
		metricResolveDuration,
		metricIndexSize,
		metricTombstonePurged,
		metricEbpfEvents,
		metricEbpfDrops,
	} {
		if err := Registerer.Register(c); err != nil {
			if _, dup := err.(prometheus.AlreadyRegisteredError); !dup {
				panic(err)
			}
		}
	}
}

func recordResolve(method, outcome string, started time.Time) {
	metricResolveTotal.WithLabelValues(method, outcome).Inc()
	metricResolveDuration.WithLabelValues(method).Observe(time.Since(started).Seconds())
}

func updateIndexSizes(c *Cache) {
	pods, ips, containers := c.Sizes()
	metricIndexSize.WithLabelValues("pods").Set(float64(pods))
	metricIndexSize.WithLabelValues("ips").Set(float64(ips))
	metricIndexSize.WithLabelValues("containers").Set(float64(containers))
}

func updateCgroupIndexSize(c *Cache) {
	metricIndexSize.WithLabelValues("cgroups").Set(float64(c.CgroupSizes()))
}
