// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package resolverv1

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	calls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_resolver_client_calls_total",
		Help: "Resolver client RPC outcomes, labelled by method and outcome (hit/miss/breaker_open/error).",
	}, []string{"method", "outcome"})

	dialFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_resolver_client_dial_failures_total",
		Help: "Resolver dial failures by transport (uds/tcp).",
	}, []string{"transport"})

	cacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ugallu_resolver_client_cache_size",
		Help: "Current size of the resolver client LRU.",
	})
)

func init() {
	metrics.Registry.MustRegister(calls, dialFailures, cacheSize)
}
