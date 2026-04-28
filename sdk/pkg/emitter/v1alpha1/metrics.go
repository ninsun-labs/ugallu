// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	emittedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_emitter_emitted_total",
		Help: "Number of SecurityEvents successfully published, labelled by class/type/severity.",
	}, []string{"class", "type", "severity"})

	droppedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_emitter_dropped_total",
		Help: "Number of SecurityEvents dropped, labelled by reason.",
	}, []string{"reason"})

	bufferDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ugallu_emitter_buffer_depth",
		Help: "Current depth of the retry buffer (0 == idle).",
	})

	enrichLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ugallu_emitter_enrich_latency_seconds",
		Help:    "Resolver-enrichment latency in seconds, labelled by EnrichVia + outcome.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2},
	}, []string{"enrich_via", "outcome"})
)

// init registers metrics on controller-runtime's shared registry so a
// hosting manager auto-exposes them on its /metrics endpoint.
func init() {
	metrics.Registry.MustRegister(emittedTotal, droppedTotal, bufferDepth, enrichLatency)
}
