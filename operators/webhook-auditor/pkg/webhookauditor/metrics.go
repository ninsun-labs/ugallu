// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Telemetry contract for the webhook-auditor.
var (
	scoreEmitTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_webhook_score_total",
		Help: "SE emissions by Type and Severity (incl. sub-score SEs).",
	}, []string{"type", "severity"})

	evalTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ugallu_webhook_eval_total",
		Help: "Webhook configurations evaluated (post-debounce).",
	})

	evalSkippedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_webhook_eval_skipped_total",
		Help: "Evaluations skipped, by reason (ignored, debounced, missing_secret).",
	}, []string{"reason"})

	dropTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_webhook_drop_total",
		Help: "SE emissions dropped, by reason (ratelimit).",
	}, []string{"reason"})

	scoreDistribution = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ugallu_webhook_score_distribution",
		Help:    "Distribution of risk scores (post-evaluation).",
		Buckets: []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
	})

	observedCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ugallu_webhook_observed_count",
		Help: "Total MWC + VWC count seen at the most recent reconcile.",
	})

	evalTimeoutsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ugallu_webhook_eval_timeouts_total",
		Help: "Evaluator timeouts (per-MWC budget exceeded).",
	})

	caResolveFallbackTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_webhook_ca_resolve_fallback_total",
		Help: "Indirect caBundle resolution fell back to empty bytes, by reason (annotation_parse_error, namespace_forbidden, resolve_error, resolver_disabled).",
	}, []string{"reason"})
)

func init() {
	metrics.Registry.MustRegister(
		scoreEmitTotal,
		evalTotal,
		evalSkippedTotal,
		dropTotal,
		scoreDistribution,
		observedCount,
		evalTimeoutsTotal,
		caResolveFallbackTotal,
	)
}
