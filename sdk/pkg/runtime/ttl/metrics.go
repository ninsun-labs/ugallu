// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package ttl

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Postpone reasons (label values) used by metricPostponed.
const (
	postponeReasonBundleNotSealed = "bundle_not_sealed"
	postponeReasonAnnotation      = "annotation"
	postponeReasonNotExpired      = "not_expired"
)

// Failure stages (label values) used by metricFailures.
const (
	failureStagePrecondition = "precondition"
	failureStageSnapshot     = "snapshot"
	failureStageDelete       = "delete"
	failureStageConfig       = "config"
)

// CR kind label values.
const (
	kindSE = "SecurityEvent"
	kindER = "EventResponse"
	kindAB = "AttestationBundle"
)

var (
	metricArchived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ugallu_ttl_archived_total",
			Help: "Number of CRs archived to WORM and deleted by the TTL controller.",
		},
		[]string{"kind", "severity"},
	)

	metricPostponed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ugallu_ttl_postponed_total",
			Help: "Number of TTL evaluations that postponed archiving (with reason).",
		},
		[]string{"kind", "reason"},
	)

	metricFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ugallu_ttl_failures_total",
			Help: "Number of TTL pipeline failures, grouped by stage.",
		},
		[]string{"kind", "stage"},
	)

	metricArchiveDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ugallu_ttl_archive_duration_seconds",
			Help:    "Duration of the snapshot+delete pipeline once preconditions are satisfied.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"kind"},
	)

	metricWatchdogUnavailable = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ugallu_ttl_attestor_unavailable",
			Help: "1 when the attestor Lease is currently considered stale, 0 otherwise.",
		},
		[]string{},
	)
)

func init() {
	crmetrics.Registry.MustRegister(
		metricArchived,
		metricPostponed,
		metricFailures,
		metricArchiveDuration,
		metricWatchdogUnavailable,
	)
}

// recordArchive bumps the archive counter and observes the elapsed time.
func recordArchive(kind, severity string, started time.Time) {
	metricArchived.WithLabelValues(kind, severity).Inc()
	metricArchiveDuration.WithLabelValues(kind).Observe(time.Since(started).Seconds())
}

// recordPostpone bumps the postpone counter for the given reason.
func recordPostpone(kind, reason string) {
	metricPostponed.WithLabelValues(kind, reason).Inc()
}

// recordFailure bumps the failure counter for the given pipeline stage.
func recordFailure(kind, stage string) {
	metricFailures.WithLabelValues(kind, stage).Inc()
}

// setWatchdogUnavailable updates the unavailable gauge (1=down, 0=up).
func setWatchdogUnavailable(down bool) {
	v := 0.0
	if down {
		v = 1.0
	}
	metricWatchdogUnavailable.WithLabelValues().Set(v)
}
