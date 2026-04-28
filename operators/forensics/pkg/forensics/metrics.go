// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	pipelineIncidentsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_forensics_incidents_total",
		Help: "Forensic incidents by terminal outcome (started, completed, failed, emit_failed).",
	}, []string{"outcome"})

	pipelineStepsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_forensics_steps_total",
		Help: "Forensic pipeline step executions by step name and outcome.",
	}, []string{"step", "outcome"})

	pipelineQueueSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ugallu_forensics_queue_size",
		Help: "Trigger SE reconciles deferred because MaxConcurrentIncidents was reached.",
	})

	pipelineSkippedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_forensics_skipped_total",
		Help: "Trigger SEs the predicate filter skipped, by reason.",
	}, []string{"reason"})

	cniDetectFailuresTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ugallu_forensics_cni_detect_failures_total",
		Help: "Failed CNI backend detection probes.",
	})

	recoveryTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_forensics_recovery_total",
		Help: "Crash-recovery sweeps over Pending/Running ERs by outcome.",
	}, []string{"outcome"})

	autoUnfreezeTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_forensics_auto_unfreeze_total",
		Help: "Auto-unfreeze events fired by the timer-based reconciler.",
	}, []string{"outcome"})
)

func init() {
	metrics.Registry.MustRegister(
		pipelineIncidentsTotal,
		pipelineStepsTotal,
		pipelineQueueSize,
		pipelineSkippedTotal,
		cniDetectFailuresTotal,
		recoveryTotal,
		autoUnfreezeTotal,
	)
}
