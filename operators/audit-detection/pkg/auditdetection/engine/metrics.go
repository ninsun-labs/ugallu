// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	ruleMatchesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_audit_rule_matches_total",
		Help: "SigmaRule matches per rule (pre rate-limit).",
	}, []string{"rule"})

	ruleDropsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_audit_rule_dropped_total",
		Help: "SigmaRule matches dropped by the per-rule token bucket.",
	}, []string{"rule"})

	ruleEmitErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_audit_rule_emit_errors_total",
		Help: "SecurityEvent emit failures per SigmaRule.",
	}, []string{"rule"})

	ruleCompileErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ugallu_audit_rule_compile_errors_total",
		Help: "SigmaRule reconcile attempts that failed to compile.",
	}, []string{"rule"})
)

func init() {
	metrics.Registry.MustRegister(
		ruleMatchesTotal,
		ruleDropsTotal,
		ruleEmitErrorsTotal,
		ruleCompileErrorsTotal,
	)
}
