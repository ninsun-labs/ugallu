// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package auditdetection

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	fileSourceLines = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ugallu_audit_file_lines_total",
		Help: "Audit-log lines successfully parsed by the file source.",
	})
	fileSourceParseErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ugallu_audit_file_parse_errors_total",
		Help: "Audit-log lines the file source could not unmarshal.",
	})

	webhookSourceLines = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ugallu_audit_webhook_events_total",
		Help: "Audit events accepted by the webhook source.",
	})
	webhookSourceParseErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ugallu_audit_webhook_parse_errors_total",
		Help: "Audit events the webhook source could not unmarshal.",
	})
	webhookSourceAuthFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ugallu_audit_webhook_auth_failures_total",
		Help: "Webhook source POSTs rejected because of bearer-token mismatch.",
	})
	webhookSourceBackpressure = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ugallu_audit_webhook_backpressure_total",
		Help: "Webhook source 503 responses returned because the events channel was full.",
	})
)

func init() {
	metrics.Registry.MustRegister(
		fileSourceLines,
		fileSourceParseErrors,
		webhookSourceLines,
		webhookSourceParseErrors,
		webhookSourceAuthFailures,
		webhookSourceBackpressure,
	)
}
