// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package ttl

import (
	"context"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// DefaultTTLConfigNamespace is the namespace TTL reconcilers consult
// for the singleton TTLConfig CR.
const DefaultTTLConfigNamespace = "ugallu-system"

// effectiveTTLConfig wraps a (possibly nil) TTLConfigSpec and exposes
// helpers that fall back to baked-in defaults when the spec is
// unavailable. nil spec is the "TTLConfig missing" path.
type effectiveTTLConfig struct {
	spec *securityv1alpha1.TTLConfigSpec
}

// loadEffectiveTTLConfig fetches the TTLConfig singleton (preferring
// name="default") from the given namespace. Missing TTLConfig is not
// an error: the returned wrapper falls back to baked-in defaults.
func loadEffectiveTTLConfig(ctx context.Context, c client.Client, namespace string) (effectiveTTLConfig, error) {
	if namespace == "" {
		namespace = DefaultTTLConfigNamespace
	}
	list := &securityv1alpha1.TTLConfigList{}
	if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return effectiveTTLConfig{}, err
	}
	if len(list.Items) == 0 {
		return effectiveTTLConfig{}, nil
	}
	for i := range list.Items {
		if list.Items[i].Name == "default" {
			return effectiveTTLConfig{spec: &list.Items[i].Spec}, nil
		}
	}
	return effectiveTTLConfig{spec: &list.Items[0].Spec}, nil
}

// severityTTL returns the TTL for the given severity, honouring the
// loaded TTLConfig and falling back to baked-in defaults when
// either the config or the specific field is unset.
func (e effectiveTTLConfig) severityTTL(s securityv1alpha1.Severity) time.Duration {
	if e.spec == nil {
		return defaultSeverityTTL(s)
	}
	sev := e.spec.Defaults.SecurityEvent
	var d time.Duration
	switch s {
	case securityv1alpha1.SeverityCritical:
		d = sev.Critical.Duration
	case securityv1alpha1.SeverityHigh:
		d = sev.High.Duration
	case securityv1alpha1.SeverityMedium:
		d = sev.Medium.Duration
	case securityv1alpha1.SeverityLow:
		d = sev.Low.Duration
	case securityv1alpha1.SeverityInfo:
		d = sev.Info.Duration
	}
	if d <= 0 {
		return defaultSeverityTTL(s)
	}
	return d
}

// bundleGrace returns the AttestationBundle sealed-to-archive grace
// window from the loaded TTLConfig, falling back to defaultBundleGrace.
func (e effectiveTTLConfig) bundleGrace() time.Duration {
	if e.spec == nil {
		return defaultBundleGrace
	}
	g := e.spec.Defaults.AttestationBundle.Grace.Duration
	if g <= 0 {
		return defaultBundleGrace
	}
	return g
}

// DefaultWorkerPoolSize is the per-reconciler concurrency used when
// neither a CLI flag nor the TTLConfig CR provides a value. Picked
// conservatively to keep small clusters quiet while still providing
// headroom over the controller-runtime default of 1.
const DefaultWorkerPoolSize = 4

// workerPoolSize returns the per-reconciler MaxConcurrentReconciles
// from the loaded TTLConfig, falling back to DefaultWorkerPoolSize
// when missing. Values <= 0 are treated as "unset".
func (e effectiveTTLConfig) workerPoolSize() int {
	if e.spec == nil {
		return DefaultWorkerPoolSize
	}
	if e.spec.Worker.PoolSize <= 0 {
		return DefaultWorkerPoolSize
	}
	return e.spec.Worker.PoolSize
}

// queueQPS returns the workqueue token-bucket fill rate (events/sec)
// when configured, or 0 to mean "no global throttle" (controller-
// runtime falls back to the per-item exponential backoff).
func (e effectiveTTLConfig) queueQPS() float64 {
	if e.spec == nil || e.spec.Worker.QueueRateLimit == nil {
		return 0
	}
	v, ok := e.spec.Worker.QueueRateLimit.AsInt64()
	if !ok || v <= 0 {
		return 0
	}
	return float64(v)
}
