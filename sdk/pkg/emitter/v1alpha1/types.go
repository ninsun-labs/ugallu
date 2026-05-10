// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// EnrichKey identifies which Resolver RPC the Emitter should call for
// Tier-1 hydration of the Subject. An empty value disables enrichment
// and the emitter ships the bare Subject built from EmitOpts.
type EnrichKey string

// EnrichKey constants mirror the resolver's RPC surface.
const (
	EnrichByCgroupID    EnrichKey = "cgroup_id"
	EnrichByPID         EnrichKey = "pid"
	EnrichByPodUID      EnrichKey = "pod_uid"
	EnrichByPodIP       EnrichKey = "pod_ip"
	EnrichByContainerID EnrichKey = "container_id"
	EnrichBySAUsername  EnrichKey = "sa_username"
)

// EmitOpts is the input shape for Emit. Every detection source builds
// one and hands it off; the Emitter validates, enriches, idempotency-
// hashes and publishes.
type EmitOpts struct {
	// Class is the SE classification (Anomaly / Detection / ...).
	Class securityv1alpha1.Class

	// Type MUST appear in the package-local catalog snapshot. Unknown
	// types fail fast with ErrInvalidType, before any API call.
	Type string

	// Severity drives the TTL bucket downstream.
	Severity securityv1alpha1.Severity

	// Subject identity — populated even when EnrichVia is set so the
	// Subject survives a resolver outage with partial=true.
	SubjectKind      securityv1alpha1.SubjectKind
	SubjectName      string
	SubjectUID       types.UID
	SubjectNamespace string

	// EnrichVia + EnrichKey trigger a single Resolver RPC. Empty
	// EnrichVia keeps the bare Subject from the fields above.
	EnrichVia EnrichKey
	EnrichKey string

	// Free-form signals attached to spec.signals.
	Signals map[string]string

	// Parents links to other SE/ER (multi-step incidents).
	Parents []corev1.ObjectReference

	// CorrelationID overrides the auto-derived value when non-empty.
	// Use it for cross-source dedup (e.g. tetragon + dns-detect see
	// the same event from different angles).
	CorrelationID string

	// ClusterIdentity is filled by the caller; the resolver doesn't
	// know the cluster name.
	ClusterIdentity securityv1alpha1.ClusterIdentity

	// DetectedAt is the wall-clock time the detection source
	// observed the underlying fact. Zero falls back to metav1.Now()
	// at emission, but real sources should pass the audit log
	// timestamp for accurate forensics.
	DetectedAt metav1.Time
}
