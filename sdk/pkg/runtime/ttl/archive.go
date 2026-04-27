// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package ttl

import (
	"bytes"
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/worm"
)

// Annotation keys recognised by the TTL controller (design 09 T8).
const (
	AnnotationTTL              = "ugallu.io/ttl"
	AnnotationTTLPostponeUntil = "ugallu.io/ttl-postpone-until"
	AnnotationTTLFrozen        = "ugallu.io/ttl-frozen"
	AnnotationTTLForce         = "ugallu.io/ttl-force"
	AnnotationTTLAttempts      = "ugallu.io/ttl-archive-attempts"
)

// SnapshotMediaType is the WORM mediaType for archived CR YAML.
const SnapshotMediaType = "application/vnd.k8s.cr+yaml"

// defaultSeverityTTL returns the design 09 T3 default TTL for a SE
// severity; unknown severities fall back to medium (24h).
func defaultSeverityTTL(s securityv1alpha1.Severity) time.Duration {
	switch s {
	case securityv1alpha1.SeverityCritical:
		return 7 * 24 * time.Hour
	case securityv1alpha1.SeverityHigh:
		return 72 * time.Hour
	case securityv1alpha1.SeverityMedium:
		return 24 * time.Hour
	case securityv1alpha1.SeverityLow:
		return 12 * time.Hour
	case securityv1alpha1.SeverityInfo:
		return 6 * time.Hour
	}
	return 24 * time.Hour
}

// defaultBundleGrace is the AttestationBundle retention beyond its
// parent CR (design 09 T3: parent TTL + 7d).
const defaultBundleGrace = 7 * 24 * time.Hour

// annotationOverrideTTL parses `ugallu.io/ttl: <duration>` if present.
// Returns (0, false) when absent or unparseable; the caller falls back
// to the default policy.
func annotationOverrideTTL(annos map[string]string) (time.Duration, bool) {
	v, ok := annos[AnnotationTTL]
	if !ok || v == "" {
		return 0, false
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}

// isFrozen reports whether `ugallu.io/ttl-frozen=true` is set.
func isFrozen(annos map[string]string) bool {
	return annos[AnnotationTTLFrozen] == "true"
}

// postponedUntil parses `ugallu.io/ttl-postpone-until: <RFC3339>`. The
// zero time is returned when the annotation is absent or unparseable.
func postponedUntil(annos map[string]string) time.Time {
	v, ok := annos[AnnotationTTLPostponeUntil]
	if !ok || v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// snapshotKey is the WORM object key for a CR snapshot. Layout per
// design 09 T2bis:
//
//	cr-snapshots/<clusterID>/<YYYY>/<MM>/<crUID>.yaml
//
// clusterID falls back to "unknown" when not set on the CR; the layout
// still validates and is rewritten when ClusterIdentity propagation
// lands.
func snapshotKey(clusterID, uid string, when time.Time) string {
	if clusterID == "" {
		clusterID = "unknown"
	}
	if uid == "" {
		uid = "no-uid"
	}
	return fmt.Sprintf("cr-snapshots/%s/%04d/%02d/%s.yaml",
		clusterID, when.Year(), int(when.Month()), uid)
}

// snapshotAndDelete uploads obj's YAML to WORM and then deletes the CR.
// Both operations are idempotent: a NotFound on Delete is swallowed,
// and the WORM put is keyed by UID so retries land at the same key.
func snapshotAndDelete(
	ctx context.Context,
	c client.Client,
	uploader worm.Uploader,
	obj client.Object,
	clusterID string,
	lockUntil time.Time,
) (*worm.ObjectRef, error) {
	if uploader == nil {
		return nil, fmt.Errorf("worm.Uploader is nil; call SetupReconcilers")
	}

	// Marshal as YAML for human auditor friendliness; sha256 is computed
	// inside the uploader.
	raw, err := yaml.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("marshal CR YAML: %w", err)
	}

	key := snapshotKey(clusterIDOrFallback(clusterID), string(obj.GetUID()), time.Now().UTC())
	ref, err := uploader.Put(ctx, key, bytes.NewReader(raw), worm.PutOpts{
		MediaType: SnapshotMediaType,
		LockUntil: lockUntil,
		Metadata: map[string]string{
			"kind": obj.GetObjectKind().GroupVersionKind().Kind,
			"name": obj.GetName(),
			"uid":  string(obj.GetUID()),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("WORM snapshot: %w", err)
	}

	if err := c.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
		return ref, fmt.Errorf("delete CR: %w", err)
	}
	return ref, nil
}

// clusterIDOrFallback returns clusterID, defaulting to "unknown" when
// empty so snapshot paths are always well-formed.
func clusterIDOrFallback(clusterID string) string {
	if clusterID == "" {
		return "unknown"
	}
	return clusterID
}

// bundleSealed reports whether the named AttestationBundle is in
// Phase=Sealed. NotFound returns (false, nil) so callers can postpone.
func bundleSealed(ctx context.Context, c client.Client, name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	b := &securityv1alpha1.AttestationBundle{}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, b); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return b.Status.Phase == securityv1alpha1.AttestationBundlePhaseSealed, nil
}

// timeOrCreated returns the supplied metav1.Time pointer when non-nil,
// or the resource's CreationTimestamp when not yet set. Used so a CR
// missing its post-attest timestamp still gets a deterministic anchor
// for TTL accounting.
func timeOrCreated(t *metav1.Time, created metav1.Time) time.Time {
	if t != nil && !t.IsZero() {
		return t.Time
	}
	return created.Time
}
