// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// Incident is the in-memory record of one capture in flight. The
// orchestrator builds it from the trigger SE + suspect Pod, runs
// the steps against it, and stamps the final IncidentCaptureCompleted
// SE off its evidence list.
type Incident struct {
	// UID is the deterministic incident identifier derived from the
	// trigger SE UID. Re-running the pipeline against the same SE
	// produces the same UID - so the snapshot S3 key, ephemeral
	// container name, and (Cilium)NetworkPolicy name all stay stable
	// across recovery attempts.
	UID string

	// TriggerSE is the SecurityEvent that opened the incident.
	TriggerSE *securityv1alpha1.SecurityEvent

	// SuspectPod points at the Pod the pipeline targets. Resolved
	// from TriggerSE.Spec.Subject (Kind=Pod).
	SuspectPod types.NamespacedName

	// SuspectPodUID is the live Pod UID at incident creation.
	// Snapshot binary names + NetworkPolicy names key off it.
	SuspectPodUID string

	// Evidence accumulates per-step ObjectRefs (snapshot blob, future
	// memory dump, future evidence manifest). The orchestrator drops
	// these into the final SE's spec.signals + spec.parents chain.
	Evidence []EvidenceEntry
}

// EvidenceEntry pairs the produced blob with its origin step.
type EvidenceEntry struct {
	Step      string
	URL       string
	SHA256    string
	Size      int64
	MediaType string
	Truncated bool
}

// NewIncident builds the in-memory state for a trigger SE. Returns
// nil when the SE does not name a Pod subject (the predicate filter
// already excludes those, but defense-in-depth).
func NewIncident(se *securityv1alpha1.SecurityEvent) *Incident {
	if se == nil || se.Spec.Subject.Kind != "Pod" {
		return nil
	}
	if se.Spec.Subject.Name == "" || se.Spec.Subject.Namespace == "" {
		return nil
	}
	return &Incident{
		UID:           deriveIncidentUID(se),
		TriggerSE:     se,
		SuspectPod:    types.NamespacedName{Namespace: se.Spec.Subject.Namespace, Name: se.Spec.Subject.Name},
		SuspectPodUID: string(se.Spec.Subject.UID),
	}
}

// AppendEvidence registers a step's output. Called by the
// orchestrator after each successful step.
func (i *Incident) AppendEvidence(step string, ref *EvidenceEntry) {
	ref.Step = step
	i.Evidence = append(i.Evidence, *ref)
}

// deriveIncidentUID hashes the trigger SE UID into a 16-byte
// fingerprint. Deterministic per-SE so re-runs converge on the same
// resource names. Hex output keeps the value DNS-1123 friendly for
// k8s names.
func deriveIncidentUID(se *securityv1alpha1.SecurityEvent) string {
	h := sha256.Sum256([]byte(string(se.UID)))
	return hex.EncodeToString(h[:8])
}

// Pod returns a corev1.Pod stub carrying just the metadata the
// freezer + snapshotter consume (name / namespace / UID). Callers
// that need the full spec (e.g. snapshot ephemeral-container
// injection) fetch the live Pod via the controller-runtime client.
func (i *Incident) Pod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: i.SuspectPod.Namespace,
			Name:      i.SuspectPod.Name,
			UID:       types.UID(i.SuspectPodUID),
		},
	}
}

// Validate enforces the incident invariants the pipeline expects.
// Called once after NewIncident before kicking the worker.
func (i *Incident) Validate() error {
	if i == nil {
		return fmt.Errorf("incident: nil")
	}
	if i.UID == "" {
		return fmt.Errorf("incident: UID is empty")
	}
	if i.TriggerSE == nil {
		return fmt.Errorf("incident: TriggerSE is nil")
	}
	if i.SuspectPod.Name == "" || i.SuspectPod.Namespace == "" {
		return fmt.Errorf("incident: SuspectPod is incomplete")
	}
	return nil
}
