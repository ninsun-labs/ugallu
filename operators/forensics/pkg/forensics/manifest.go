// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// ManifestSchemaVersion identifies the JSON shape callers will see.
// Bump on any backwards-incompatible change to Manifest.
const ManifestSchemaVersion = "ugallu.io/forensics-manifest/v1"

// ManifestMediaType is what the EvidenceUploadStep records on the
// resulting EvidenceRef + S3 ContentType so verifiers can route the
// blob through the correct decoder without sniffing.
const ManifestMediaType = "application/vnd.ugallu.forensics.manifest+json"

// Manifest is the per-incident audit document. It lists every
// evidence chunk the pipeline produced (snapshot blob today,
// memory dump in a future Phase 3) with sha256 + size +
// step-of-origin so a single signed reference is enough to walk the
// full incident. The IncidentCaptureCompleted SE references a
// manifest URL instead of inlining N chunks in spec.signals,
// keeping the SE small + the audit fully reconstructable.
type Manifest struct {
	Schema      string          `json:"schema"`
	IncidentUID string          `json:"incidentUid"`
	ClusterID   string          `json:"clusterId"`
	ClusterName string          `json:"clusterName,omitempty"`
	TriggerSE   TriggerRef      `json:"triggerSe"`
	Pod         ManifestPodRef  `json:"pod"`
	CreatedAt   time.Time       `json:"createdAt"`
	Chunks      []ManifestChunk `json:"chunks"`
}

// TriggerRef is the minimal handle on the SE that opened the
// incident — UID + Type so the manifest is self-describing.
type TriggerRef struct {
	UID  string `json:"uid"`
	Type string `json:"type"`
}

// ManifestPodRef carries the suspect Pod identity that the
// pipeline acted on.
type ManifestPodRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

// ManifestChunk captures one upstream EvidenceRef plus the step
// that produced it. The step label lets future verifiers replay
// the pipeline ordering without parsing ER labels.
type ManifestChunk struct {
	Step      string `json:"step"`
	MediaType string `json:"mediaType"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated,omitempty"`
}

// BuildManifest gathers chunks from the in-flight Incident +
// per-step EvidenceRefs into a Manifest. now is injectable for
// tests; production passes time.Now.
func BuildManifest(incident *Incident, pod *corev1.Pod, ci securityv1alpha1.ClusterIdentity, evidence []securityv1alpha1.EvidenceRef, stepFor func(securityv1alpha1.EvidenceRef) string, now time.Time) (*Manifest, error) {
	if incident == nil || pod == nil {
		return nil, errors.New("manifest: incident + pod required")
	}
	chunks := make([]ManifestChunk, 0, len(evidence))
	for i := range evidence {
		ev := &evidence[i]
		step := ""
		if stepFor != nil {
			step = stepFor(*ev)
		}
		chunks = append(chunks, ManifestChunk{
			Step:      step,
			MediaType: ev.MediaType,
			URL:       ev.URL,
			SHA256:    ev.SHA256,
			Size:      ev.Size,
		})
	}
	// Stable order — chunks come from a list that already reflects
	// step order, but sort defensively so a re-run with the same
	// inputs always produces the same canonical bytes.
	sort.SliceStable(chunks, func(i, j int) bool {
		if chunks[i].Step != chunks[j].Step {
			return chunks[i].Step < chunks[j].Step
		}
		return chunks[i].URL < chunks[j].URL
	})
	return &Manifest{
		Schema:      ManifestSchemaVersion,
		IncidentUID: incident.UID,
		ClusterID:   ci.ClusterID,
		ClusterName: ci.ClusterName,
		TriggerSE: TriggerRef{
			UID:  string(incident.TriggerSE.UID),
			Type: incident.TriggerSE.Spec.Type,
		},
		Pod: ManifestPodRef{
			Namespace: pod.Namespace,
			Name:      pod.Name,
			UID:       string(pod.UID),
		},
		CreatedAt: now.UTC(),
		Chunks:    chunks,
	}, nil
}

// CanonicalBytes returns the canonical JSON encoding of m: keys
// sorted alphabetically, no extraneous whitespace, no HTML escape.
// Two manifests with identical content always produce identical
// bytes — this is what makes the manifest content-addressable.
func (m *Manifest) CanonicalBytes() ([]byte, error) {
	if m == nil {
		return nil, errors.New("manifest: nil")
	}
	// json.Marshal sorts map keys but does HTML-escape and emits
	// pretty whitespace via Encoder.SetIndent. The canonical form
	// disables both via a manual Encoder.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("manifest encode: %w", err)
	}
	// Encoder.Encode trails a newline; trim for content-addressing
	// stability so the digest doesn't depend on the encoder quirk.
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}

// SHA256 returns the hex-encoded sha256 of the manifest's canonical
// bytes prefixed with "sha256:". Used both as the WORM object key
// suffix and as the EvidenceRef.SHA256 the SE references.
func (m *Manifest) SHA256() (digest string, body []byte, err error) {
	body, err = m.CanonicalBytes()
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), body, nil
}

// ObjectKey assembles the deterministic S3 key the
// EvidenceUploadStep writes the manifest under. Keying on the
// content sha makes re-uploads idempotent (If-None-Match: *) and
// proves the manifest hasn't been silently rewritten.
func (m *Manifest) ObjectKey() (key string, body []byte, digest string, err error) {
	digest, body, err = m.SHA256()
	if err != nil {
		return "", nil, "", err
	}
	// Strip the "sha256:" prefix for the URL-safe filename.
	hexDigest := digest[len("sha256:"):]
	return fmt.Sprintf("forensics/%s/manifest-%s.json", m.IncidentUID, hexDigest), body, digest, nil
}
