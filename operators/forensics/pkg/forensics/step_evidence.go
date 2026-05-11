// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/worm"
)

// EvidenceUploaderOptions configures EvidenceUploader. The
// uploader runs in the operator pod (not in the suspect Pod's
// namespace), so it talks to the WORM endpoint directly without
// going through the per-suspect freeze policy.
type EvidenceUploaderOptions struct {
	// Bucket / Endpoint / Region / UsePathStyle / AccessKey /
	// SecretKey mirror the snapshot binary's WORM args. Defaults
	// match the chart values for the lab.
	Bucket       string
	Endpoint     string
	Region       string
	UsePathStyle bool
	AccessKey    string
	SecretKey    string

	// LockMode + LockUntil set Object Lock retention on the
	// uploaded manifest. Defaults track the chart
	// (COMPLIANCE / 168h).
	LockMode  string
	LockUntil time.Duration
}

// EvidenceUploader writes the per-incident manifest blob to WORM.
// The blob is content-addressed (sha256 of canonical JSON) so
// re-uploads of the same content are no-ops; rewriting an existing
// key with different content triggers an Object-Lock-protected
// rejection.
type EvidenceUploader struct {
	uploader *worm.S3Uploader
	lockMode string
	lockTTL  time.Duration
}

// NewEvidenceUploader validates opts and initialises the underlying
// S3 client.
func NewEvidenceUploader(ctx context.Context, opts *EvidenceUploaderOptions) (*EvidenceUploader, error) {
	if opts == nil {
		return nil, errors.New("evidence uploader: opts required")
	}
	if opts.Bucket == "" {
		return nil, errors.New("evidence uploader: Bucket required")
	}
	if opts.LockMode == "" {
		opts.LockMode = "COMPLIANCE"
	}
	if opts.LockUntil <= 0 {
		opts.LockUntil = 168 * time.Hour
	}
	up, err := worm.NewS3Uploader(ctx, &worm.S3UploaderOptions{
		Bucket:         opts.Bucket,
		Region:         opts.Region,
		EndpointURL:    opts.Endpoint,
		UsePathStyle:   opts.UsePathStyle,
		AccessKey:      opts.AccessKey,
		SecretKey:      opts.SecretKey,
		ObjectLockMode: opts.LockMode,
	})
	if err != nil {
		return nil, fmt.Errorf("evidence uploader: build S3 client: %w", err)
	}
	return &EvidenceUploader{
		uploader: up,
		lockMode: opts.LockMode,
		lockTTL:  opts.LockUntil,
	}, nil
}

// Upload pushes m to WORM under m.ObjectKey(). The returned
// EvidenceRef is what the EvidenceUploadStep stamps on the ER
// status.evidence + the IncidentCaptureCompleted SE references as
// the single manifest pointer.
func (u *EvidenceUploader) Upload(ctx context.Context, m *Manifest) (*securityv1alpha1.EvidenceRef, error) {
	key, body, digest, err := m.ObjectKey()
	if err != nil {
		return nil, err
	}
	lockUntil := time.Time{}
	if !strings.EqualFold(u.lockMode, "NONE") {
		lockUntil = time.Now().Add(u.lockTTL).UTC()
	}
	ref, err := u.uploader.Put(ctx, key, bytes.NewReader(body), worm.PutOpts{
		LockUntil: lockUntil,
		MediaType: ManifestMediaType,
		Metadata: map[string]string{
			"incident-uid": m.IncidentUID,
			"schema":       m.Schema,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("evidence upload: %w", err)
	}
	// Sanity: the digest the uploader computed must match what the
	// canonical bytes hash to. Diverging here means somebody
	// rewrote the body between BuildManifest and Upload.
	if ref.SHA256 != digest {
		return nil, fmt.Errorf("evidence upload: digest mismatch (uploaded=%s, computed=%s)", ref.SHA256, digest)
	}
	return &securityv1alpha1.EvidenceRef{
		MediaType: ManifestMediaType,
		URL:       ref.URL,
		SHA256:    ref.SHA256,
		Size:      ref.Size,
	}, nil
}

// EvidenceUploadStep wraps EvidenceUploader inside the per-step ER
// chain. It is the LAST step in the pipeline and the only step
// whose Run() consumes the evidence the previous steps produced.
type EvidenceUploadStep struct {
	Uploader *EvidenceUploader

	// ClusterIdentity is stamped on the manifest body so verifiers
	// don't need a side channel to know which cluster produced
	// this evidence.
	ClusterIdentity securityv1alpha1.ClusterIdentity

	// Now is injectable for tests; production passes time.Now.
	Now func() time.Time
}

// Type returns the ER ActionType for this step.
func (s *EvidenceUploadStep) Type() securityv1alpha1.ActionType {
	return securityv1alpha1.ActionEvidenceUpload
}

// Run builds the canonical manifest from exec.Evidence + uploads
// it to WORM. The uploaded EvidenceRef is appended to exec.Evidence
// so the pipeline's emitCompletion() picks it up (and the
// completion SE references the manifest as its sole evidence ref).
func (s *EvidenceUploadStep) Run(ctx context.Context, exec *StepExecution) error {
	if s.Uploader == nil {
		return errors.New("evidence upload: Uploader is nil")
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	stepFor := func(ev securityv1alpha1.EvidenceRef) string {
		// EvidenceRefs added by FilesystemSnapshotStep carry the
		// "application/x-tar+gzip" MediaType - encode the step
		// name into the manifest chunk based on the MediaType so
		// future steps (mem-snapshot) drop in cleanly.
		switch ev.MediaType {
		case "application/x-tar+gzip":
			return "filesystem-snapshot"
		case ManifestMediaType:
			// Should never appear here - the manifest is built
			// before being added to evidence - guard against
			// recursive accidents.
			return "evidence-upload"
		default:
			return "unknown"
		}
	}
	m, err := BuildManifest(exec.Incident, exec.Pod, s.ClusterIdentity, exec.Evidence, stepFor, now())
	if err != nil {
		return err
	}
	ref, err := s.Uploader.Upload(ctx, m)
	if err != nil {
		return err
	}
	exec.Evidence = append(exec.Evidence, *ref)
	exec.Parameters["manifest.url"] = ref.URL
	exec.Parameters["manifest.sha256"] = ref.SHA256
	exec.Parameters["manifest.size"] = fmt.Sprintf("%d", ref.Size)
	exec.Parameters["manifest.chunks"] = fmt.Sprintf("%d", len(m.Chunks))
	return nil
}
