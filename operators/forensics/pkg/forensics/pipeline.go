// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// PipelineOptions configures the orchestrator.
type PipelineOptions struct {
	Client      client.Client
	Emitter     *emitterv1alpha1.Emitter
	Freezer     *Freezer
	Snapshotter *Snapshotter

	// CredentialsMirror copies the WORM Secret into the suspect
	// Pod's namespace so the ephemeral container can read it via
	// secretKeyRef. nil disables the copy (useful in tests).
	CredentialsMirror *CredentialsMirror

	// ClusterIdentity is stamped on every emitted SE.
	ClusterIdentity securityv1alpha1.ClusterIdentity

	// MaxConcurrent caps in-flight pipelines (default 5).
	MaxConcurrent int

	Log *slog.Logger

	// StepRunner runs each Step inside a per-step EventResponse
	// for IR-as-code attestation. Sprint 3 wires it; Sprint 2 ran
	// the freezer + snapshotter directly.
	StepRunner *StepRunner

	// EvidenceUploader writes the per-incident manifest to WORM
	// as the closing step of the pipeline. nil disables the step
	// (the completion SE then falls back to inlining evidence
	// signals — Sprint-2 behaviour, kept as escape hatch for
	// air-gapped deployments without S3).
	EvidenceUploader *EvidenceUploader
}

// Pipeline is the per-incident orchestrator. It owns a semaphore
// that bounds in-flight captures and a small worker pool that runs
// the per-incident step sequence (freeze → snapshot → emit completion
// SE) without blocking the SE reconciler's worker queue.
type Pipeline struct {
	opts PipelineOptions

	sem      chan struct{}
	inFlight atomic.Int64

	mu      sync.Mutex
	pending map[string]struct{}
}

// NewPipeline validates opts and returns a ready Pipeline.
func NewPipeline(opts *PipelineOptions) (*Pipeline, error) {
	if opts == nil || opts.Client == nil {
		return nil, errors.New("pipeline: Client is required")
	}
	if opts.Emitter == nil {
		return nil, errors.New("pipeline: Emitter is required")
	}
	if opts.Freezer == nil {
		return nil, errors.New("pipeline: Freezer is required")
	}
	if opts.Snapshotter == nil {
		return nil, errors.New("pipeline: Snapshotter is required")
	}
	if opts.StepRunner == nil {
		return nil, errors.New("pipeline: StepRunner is required")
	}
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = 5
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	return &Pipeline{
		opts:    *opts,
		sem:     make(chan struct{}, opts.MaxConcurrent),
		pending: map[string]struct{}{},
	}, nil
}

// InFlight reports the live concurrent-incident count for metrics +
// kubectl-side observability.
func (p *Pipeline) InFlight() int64 { return p.inFlight.Load() }

// Start kicks off the pipeline for incident in a background
// goroutine. Returns an error when the semaphore is full (the
// reconciler reschedules) or when the incident is already active.
func (p *Pipeline) Start(ctx context.Context, incident *Incident) error {
	if err := incident.Validate(); err != nil {
		return err
	}
	p.mu.Lock()
	if _, dup := p.pending[incident.UID]; dup {
		p.mu.Unlock()
		return fmt.Errorf("pipeline: incident %s already in flight", incident.UID)
	}
	select {
	case p.sem <- struct{}{}:
	default:
		p.mu.Unlock()
		return fmt.Errorf("pipeline: max concurrent incidents reached (%d)", cap(p.sem))
	}
	p.pending[incident.UID] = struct{}{}
	p.mu.Unlock()

	p.inFlight.Add(1)
	go p.run(ctx, incident)
	return nil
}

// run executes the per-incident step sequence. Each step's outcome
// is logged + any non-recoverable error emits a
// SE{Type=IncidentCaptureFailed} with the cause in signals.
func (p *Pipeline) run(ctx context.Context, incident *Incident) {
	defer func() {
		<-p.sem
		p.inFlight.Add(-1)
		p.mu.Lock()
		delete(p.pending, incident.UID)
		p.mu.Unlock()
	}()

	log := p.opts.Log.With(
		"incident", incident.UID,
		"pod", incident.SuspectPod.String(),
	)

	log.Info("incident capture started")
	pipelineIncidentsTotal.WithLabelValues("started").Inc()

	pod, err := p.fetchSuspectPod(ctx, incident)
	if err != nil {
		p.fail(ctx, incident, "fetch_suspect_pod", err)
		return
	}
	// Always update the incident's pod UID with the live value (the
	// trigger SE may have been emitted before the pod was created or
	// after a recreate).
	incident.SuspectPodUID = string(pod.UID)

	if p.opts.CredentialsMirror != nil {
		if mirrorErr := p.opts.CredentialsMirror.EnsureIn(ctx, pod.Namespace); mirrorErr != nil {
			p.fail(ctx, incident, "credentials_mirror", mirrorErr)
			return
		}
	}

	exec := &StepExecution{Incident: incident, Pod: pod}

	// Step 1 — PodFreeze. Sequential blocker for the next step
	// (the snapshot must run on an isolated Pod).
	if err := p.opts.StepRunner.Run(ctx, &PodFreezeStep{Freezer: p.opts.Freezer}, exec); err != nil {
		pipelineStepsTotal.WithLabelValues("pod_freeze", "error").Inc()
		p.fail(ctx, incident, "pod_freeze", err)
		return
	}
	pipelineStepsTotal.WithLabelValues("pod_freeze", "ok").Inc()
	p.emitForensicSE(ctx, securityv1alpha1.TypePodFrozen, securityv1alpha1.SeverityInfo, incident, pod, nil)

	// Step 2 — FilesystemSnapshot. Sequential after freeze; the
	// snapshot binary runs against a Pod with active isolation.
	cfg := p.activeSnapshotConfig(ctx)
	if err := p.opts.StepRunner.Run(ctx, &FilesystemSnapshotStep{
		Snapshotter: p.opts.Snapshotter,
		Config:      &cfg,
	}, exec); err != nil {
		pipelineStepsTotal.WithLabelValues("filesystem_snapshot", "error").Inc()
		p.fail(ctx, incident, "filesystem_snapshot", err)
		return
	}
	pipelineStepsTotal.WithLabelValues("filesystem_snapshot", "ok").Inc()
	for i := range exec.Evidence {
		incident.AppendEvidence("filesystem_snapshot", &EvidenceEntry{
			URL:       exec.Evidence[i].URL,
			SHA256:    exec.Evidence[i].SHA256,
			Size:      exec.Evidence[i].Size,
			MediaType: exec.Evidence[i].MediaType,
		})
	}

	// Step 3 — EvidenceUpload manifest. The pipeline-level
	// evidence list now contains the single manifest ref instead
	// of the prior per-chunk inlining; the completion SE
	// references the manifest as its sole evidence pointer.
	if p.opts.EvidenceUploader != nil {
		if err := p.opts.StepRunner.Run(ctx, &EvidenceUploadStep{
			Uploader:        p.opts.EvidenceUploader,
			ClusterIdentity: p.opts.ClusterIdentity,
		}, exec); err != nil {
			pipelineStepsTotal.WithLabelValues("evidence_upload", "error").Inc()
			p.fail(ctx, incident, "evidence_upload", err)
			return
		}
		pipelineStepsTotal.WithLabelValues("evidence_upload", "ok").Inc()
		// The manifest ref is the LAST entry the step appended.
		// Replace the per-chunk evidence list on the incident with
		// just the manifest reference — that's what the
		// completion SE points at.
		manifestRef := exec.Evidence[len(exec.Evidence)-1]
		incident.Evidence = []EvidenceEntry{{
			Step:      "evidence-upload",
			URL:       manifestRef.URL,
			SHA256:    manifestRef.SHA256,
			Size:      manifestRef.Size,
			MediaType: manifestRef.MediaType,
		}}
	}

	if err := p.emitCompletion(ctx, incident, pod); err != nil {
		log.Warn("emit completion SE", "err", err)
		pipelineIncidentsTotal.WithLabelValues("emit_failed").Inc()
		return
	}
	pipelineIncidentsTotal.WithLabelValues("completed").Inc()
	log.Info("incident capture completed", "evidence_count", len(incident.Evidence))
}

// fetchSuspectPod loads the live Pod referenced by the trigger SE.
// NotFound is fatal — the pipeline cannot freeze a vanished pod;
// the orchestrator emits IncidentCaptureFailed reason=target_deleted.
func (p *Pipeline) fetchSuspectPod(ctx context.Context, incident *Incident) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	if err := p.opts.Client.Get(ctx, incident.SuspectPod, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("pod %s vanished before capture started", incident.SuspectPod)
		}
		return nil, err
	}
	return pod, nil
}

// activeSnapshotConfig fetches the singleton ForensicsConfig and
// returns its SnapshotConfig with defaults filled in. A missing CR
// falls back to the safe Wave-2 defaults — the pipeline never
// crashes on a deleted config.
func (p *Pipeline) activeSnapshotConfig(ctx context.Context) securityv1alpha1.SnapshotConfig {
	cfg := &securityv1alpha1.ForensicsConfig{}
	if err := p.opts.Client.Get(ctx, client.ObjectKey{Name: DefaultForensicsConfigName}, cfg); err == nil {
		out := cfg.Spec.Snapshot
		if out.TimeoutSeconds == 0 {
			out.TimeoutSeconds = 300
		}
		return out
	}
	return securityv1alpha1.SnapshotConfig{
		FilesystemSnapshot: true,
		TimeoutSeconds:     300,
	}
}

// emitForensicSE publishes a Forensic-class SE with the supplied
// type. Used as a status beacon along the pipeline (PodFrozen,
// IncidentCaptureCompleted, IncidentCaptureFailed).
func (p *Pipeline) emitForensicSE(ctx context.Context, eventType string, sev securityv1alpha1.Severity, incident *Incident, pod *corev1.Pod, signals map[string]string) {
	if signals == nil {
		signals = map[string]string{}
	}
	signals["incident.uid"] = incident.UID
	signals["trigger.uid"] = string(incident.TriggerSE.UID)
	signals["trigger.type"] = incident.TriggerSE.Spec.Type
	signals["pod.uid"] = string(pod.UID)
	// CorrelationID intentionally left empty so the emitter SDK
	// auto-derives a per-(class,type,subjectUID,bucket) ID. Setting
	// it to incident.UID would collide every emit on this incident
	// onto the same deterministic SE.metadata.name (the SDK hashes
	// the correlation into the name), masking PodFrozen behind the
	// final completion SE. The incident.uid signal already wires
	// every forensic SE back to its owning capture.
	if _, err := p.opts.Emitter.Emit(ctx, &emitterv1alpha1.EmitOpts{
		Class:            "Forensic",
		Type:             eventType,
		Severity:         sev,
		SubjectKind:      "Pod",
		SubjectName:      pod.Name,
		SubjectNamespace: pod.Namespace,
		SubjectUID:       pod.UID,
		Signals:          signals,
		ClusterIdentity:  p.opts.ClusterIdentity,
	}); err != nil {
		p.opts.Log.Warn("emit forensic SE", "type", eventType, "err", err)
	}
}

// emitCompletion stamps the IncidentCaptureCompleted SE that closes
// the capture loop and lists every evidence URL the pipeline
// produced. The annotations carry the human-readable acknowledge
// hint; the operator picks up `ugallu.io/incident-acknowledged=true`
// in the unfreeze controller.
func (p *Pipeline) emitCompletion(ctx context.Context, incident *Incident, pod *corev1.Pod) error {
	signals := map[string]string{
		"evidence.count": fmt.Sprintf("%d", len(incident.Evidence)),
	}
	for i, e := range incident.Evidence {
		prefix := fmt.Sprintf("evidence.%d", i)
		signals[prefix+".step"] = e.Step
		signals[prefix+".url"] = e.URL
		signals[prefix+".sha256"] = e.SHA256
		signals[prefix+".size"] = fmt.Sprintf("%d", e.Size)
		if e.Truncated {
			signals[prefix+".truncated"] = "true"
		}
	}
	_, err := p.opts.Emitter.Emit(ctx, &emitterv1alpha1.EmitOpts{
		Class:            "Forensic",
		Type:             securityv1alpha1.TypeIncidentCaptureCompleted,
		Severity:         securityv1alpha1.SeverityHigh,
		SubjectKind:      "Pod",
		SubjectName:      pod.Name,
		SubjectNamespace: pod.Namespace,
		SubjectUID:       pod.UID,
		Signals:          signals,
		ClusterIdentity:  p.opts.ClusterIdentity,
		DetectedAt:       metav1.NewTime(time.Now()),
	})
	return err
}

// fail tears down whatever state the pipeline managed to install
// (label, network policy) and emits IncidentCaptureFailed with the
// cause string. Best-effort; per-step error logs already captured
// the detail.
func (p *Pipeline) fail(ctx context.Context, incident *Incident, step string, cause error) {
	pipelineIncidentsTotal.WithLabelValues("failed").Inc()
	pipelineStepsTotal.WithLabelValues(step, "error").Inc()
	p.opts.Log.Warn("incident capture failed", "incident", incident.UID, "step", step, "err", cause)

	signals := map[string]string{
		"incident.uid":    incident.UID,
		"failure.step":    step,
		"failure.message": cause.Error(),
	}
	pod := incident.Pod()
	if _, err := p.opts.Emitter.Emit(ctx, &emitterv1alpha1.EmitOpts{
		Class:            "Forensic",
		Type:             securityv1alpha1.TypeIncidentCaptureFailed,
		Severity:         securityv1alpha1.SeverityHigh,
		SubjectKind:      "Pod",
		SubjectName:      pod.Name,
		SubjectNamespace: pod.Namespace,
		SubjectUID:       pod.UID,
		Signals:          signals,
		ClusterIdentity:  p.opts.ClusterIdentity,
	}); err != nil {
		p.opts.Log.Warn("emit failure SE", "err", err)
	}
}

// CredentialsMirror copies the master WORM Secret into a suspect
// Pod's namespace so the ephemeral container can mount it via
// secretKeyRef (which is namespace-local). The alternative —
// inlining the credentials in the env vars of the ephemeral
// container spec — leaks the secret value into pod descriptions and
// audit logs.
type CredentialsMirror struct {
	Client     client.Client
	SourceName string
	SourceNS   string
	TargetName string
}

// EnsureIn copies the source Secret into ns under TargetName.
// Idempotent: existing Secrets keep their content; only missing
// targets are seeded.
func (m *CredentialsMirror) EnsureIn(ctx context.Context, ns string) error {
	if m == nil || m.Client == nil {
		return nil
	}
	if ns == m.SourceNS {
		return nil
	}
	src := &corev1.Secret{}
	if err := m.Client.Get(ctx, client.ObjectKey{Namespace: m.SourceNS, Name: m.SourceName}, src); err != nil {
		return fmt.Errorf("read source secret %s/%s: %w", m.SourceNS, m.SourceName, err)
	}
	dst := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.TargetName,
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": ManagedByValue,
			},
		},
		Type: src.Type,
		Data: src.Data,
	}
	if err := m.Client.Create(ctx, dst); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create mirror secret: %w", err)
	}
	return nil
}
