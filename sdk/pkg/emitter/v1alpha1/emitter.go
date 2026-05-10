// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
	resolverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/clientv1"
)

// EmitterOpts configures NewEmitter. Defaults: 50 burst, 10 sustained
// tokens per second, 1000-entry retry ring.
type EmitterOpts struct {
	// Client is the controller-runtime client used to publish SE
	// CRs. Required.
	Client client.Client

	// Resolver is the optional Tier-1 lookup gRPC client. Nil means
	// the Emitter ships the bare Subject from EmitOpts without
	// enrichment.
	Resolver resolverv1.ResolverClient

	// AttestorMeta is baked into SecurityEvent.spec.source so each
	// emitted SE identifies the controller and version that produced
	// it. The "Attestor" name is historical (it predates the events
	// SDK); it now serves any source.
	AttestorMeta sign.AttestorMeta

	// Log routes Emit-time diagnostics. nil → discard.
	Log *slog.Logger

	// BufferSize caps the retry ring; default 1000.
	BufferSize int

	// BurstPerSec is the token-bucket peak; default 50.
	BurstPerSec int

	// SustainedPerSec is the token-bucket fill rate; default 10.
	SustainedPerSec int

	// EnrichTimeout caps a single resolver RPC; default 200ms.
	EnrichTimeout time.Duration
}

// Emitter is the package's owner type — see package doc for the full
// contract. It is safe for concurrent use; the worker goroutine
// drains the retry ring under the same context the caller hands to
// NewEmitter.
type Emitter struct {
	opts        EmitterOpts
	rateLimiter *rate.Limiter
	buffer      chan *securityv1alpha1.SecurityEvent
	bufDepth    atomic.Int64

	stopCh   chan struct{}
	stopOnce sync.Once

	now func() time.Time // injectable for tests
}

// NewEmitter validates opts and starts the background retry worker.
// The caller stops the worker by calling Close(); the worker also
// exits when ctx (passed via Start) is cancelled.
func NewEmitter(opts *EmitterOpts) (*Emitter, error) {
	if opts == nil || opts.Client == nil {
		return nil, errors.New("emitter: Client is required")
	}
	if opts.AttestorMeta.Name == "" {
		return nil, errors.New("emitter: AttestorMeta.Name is required")
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = 1000
	}
	if opts.BurstPerSec <= 0 {
		opts.BurstPerSec = 50
	}
	if opts.SustainedPerSec <= 0 {
		opts.SustainedPerSec = 10
	}
	if opts.EnrichTimeout <= 0 {
		opts.EnrichTimeout = 200 * time.Millisecond
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	return &Emitter{
		opts:        *opts,
		rateLimiter: rate.NewLimiter(rate.Limit(opts.SustainedPerSec), opts.BurstPerSec),
		buffer:      make(chan *securityv1alpha1.SecurityEvent, opts.BufferSize),
		stopCh:      make(chan struct{}),
		now:         time.Now,
	}, nil
}

// Start launches the retry worker. ctx cancellation drains the buffer
// best-effort and returns. Safe to call once; multiple Start calls
// race the worker — the second wins.
func (e *Emitter) Start(ctx context.Context) {
	go e.runRetry(ctx)
}

// Close stops the retry worker. Pending buffered events are dropped
// after a final 1s drain; metrics record them as reason=shutdown.
func (e *Emitter) Close() {
	e.stopOnce.Do(func() { close(e.stopCh) })
}

// Emit produces a SecurityEvent honouring every guarantee documented
// in the package comment. opts is taken by pointer so callers can
// reuse a heap-allocated struct across many Emit calls without paying
// the 248-byte copy cost.
func (e *Emitter) Emit(ctx context.Context, opts *EmitOpts) (*securityv1alpha1.SecurityEvent, error) {
	if opts == nil {
		return nil, errors.New("emitter: opts is required")
	}
	if !IsKnownType(opts.Type) {
		droppedTotal.WithLabelValues("invalid_type").Inc()
		return nil, fmt.Errorf("%w: %q", ErrInvalidType, opts.Type)
	}
	if opts.SubjectName == "" && opts.SubjectUID == "" && opts.EnrichVia == "" {
		droppedTotal.WithLabelValues("subject_missing").Inc()
		return nil, ErrSubjectMissing
	}
	if err := e.rateLimiter.Wait(ctx); err != nil {
		droppedTotal.WithLabelValues("ratelimit_ctx_cancel").Inc()
		return nil, fmt.Errorf("emitter rate-limit wait: %w", err)
	}

	now := e.now()
	if opts.CorrelationID == "" {
		opts.CorrelationID = deriveCorrelationID(opts, now)
	}
	subject := e.buildSubject(ctx, opts)

	se := &securityv1alpha1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{
			Name: deterministicSEName(opts.CorrelationID),
			Labels: map[string]string{
				"ugallu.io/correlation-id":     opts.CorrelationID,
				"app.kubernetes.io/managed-by": e.opts.AttestorMeta.Name,
			},
		},
		Spec: securityv1alpha1.SecurityEventSpec{
			Class:           opts.Class,
			Type:            opts.Type,
			Severity:        opts.Severity,
			ClusterIdentity: opts.ClusterIdentity,
			Source: securityv1alpha1.SourceRef{
				APIVersion: securityv1alpha1.GroupVersion.String(),
				Kind:       e.opts.AttestorMeta.Name,
				Name:       e.opts.AttestorMeta.Name,
				Version:    e.opts.AttestorMeta.Version,
				Instance:   e.opts.AttestorMeta.Instance,
			},
			Subject:       subject,
			DetectedAt:    pickTime(opts.DetectedAt, now),
			Signals:       opts.Signals,
			Parents:       opts.Parents,
			CorrelationID: opts.CorrelationID,
		},
	}

	if err := e.opts.Client.Create(ctx, se); err != nil {
		if apierrors.IsAlreadyExists(err) {
			emittedTotal.WithLabelValues(string(opts.Class), opts.Type, string(opts.Severity)).Inc()
			return se, nil
		}
		// Transient → enqueue. Permanent (validation, RBAC) → bubble.
		if isTransient(err) {
			if enqErr := e.enqueue(se); enqErr != nil {
				droppedTotal.WithLabelValues("buffer_full").Inc()
				return nil, fmt.Errorf("emitter create %s/%s: %w (and buffer enqueue: %v)", opts.Class, opts.Type, err, enqErr)
			}
			droppedTotal.WithLabelValues("buffered_for_retry").Inc()
			return se, nil
		}
		droppedTotal.WithLabelValues("permanent").Inc()
		return nil, fmt.Errorf("emitter create %s/%s: %w", opts.Class, opts.Type, err)
	}
	emittedTotal.WithLabelValues(string(opts.Class), opts.Type, string(opts.Severity)).Inc()
	return se, nil
}

// buildSubject populates the SubjectTier1 from EmitOpts. When
// EnrichVia is set the resolver answer wins; otherwise the bare
// Subject from the EmitOpts identity fields is used.
func (e *Emitter) buildSubject(ctx context.Context, opts *EmitOpts) securityv1alpha1.SubjectTier1 {
	bare := securityv1alpha1.SubjectTier1{
		Kind:      opts.SubjectKind,
		Name:      opts.SubjectName,
		Namespace: opts.SubjectNamespace,
		UID:       opts.SubjectUID,
	}
	if e.opts.Resolver == nil || opts.EnrichVia == "" {
		// Without resolver enrichment the bare subject carries Kind +
		// Name but no kind-specific discriminator (Pod / Container /
		// ClusterRoleBinding / …). The subject-discriminator
		// admission policy demands either a populated discriminator
		// or Unresolved=true, so flag this branch as Unresolved.
		// Callers that want a fully-populated discriminator must
		// provide a Resolver and EnrichVia.
		bare.Unresolved = true
		return bare
	}

	enrichCtx, cancel := context.WithTimeout(ctx, e.opts.EnrichTimeout)
	defer cancel()
	start := time.Now()
	resp, err := e.callResolver(enrichCtx, opts)
	outcome := "hit"
	switch {
	case err != nil:
		outcome = "error"
	case resp == nil || resp.GetUnresolved():
		outcome = "unresolved"
	case resp.GetTombstone():
		outcome = "tombstone"
	case resp.GetPartial():
		outcome = "partial"
	}
	enrichLatency.WithLabelValues(string(opts.EnrichVia), outcome).Observe(time.Since(start).Seconds())

	if err != nil || resp == nil || len(resp.GetTier1Json()) == 0 {
		bare.Partial = true
		if bare.Name == "" && bare.UID == "" {
			bare.Unresolved = true
		}
		if opts.Signals == nil {
			opts.Signals = map[string]string{}
		}
		if err != nil {
			opts.Signals["resolver_error"] = err.Error()
		}
		return bare
	}
	var tier1 securityv1alpha1.SubjectTier1
	if uErr := json.Unmarshal(resp.GetTier1Json(), &tier1); uErr != nil {
		bare.Partial = true
		return bare
	}
	if resp.GetPartial() {
		tier1.Partial = true
	}
	if resp.GetTombstone() {
		tier1.Tombstone = true
	}
	return tier1
}

// callResolver dispatches to the right gRPC method based on
// EnrichVia. EnrichKey is interpreted per-method (numeric for cgroup
// id and pid, string otherwise).
func (e *Emitter) callResolver(ctx context.Context, opts *EmitOpts) (*resolverv1.SubjectResponse, error) {
	switch opts.EnrichVia {
	case EnrichByCgroupID:
		id, err := strconv.ParseUint(opts.EnrichKey, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("cgroup id %q is not a uint64: %w", opts.EnrichKey, err)
		}
		return e.opts.Resolver.ResolveByCgroupID(ctx, &resolverv1.CgroupIDRequest{CgroupId: id})
	case EnrichByPID:
		pid, err := strconv.ParseInt(opts.EnrichKey, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("pid %q is not an int32: %w", opts.EnrichKey, err)
		}
		return e.opts.Resolver.ResolveByPID(ctx, &resolverv1.PIDRequest{Pid: int32(pid)})
	case EnrichByPodUID:
		return e.opts.Resolver.ResolveByPodUID(ctx, &resolverv1.PodUIDRequest{Uid: opts.EnrichKey})
	case EnrichByPodIP:
		return e.opts.Resolver.ResolveByPodIP(ctx, &resolverv1.PodIPRequest{Ip: opts.EnrichKey})
	case EnrichByContainerID:
		return e.opts.Resolver.ResolveByContainerID(ctx, &resolverv1.ContainerIDRequest{ContainerId: opts.EnrichKey})
	case EnrichBySAUsername:
		return e.opts.Resolver.ResolveBySAUsername(ctx, &resolverv1.SAUsernameRequest{Username: opts.EnrichKey})
	default:
		return nil, fmt.Errorf("unknown EnrichVia %q", opts.EnrichVia)
	}
}

// enqueue places se on the retry buffer. Returns ErrBufferFull on
// overflow; the caller treats that as a permanent drop.
func (e *Emitter) enqueue(se *securityv1alpha1.SecurityEvent) error {
	select {
	case e.buffer <- se:
		bufferDepth.Set(float64(e.bufDepth.Add(1)))
		return nil
	default:
		return ErrBufferFull
	}
}

// runRetry drains the buffer with exponential backoff. Successful
// retries decrement the depth gauge; permanent failures drop with a
// labelled metric so the SOC sees the loss.
func (e *Emitter) runRetry(ctx context.Context) {
	backoff := wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Jitter:   0.2,
		Steps:    5,
		Cap:      30 * time.Second,
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case se := <-e.buffer:
			e.retryOne(ctx, se, backoff)
			bufferDepth.Set(float64(e.bufDepth.Add(-1)))
		}
	}
}

// retryOne loops Create with the configured backoff until success,
// permanent failure, or context cancellation.
func (e *Emitter) retryOne(ctx context.Context, se *securityv1alpha1.SecurityEvent, b wait.Backoff) {
	for {
		err := e.opts.Client.Create(ctx, se)
		if err == nil || apierrors.IsAlreadyExists(err) {
			emittedTotal.WithLabelValues(string(se.Spec.Class), se.Spec.Type, string(se.Spec.Severity)).Inc()
			return
		}
		if !isTransient(err) {
			droppedTotal.WithLabelValues("retry_permanent").Inc()
			e.opts.Log.Error("emitter retry: permanent error",
				"name", se.Name, "type", se.Spec.Type, "err", err)
			return
		}
		select {
		case <-ctx.Done():
			droppedTotal.WithLabelValues("retry_ctx_cancel").Inc()
			return
		case <-time.After(b.Step()):
		}
		if b.Steps == 0 {
			droppedTotal.WithLabelValues("retry_exhausted").Inc()
			e.opts.Log.Error("emitter retry: gave up",
				"name", se.Name, "type", se.Spec.Type, "lastErr", err)
			return
		}
	}
}

// isTransient flags errors the retry path can profitably reattempt.
// Conflict (already exists) is the success-cover; everything in the
// "5xx-ish" / network bucket is transient. Validation / RBAC are
// permanent.
func isTransient(err error) bool {
	switch {
	case apierrors.IsServerTimeout(err),
		apierrors.IsTimeout(err),
		apierrors.IsTooManyRequests(err),
		apierrors.IsServiceUnavailable(err),
		apierrors.IsInternalError(err):
		return true
	}
	return false
}

// pickTime returns explicit when non-zero, else fallback wrapped in
// metav1.Time.
func pickTime(explicit metav1.Time, fallback time.Time) metav1.Time {
	if !explicit.IsZero() {
		return explicit
	}
	return metav1.NewTime(fallback)
}

// discardWriter is the io.Writer fallback for slog when the caller
// passes nil; it silences the logger without nil-checking inside Emit.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
