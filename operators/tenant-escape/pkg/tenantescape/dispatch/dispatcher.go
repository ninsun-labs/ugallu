// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package dispatch fans events from the source backends through the
// detector chain and forwards firing Findings to the SDK Emitter.
package dispatch

import (
	"context"
	"sync"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/detector"
)

// Dispatcher routes events from the audit-bus + Tetragon sources
// through the configured detector chains and emits a SecurityEvent
// for each firing Finding.
type Dispatcher struct {
	auditDetectors []detector.AuditDetector
	execDetectors  []detector.ExecDetector
	boundaries     detector.BoundarySet
	emitter        *emitterv1alpha1.Emitter
	clusterID      securityv1alpha1.ClusterIdentity

	mu sync.Mutex
}

// New returns a wired dispatcher. boundaries is the
// thread-safe BoundarySet (the boundary index) the detectors query.
func New(
	auditDetectors []detector.AuditDetector,
	execDetectors []detector.ExecDetector,
	boundaries detector.BoundarySet,
	em *emitterv1alpha1.Emitter,
	ci securityv1alpha1.ClusterIdentity,
) *Dispatcher {
	return &Dispatcher{
		auditDetectors: auditDetectors,
		execDetectors:  execDetectors,
		boundaries:     boundaries,
		emitter:        em,
		clusterID:      ci,
	}
}

// RunAudit consumes audit events from src until the channel closes
// or ctx is cancelled.
func (d *Dispatcher) RunAudit(ctx context.Context, src <-chan *detector.AuditInput) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-src:
			if !ok {
				return
			}
			d.dispatchAudit(ctx, ev)
		}
	}
}

// RunExec consumes exec events from src until the channel closes or
// ctx is cancelled.
func (d *Dispatcher) RunExec(ctx context.Context, src <-chan *detector.ExecInput) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-src:
			if !ok {
				return
			}
			d.dispatchExec(ctx, ev)
		}
	}
}

func (d *Dispatcher) dispatchAudit(ctx context.Context, ev *detector.AuditInput) {
	if ev == nil {
		return
	}
	for _, det := range d.auditDetectors {
		f := det.Evaluate(ev, d.boundaries)
		if !f.Has() {
			continue
		}
		d.emit(ctx, f)
	}
}

func (d *Dispatcher) dispatchExec(ctx context.Context, ev *detector.ExecInput) {
	if ev == nil {
		return
	}
	for _, det := range d.execDetectors {
		f := det.Evaluate(ev, d.boundaries)
		if !f.Has() {
			continue
		}
		d.emit(ctx, f)
	}
}

func (d *Dispatcher) emit(ctx context.Context, f *detector.Finding) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, _ = d.emitter.Emit(ctx, &emitterv1alpha1.EmitOpts{
		Class:            securityv1alpha1.ClassDetection,
		Type:             f.Type,
		Severity:         securityv1alpha1.Severity(f.Severity),
		SubjectKind:      securityv1alpha1.SubjectKind(f.Subject.Kind),
		SubjectName:      f.Subject.Name,
		SubjectNamespace: f.Subject.Namespace,
		SubjectUID:       f.Subject.UID,
		Signals:          f.Signals,
		ClusterIdentity:  d.clusterID,
	})
}
