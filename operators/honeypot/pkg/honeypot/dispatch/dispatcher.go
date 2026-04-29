// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package dispatch fans audit events from the bus through the
// honeypot detector chain and emits a SecurityEvent for each
// firing Finding.
package dispatch

import (
	"context"
	"sync"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/detector"
)

// Dispatcher routes audit events through the registered detectors.
type Dispatcher struct {
	detectors []detector.AuditDetector
	emitter   *emitterv1alpha1.Emitter
	clusterID securityv1alpha1.ClusterIdentity

	mu sync.Mutex
}

// New returns a wired dispatcher.
func New(detectors []detector.AuditDetector, em *emitterv1alpha1.Emitter, ci securityv1alpha1.ClusterIdentity) *Dispatcher {
	return &Dispatcher{
		detectors: detectors,
		emitter:   em,
		clusterID: ci,
	}
}

// RunAudit consumes events until src closes or ctx is cancelled.
func (d *Dispatcher) RunAudit(ctx context.Context, src <-chan *detector.AuditInput) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-src:
			if !ok {
				return
			}
			d.dispatch(ctx, ev)
		}
	}
}

func (d *Dispatcher) dispatch(ctx context.Context, ev *detector.AuditInput) {
	if ev == nil {
		return
	}
	for _, det := range d.detectors {
		f := det.Evaluate(ev)
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
