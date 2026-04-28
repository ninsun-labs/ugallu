// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package dnsdetect

import (
	"context"
	"sync"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsdetect/detector"
	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsevent"
)

// Dispatcher fans every DNSEvent through the registered detector
// chain and forwards a Finding (when one fires) to the emitter.
//
// Detectors are evaluated in order — short-circuit not used: every
// detector sees every event so per-detector counters stay accurate.
// The detector slice is set at construction; runtime updates are
// not supported (a config change goes through Stop+New).
type Dispatcher struct {
	detectors       []detector.Detector
	emitter         *emitterv1alpha1.Emitter
	clusterIdentity securityv1alpha1.ClusterIdentity

	mu sync.Mutex
}

// NewDispatcher returns a wired dispatcher.
func NewDispatcher(detectors []detector.Detector, em *emitterv1alpha1.Emitter, ci securityv1alpha1.ClusterIdentity) *Dispatcher {
	return &Dispatcher{
		detectors:       detectors,
		emitter:         em,
		clusterIdentity: ci,
	}
}

// Run consumes events from src until the channel closes (source
// stopped or ctx cancelled). Each event is dispatched to every
// detector; firing detectors emit a SE via the configured emitter.
func (d *Dispatcher) Run(ctx context.Context, src <-chan *dnsevent.DNSEvent) {
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

// dispatch runs every detector against ev and emits SEs for findings.
func (d *Dispatcher) dispatch(ctx context.Context, ev *dnsevent.DNSEvent) {
	if ev == nil {
		return
	}
	for _, det := range d.detectors {
		f := det.Evaluate(ev)
		if !f.Has() {
			continue
		}
		d.emit(ctx, ev, f)
	}
}

// emit forwards a Finding to the emitter SDK as a SecurityEvent.
func (d *Dispatcher) emit(ctx context.Context, _ *dnsevent.DNSEvent, f detector.Finding) {
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
		ClusterIdentity:  d.clusterIdentity,
	})
}
