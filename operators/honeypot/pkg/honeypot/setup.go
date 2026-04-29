// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package honeypot wires the controller-runtime spine for the
// ugallu-honeypot operator (design 21 §H). It owns:
//   - the HoneypotConfig reconciler (materialises declared decoys
//   - maintains the in-memory decoy index);
//   - the audit-bus source backend that drives detector evaluation
//     against the live audit stream;
//   - the dispatcher that fans events through the detectors and
//     emits SecurityEvents on hits.
//
// Real wiring lands in commits 3 + 4 + 5 of Wave 3 Sprint 5; this
// file ships the Options surface + skeleton SetupWithManager.
package honeypot

import (
	"errors"

	ctrl "sigs.k8s.io/controller-runtime"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// Options bundles the runtime parameters cmd/ugallu-honeypot passes
// to SetupWithManager.
type Options struct {
	// ClusterIdentity stamps every emitted SE.
	ClusterIdentity securityv1alpha1.ClusterIdentity

	// Emitter is the SE emitter wired by cmd. Required.
	Emitter *emitterv1alpha1.Emitter

	// AuditBusEndpoint is the gRPC address of the audit-detection
	// event bus.
	AuditBusEndpoint string

	// AuditBusToken authenticates against the bus when AuthBearer
	// is configured server-side.
	AuditBusToken string
}

// SetupWithManager validates Options and registers the operator's
// reconcilers + sources against mgr. Subsequent commits add real
// wiring; current scaffold returns nil after validating Options.
func SetupWithManager(_ ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("honeypot.SetupWithManager: nil Options")
	}
	if opts.Emitter == nil {
		return errors.New("honeypot.SetupWithManager: nil Emitter")
	}
	// TODO(wave3-sprint5-commit3+): wire deployer + index + detector + audit-bus.
	return nil
}
