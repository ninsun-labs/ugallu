// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package tenantescape exposes the controller-runtime wiring for the
// ugallu-tenant-escape operator (design 21 §T). The 4 detectors +
// source backends ship in subsequent commits.
package tenantescape

import (
	"errors"

	ctrl "sigs.k8s.io/controller-runtime"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// Options bundles the runtime parameters cmd/ugallu-tenant-escape
// passes to SetupWithManager.
type Options struct {
	// ClusterIdentity stamps every emitted SE.
	ClusterIdentity securityv1alpha1.ClusterIdentity

	// Emitter is the SE emitter wired by cmd. Required.
	Emitter *emitterv1alpha1.Emitter

	// AuditBusEndpoint is the gRPC address of the audit-detection
	// event bus (typically "ugallu-audit-detection.ugallu-system:8444").
	AuditBusEndpoint string

	// AuditBusToken authenticates against the bus when AuthBearer
	// is configured server-side.
	AuditBusToken string
}

// SetupWithManager registers the operator's reconcilers + sources
// against mgr. Subsequent commits add real wiring; current scaffold
// returns nil after validating Options.
func SetupWithManager(_ ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("tenantescape.SetupWithManager: nil Options")
	}
	if opts.Emitter == nil {
		return errors.New("tenantescape.SetupWithManager: nil Emitter")
	}
	// TODO(wave3-sprint4-commit3+): wire 4 detectors + source backends + reconciler.
	return nil
}
