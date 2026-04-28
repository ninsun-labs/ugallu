// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package webhookauditor exposes the controller-runtime wiring for the
// ugallu-webhook-auditor operator (design 21 §W). The MWC/VWC informer,
// risk evaluator, and SE emitter ship in subsequent commits; this file
// holds only the manager-side bootstrap so cmd/ugallu-webhook-auditor
// can compile from day one.
package webhookauditor

import (
	"errors"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// Options bundles the runtime parameters cmd/ugallu-webhook-auditor
// passes to SetupWithManager.
type Options struct {
	// ConfigName is the singleton WebhookAuditorConfig name (default
	// "default"). Empty disables the operator's read of the CR;
	// chart-shipped CR is required, so empty is treated as error.
	ConfigName string

	// ClusterIdentity stamps every emitted SE so downstream consumers
	// (attestor, forensics) can partition by cluster.
	ClusterIdentity securityv1alpha1.ClusterIdentity

	// Emitter is the SE emitter wired by cmd. Required.
	Emitter *emitterv1alpha1.Emitter
}

// SetupWithManager registers the operator's reconcilers + informers
// against mgr. Subsequent commits add real wiring; current scaffold
// returns nil after validating Options so the binary stays bootable
// pre-implementation.
func SetupWithManager(_ ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("webhookauditor.SetupWithManager: nil Options")
	}
	if opts.Emitter == nil {
		return errors.New("webhookauditor.SetupWithManager: nil Emitter")
	}
	if opts.ConfigName == "" {
		return errors.New("webhookauditor.SetupWithManager: empty ConfigName")
	}
	// TODO(wave3-sprint1-commit2): wire MWC/VWC informer + RiskEvaluator + reconciler.
	return nil
}

// Manager is a thin re-export so cmd/ugallu-webhook-auditor's main.go
// can keep its imports stable across the scaffold → wired transition.
type Manager = manager.Manager
