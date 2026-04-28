// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package dnsdetect

import (
	"errors"

	ctrl "sigs.k8s.io/controller-runtime"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// Options bundles the runtime parameters cmd/ugallu-dns-detect passes
// to SetupWithManager.
type Options struct {
	// ConfigName is the singleton DNSDetectConfig name (default
	// "default").
	ConfigName string

	// ClusterIdentity stamps every emitted SE.
	ClusterIdentity securityv1alpha1.ClusterIdentity

	// Emitter is the SE emitter wired by cmd. Required.
	Emitter *emitterv1alpha1.Emitter
}

// SetupWithManager registers the operator's reconcilers + sources
// against mgr. Subsequent commits add real wiring; current scaffold
// returns nil after validating Options so the binary stays bootable
// pre-implementation.
func SetupWithManager(_ ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("dnsdetect.SetupWithManager: nil Options")
	}
	if opts.Emitter == nil {
		return errors.New("dnsdetect.SetupWithManager: nil Emitter")
	}
	if opts.ConfigName == "" {
		return errors.New("dnsdetect.SetupWithManager: empty ConfigName")
	}
	// TODO(wave3-sprint3-commit2+): wire 5 detectors + source backends + reconciler.
	return nil
}
