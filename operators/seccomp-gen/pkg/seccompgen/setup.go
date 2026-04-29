// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package seccompgen wires the SeccompTrainingRun reconciler against
// a controller-runtime manager. The reconciler resolves matching Pods
// for each Run, kicks the training engine (one goroutine per Run),
// and emits the matching SecurityEvents on phase transitions.
package seccompgen

import (
	"errors"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// Options bundles the runtime parameters cmd/ugallu-seccomp-gen
// passes to SetupWithManager.
type Options struct {
	ClusterIdentity securityv1alpha1.ClusterIdentity
	Emitter         *emitterv1alpha1.Emitter
	BridgeEndpoint  string
	BridgeToken     string
}

// SetupWithManager registers the SeccompTrainingRun reconciler.
func SetupWithManager(mgr ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("seccompgen.SetupWithManager: nil Options")
	}
	if opts.Emitter == nil {
		return errors.New("seccompgen.SetupWithManager: nil Emitter")
	}
	if opts.BridgeEndpoint == "" {
		return errors.New("seccompgen.SetupWithManager: empty BridgeEndpoint")
	}

	r := &TrainingRunReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Emitter:         opts.Emitter,
		ClusterIdentity: opts.ClusterIdentity,
		BridgeEndpoint:  opts.BridgeEndpoint,
		BridgeToken:     opts.BridgeToken,
		Engine:          NewEngine(),
	}
	if err := r.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("training-run reconciler: %w", err)
	}
	return nil
}
