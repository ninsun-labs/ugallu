// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package compliancescan wires the ComplianceScanRun reconciler
// against a controller-runtime manager. The reconciler dispatches
// each run to a backend-specific Scanner and writes the result.
package compliancescan

import (
	"errors"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// Options bundles the runtime parameters cmd/ugallu-compliance-scan
// passes to SetupWithManager.
type Options struct {
	ClusterIdentity securityv1alpha1.ClusterIdentity
	Emitter         *emitterv1alpha1.Emitter

	// JobNamespace is where the kube-bench backend templates its
	// privileged Job (must be PSA-privileged so the hostPath mounts
	// pass admission). Defaults to ugallu-system-privileged.
	JobNamespace string

	// KubeBenchImage overrides the upstream image; useful for
	// air-gapped clusters that mirror the image.
	KubeBenchImage string

	// Falco gRPC endpoint + mTLS material. Empty FalcoHost falls
	// back to the stub finding for the falco backend.
	FalcoHost       string
	FalcoPort       uint16
	FalcoCertFile   string
	FalcoKeyFile    string
	FalcoCARootFile string
}

// SetupWithManager registers the ComplianceScanRun reconciler.
func SetupWithManager(mgr ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("compliancescan.SetupWithManager: nil Options")
	}
	if opts.Emitter == nil {
		return errors.New("compliancescan.SetupWithManager: nil Emitter")
	}
	r := &RunReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Emitter:         opts.Emitter,
		ClusterIdentity: opts.ClusterIdentity,
		JobNamespace:    opts.JobNamespace,
		KubeBenchImage:  opts.KubeBenchImage,
		FalcoHost:       opts.FalcoHost,
		FalcoPort:       opts.FalcoPort,
		FalcoCertFile:   opts.FalcoCertFile,
		FalcoKeyFile:    opts.FalcoKeyFile,
		FalcoCARootFile: opts.FalcoCARootFile,
	}
	if err := r.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("compliance-scan reconciler: %w", err)
	}
	return nil
}
