// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package confidentialattestation wires the
// ConfidentialAttestationRun reconciler against a controller-runtime
// manager. The reconciler dispatches each run to a backend Attester
// (TPM / SEV-SNP / TDX) and writes a result + AttestationVerified|
// Failed SE.
package confidentialattestation

import (
	"errors"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// Options bundles the runtime parameters cmd/ugallu-confidential-
// attestation passes to SetupWithManager.
type Options struct {
	ClusterIdentity securityv1alpha1.ClusterIdentity
	Emitter         *emitterv1alpha1.Emitter

	// NodeName is the host the attester runs on. The reconciler
	// ignores Runs whose Spec.TargetNodeName mismatches.
	NodeName string

	// Per-backend device paths (host-mounted into the privileged
	// DaemonSet pod). The attester opens these read-only.
	TPMDevice    string
	SEVSNPDevice string
	TDXDevice    string
}

// SetupWithManager registers the ConfidentialAttestationRun
// reconciler.
func SetupWithManager(mgr ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("confidentialattestation.SetupWithManager: nil Options")
	}
	if opts.Emitter == nil {
		return errors.New("confidentialattestation.SetupWithManager: nil Emitter")
	}
	if opts.NodeName == "" {
		return errors.New("confidentialattestation.SetupWithManager: empty NodeName")
	}
	r := &RunReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Emitter:         opts.Emitter,
		ClusterIdentity: opts.ClusterIdentity,
		NodeName:        opts.NodeName,
		TPMDevice:       opts.TPMDevice,
		SEVSNPDevice:    opts.SEVSNPDevice,
		TDXDevice:       opts.TDXDevice,
	}
	if err := r.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("confidential-attestation reconciler: %w", err)
	}
	return nil
}
