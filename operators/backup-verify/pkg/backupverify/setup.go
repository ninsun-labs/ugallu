// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package backupverify wires the BackupVerifyRun reconciler. The
// reconciler delegates to a backend-specific verifier (Velero or
// etcd-snapshot) and writes a BackupVerifyResult per run.
package backupverify

import (
	"errors"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// Options bundles the runtime parameters cmd/ugallu-backup-verify
// passes to SetupWithManager.
type Options struct {
	ClusterIdentity securityv1alpha1.ClusterIdentity
	Emitter         *emitterv1alpha1.Emitter

	// EtcdSnapshotDir is the hostPath where the etcd-snapshot
	// backend looks up snapshot files. Must be mounted into the
	// operator pod when the backend is in use.
	EtcdSnapshotDir string
}

// SetupWithManager registers the BackupVerifyRun reconciler.
func SetupWithManager(mgr ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("backupverify.SetupWithManager: nil Options")
	}
	if opts.Emitter == nil {
		return errors.New("backupverify.SetupWithManager: nil Emitter")
	}

	r := &RunReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Emitter:         opts.Emitter,
		ClusterIdentity: opts.ClusterIdentity,
		EtcdSnapshotDir: opts.EtcdSnapshotDir,
	}
	if err := r.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("backup-verify reconciler: %w", err)
	}
	return nil
}
