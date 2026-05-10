// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package forensics wires the SE-triggered IR-as-code pipeline that
// runs as a leader-elected Deployment.
//
// Sprint 0 (this file) lands the Options + SetupController scaffold so
// the cmd binary builds and the helm subchart deploys a real
// (no-op for now) workload. Subsequent sprints land the ForensicsConfig
// CRD, the IncidentCapture trigger, the sequential pipeline framework,
// the pod-freeze step, filesystem + memory snapshots, auto-unfreeze,
// crash recovery and step idempotency.
package forensics

import (
	"errors"
	"log/slog"

	ctrl "sigs.k8s.io/controller-runtime"

	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// DefaultForensicsConfigName is the conventional CR name the operator
// reconciles against.
const DefaultForensicsConfigName = "default"

// DefaultWORMSecretName is the Secret bearing S3 credentials for
// snapshot uploads. It mirrors the WORM credentials Secret used by the
// attestor.
const DefaultWORMSecretName = "ugallu-worm-creds" //nolint:gosec // secret name, not a credential value

// DefaultWORMSecretNamespace is the privileged-side namespace where
// the forensics workload runs and reads its WORM credentials.
const DefaultWORMSecretNamespace = "ugallu-system-privileged" //nolint:gosec // namespace name, not a credential value

// Options configures SetupController. opts is taken by pointer
// (gocritic hugeParam fix) and validated in-place.
type Options struct {
	// Emitter is the SDK that publishes SecurityEvent CRs. Required.
	Emitter *emitterv1alpha1.Emitter

	// ForensicsConfigName overrides the singleton CR name; default
	// "default".
	ForensicsConfigName string

	// ForensicsConfigNamespace narrows the reconcile to a single
	// namespace. Empty = cluster-scoped (the v1alpha1 default).
	ForensicsConfigNamespace string

	// Log routes diagnostics. nil → discard.
	Log *slog.Logger

	// SnapshotImage overrides the ephemeral debug-container image
	// used for filesystem and memory snapshots. Empty falls back to
	// the value carried by the active ForensicsConfig CR.
	SnapshotImage string

	// WORMSecretName references the Secret with S3 access/secret
	// keys; default DefaultWORMSecretName.
	WORMSecretName string

	// WORMSecretNamespace defaults to DefaultWORMSecretNamespace.
	WORMSecretNamespace string
}

// SetupController wires the forensics reconciler into the supplied
// controller-runtime manager. The function is intentionally a stub in
// Sprint 0: it validates Options and registers nothing. The real
// pipeline (IncidentCapture trigger + freeze step + snapshot steps)
// lands in Sprint 2 and Sprint 3.
func SetupController(_ ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("forensics: opts is required")
	}
	if opts.Emitter == nil {
		return errors.New("forensics: Emitter is required")
	}
	if opts.ForensicsConfigName == "" {
		opts.ForensicsConfigName = DefaultForensicsConfigName
	}
	if opts.WORMSecretName == "" {
		opts.WORMSecretName = DefaultWORMSecretName
	}
	if opts.WORMSecretNamespace == "" {
		opts.WORMSecretNamespace = DefaultWORMSecretNamespace
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	opts.Log.Info("forensics: scaffold loaded; pipeline arrives in Sprint 2",
		"forensicsConfig", opts.ForensicsConfigName,
		"namespace", opts.ForensicsConfigNamespace,
		"wormSecret", opts.WORMSecretNamespace+"/"+opts.WORMSecretName,
	)
	return nil
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
