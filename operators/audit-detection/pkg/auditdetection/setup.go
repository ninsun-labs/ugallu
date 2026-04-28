// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package auditdetection wires the audit-log → SecurityEvent
// pipeline that runs as a control-plane DaemonSet.
//
// Sprint 0 (this file) lands the Options + SetupController scaffold so
// the cmd binary can build and the helm subchart can deploy a real
// (no-op for now) leader-elected workload. Sprint 1 layers in the
// kubelet-file backend reader, the Sigma subset rule engine, the
// SigmaRule CRD reconciler, and the rule → SE Type mapping (design
// 20 §A1-A9).
package auditdetection

import (
	"errors"
	"log/slog"

	ctrl "sigs.k8s.io/controller-runtime"

	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// DefaultAuditLogPath is the conventional bind-mount where the
// kubelet/apiserver audit log lands inside the DaemonSet pod.
const DefaultAuditLogPath = "/host/audit/audit.log"

// DefaultInotifyBufferSize sizes the inotify watcher channel; 64K
// matches the Linux default fs.inotify.max_queued_events.
const DefaultInotifyBufferSize = 64 * 1024

// Options configures SetupController. opts is taken by pointer
// (gocritic hugeParam fix) and validated in-place.
type Options struct {
	// Emitter is the SDK that publishes SecurityEvent CRs. Required.
	Emitter *emitterv1alpha1.Emitter

	// AuditLogPath overrides the kubelet audit-log file path.
	AuditLogPath string

	// SigmaRuleNamespace narrows the SigmaRule CRD watch. Empty =
	// cluster-scoped (the default in v1alpha1).
	SigmaRuleNamespace string

	// Log routes diagnostics. nil → discard.
	Log *slog.Logger

	// InotifyBufferSize defaults to DefaultInotifyBufferSize.
	InotifyBufferSize int
}

// SetupController wires the audit-detection reconciler into the
// supplied controller-runtime manager. The function is intentionally
// a stub in Sprint 0: it validates Options and registers nothing. The
// real reconciler (kubelet file tail + Sigma evaluator + SE emitter)
// lands in Sprint 1.
func SetupController(_ ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("auditdetection: opts is required")
	}
	if opts.Emitter == nil {
		return errors.New("auditdetection: Emitter is required")
	}
	if opts.AuditLogPath == "" {
		opts.AuditLogPath = DefaultAuditLogPath
	}
	if opts.InotifyBufferSize <= 0 {
		opts.InotifyBufferSize = DefaultInotifyBufferSize
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	opts.Log.Info("auditdetection: scaffold loaded; reconciler arrives in Sprint 1",
		"auditLogPath", opts.AuditLogPath,
		"sigmaRuleNamespace", opts.SigmaRuleNamespace,
	)
	return nil
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
