// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package auditdetection wires the audit-log → SecurityEvent
// pipeline that runs as a control-plane DaemonSet (file backend) or
// Deployment (webhook backend).
//
// SetupController is the small surface the cmd binary calls: it
// validates an Options bag and registers the SigmaRuleReconciler with
// the supplied controller-runtime manager. The Source layer
// (FileSource / WebhookSource) and the rule Engine are constructed
// directly by the cmd binary because they own goroutines outside the
// manager's leader-election scope.
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

// SetupController validates Options and is the documented entry
// point for the cmd binary. The reconciler itself lives in the
// engine subpackage to avoid an import cycle with sigma.
//
// Operator authors typically call cmd-level wiring directly
// (engine.New + SigmaRuleReconciler.SetupWithManager); this helper
// exists so external callers (other operators, tests) can validate
// an Options bag without pulling in the full engine.
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
	return nil
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
