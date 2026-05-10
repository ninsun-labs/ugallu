// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package honeypot wires the controller-runtime spine for the
// ugallu-honeypot operator. It assembles:
//   - the HoneypotConfig reconciler (materialises declared decoys
//   - maintains the in-memory decoy index);
//   - the audit-bus source backend that drives detector evaluation
//     against the live audit stream;
//   - the dispatcher that fans events through the detectors and
//     emits SecurityEvents on hits.
package honeypot

import (
	"context"
	"errors"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/deployer"
	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/detector"
	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/dispatch"
	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/index"
	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/source"
)

// Options bundles the runtime parameters cmd/ugallu-honeypot passes
// to SetupWithManager.
type Options struct {
	ClusterIdentity securityv1alpha1.ClusterIdentity
	Emitter         *emitterv1alpha1.Emitter

	AuditBusEndpoint     string
	AuditBusToken        string
	AuditBusConsumerName string
}

// SetupWithManager registers the HoneypotConfig reconciler, builds
// the detector chain over the shared decoy Index, and wires the
// audit-bus source + dispatcher as a manager Runnable.
func SetupWithManager(mgr ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("honeypot.SetupWithManager: nil Options")
	}
	if opts.Emitter == nil {
		return errors.New("honeypot.SetupWithManager: nil Emitter")
	}
	if opts.AuditBusEndpoint == "" {
		return errors.New("honeypot.SetupWithManager: empty AuditBusEndpoint")
	}

	idx := index.New()

	if err := (&deployer.HoneypotConfigReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Index:  idx,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("honeypotconfig reconciler: %w", err)
	}

	detectors := []detector.AuditDetector{
		detector.NewHoneypotTriggeredDetector(idx),
		detector.NewHoneypotMisplacedDetector(idx),
	}
	disp := dispatch.New(detectors, opts.Emitter, opts.ClusterIdentity)

	auditSrc, err := source.NewAuditBusSource(source.AuditBusConfig{
		Endpoint:     opts.AuditBusEndpoint,
		BearerToken:  opts.AuditBusToken,
		ConsumerName: opts.AuditBusConsumerName,
	})
	if err != nil {
		return fmt.Errorf("audit-bus source: %w", err)
	}

	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		ch, runErr := auditSrc.Run(ctx)
		if runErr != nil {
			return fmt.Errorf("audit-bus source: %w", runErr)
		}
		disp.RunAudit(ctx, ch)
		return nil
	})); err != nil {
		return fmt.Errorf("audit-bus runnable: %w", err)
	}
	return nil
}
