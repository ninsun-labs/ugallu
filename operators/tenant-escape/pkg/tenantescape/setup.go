// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package tenantescape exposes the controller-runtime wiring for the
// ugallu-tenant-escape operator (design 21 §T). It assembles:
//   - the TenantBoundary reconciler (rebuilds the in-memory boundary
//     index on every CR Add/Update/Delete);
//   - the audit-bus + Tetragon-stub source backends;
//   - the dispatcher (fans events through the 4 detectors and emits
//     SecurityEvents on hits).
package tenantescape

import (
	"context"
	"errors"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/boundary"
	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/detector"
	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/dispatch"
	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/source"
)

// Options bundles the runtime parameters cmd/ugallu-tenant-escape
// passes to SetupWithManager.
type Options struct {
	// ClusterIdentity stamps every emitted SE.
	ClusterIdentity securityv1alpha1.ClusterIdentity

	// Emitter is the SE emitter wired by cmd. Required.
	Emitter *emitterv1alpha1.Emitter

	// AuditBusEndpoint is the gRPC address of the audit-detection
	// event bus (typically "ugallu-audit-detection.ugallu-system:8444").
	AuditBusEndpoint string

	// AuditBusToken authenticates against the bus when AuthBearer
	// is configured server-side.
	AuditBusToken string

	// AuditBusConsumerName overrides the default consumer name
	// ("tenant-escape"); must match an entry in
	// AuditDetectionConfig.spec.consumers.
	AuditBusConsumerName string

	// BridgeEndpoint is the tetragon-bridge gRPC address (typically
	// "ugallu-tetragon-bridge.ugallu-system-privileged.svc:50051").
	// Empty disables the Tetragon-driven detector and the operator
	// runs the audit-bus detectors only.
	BridgeEndpoint string

	// BridgeToken authenticates against the bridge when its auth
	// interceptor is configured server-side.
	BridgeToken string
}

// SetupWithManager registers the TenantBoundary reconciler + adds the
// dispatcher + audit-bus source + Tetragon-stub source as manager
// Runnables. Returns the first wiring error encountered.
func SetupWithManager(mgr ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("tenantescape.SetupWithManager: nil Options")
	}
	if opts.Emitter == nil {
		return errors.New("tenantescape.SetupWithManager: nil Emitter")
	}
	if opts.AuditBusEndpoint == "" {
		return errors.New("tenantescape.SetupWithManager: empty AuditBusEndpoint")
	}

	idx := boundary.NewIndex()

	if err := (&TenantBoundaryReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Index:  idx,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("tenant-boundary reconciler: %w", err)
	}

	auditDetectors := []detector.AuditDetector{
		detector.NewCrossTenantSecretAccessDetector(),
		detector.NewCrossTenantHostPathOverlapDetector(),
		detector.NewCrossTenantNetworkPolicyDetector(),
	}
	execDetectors := []detector.ExecDetector{
		detector.NewCrossTenantExecDetector(),
	}
	disp := dispatch.New(auditDetectors, execDetectors, idx, opts.Emitter, opts.ClusterIdentity)

	auditSrc, err := source.NewAuditBusSource(source.AuditBusConfig{
		Endpoint:     opts.AuditBusEndpoint,
		BearerToken:  opts.AuditBusToken,
		ConsumerName: opts.AuditBusConsumerName,
	})
	if err != nil {
		return fmt.Errorf("audit-bus source: %w", err)
	}
	var execSrc source.ExecSource
	if opts.BridgeEndpoint != "" {
		bridgeSrc, bridgeErr := source.NewTetragonBridgeSource(&source.TetragonBridgeConfig{
			Endpoint:    opts.BridgeEndpoint,
			BearerToken: opts.BridgeToken,
		})
		if bridgeErr != nil {
			return fmt.Errorf("tetragon-bridge source: %w", bridgeErr)
		}
		execSrc = bridgeSrc
	} else {
		// No bridge endpoint configured — keep the stub so the
		// dispatcher exits cleanly. CrossTenantExec is dormant in
		// this mode (audit-bus detectors still run).
		execSrc = source.NewTetragonStubSource()
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
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		ch, runErr := execSrc.Run(ctx)
		if runErr != nil {
			return fmt.Errorf("exec source: %w", runErr)
		}
		disp.RunExec(ctx, ch)
		return nil
	})); err != nil {
		return fmt.Errorf("exec runnable: %w", err)
	}
	return nil
}
