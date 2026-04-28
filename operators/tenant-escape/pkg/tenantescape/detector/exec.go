// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// CrossTenantExecDetector flags Tetragon process_exec events where
// an SA from one tenant's namespace exec-s into a Pod in another
// tenant's namespace, unless the executor SA is in the target
// tenant's allowlist (design 21 §T4.4). Severity critical because
// exec is remote-code-execution.
type CrossTenantExecDetector struct{}

// NewCrossTenantExecDetector returns a ready detector.
func NewCrossTenantExecDetector() *CrossTenantExecDetector {
	return &CrossTenantExecDetector{}
}

// Name returns the detector name.
func (d *CrossTenantExecDetector) Name() string { return "cross_tenant_exec" }

// Evaluate runs the heuristic.
func (d *CrossTenantExecDetector) Evaluate(in *ExecInput, b BoundarySet) *Finding {
	if in == nil || b == nil {
		return nil
	}
	if in.ExecutorPodNamespace == "" || in.TargetPodNamespace == "" {
		return nil
	}
	if in.ExecutorPodNamespace == in.TargetPodNamespace {
		return nil
	}
	executorTenant := b.TenantOf(in.ExecutorPodNamespace)
	targetTenant := b.TenantOf(in.TargetPodNamespace)
	if executorTenant == "" || targetTenant == "" || executorTenant == targetTenant {
		return nil
	}
	if b.SAAllowedFor(in.ExecutorUsername, targetTenant) {
		return nil
	}
	return &Finding{
		Type:     securityv1alpha1.TypeCrossTenantExec,
		Severity: Severity(securityv1alpha1.TypeCrossTenantExec),
		Subject: Subject{
			Kind:      "Pod",
			Name:      in.TargetPodName,
			Namespace: in.TargetPodNamespace,
			UID:       in.TargetPodUID,
		},
		Signals: map[string]string{
			"executor.username":  in.ExecutorUsername,
			"executor.namespace": in.ExecutorPodNamespace,
			"target.namespace":   in.TargetPodNamespace,
			"target.name":        in.TargetPodName,
			"command":            in.Command,
		},
	}
}
