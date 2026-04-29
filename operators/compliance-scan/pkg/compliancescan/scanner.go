// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package compliancescan

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// ScanOutcome is what a Scanner returns to the reconciler — the raw
// materials the run needs to write a ComplianceScanResult.
type ScanOutcome struct {
	Checks  []securityv1alpha1.ComplianceCheckResult
	Summary map[string]int
}

// Scanner is the backend-agnostic interface every supported scanner
// implements. The k8s client is passed in (rather than stored on the
// struct) so the reconciler controls request-scope context.
type Scanner interface {
	Scan(ctx context.Context, c client.Client, spec *securityv1alpha1.ComplianceScanRunSpec) (*ScanOutcome, error)
}

// ScannerFor returns the right backend.
func ScannerFor(spec *securityv1alpha1.ComplianceScanRunSpec) (Scanner, error) {
	switch spec.Backend {
	case securityv1alpha1.ComplianceScanBackendKubeBench:
		return &kubeBenchScanner{}, nil
	case securityv1alpha1.ComplianceScanBackendFalco:
		return &falcoScanner{}, nil
	case securityv1alpha1.ComplianceScanBackendCELCustom:
		return &celCustomScanner{}, nil
	default:
		return nil, fmt.Errorf("unsupported backend %q", spec.Backend)
	}
}

// celCustomScanner is the v0.1.0 in-tree backend. It walks the
// cluster and runs a small fixed set of CEL-equivalent checks
// directly in Go (no CEL runtime dep yet — the rules are simple
// enough that a hand-rolled evaluator beats pulling in the full
// k8s.io/apiserver/pkg/cel transitive tree).
type celCustomScanner struct{}

func (s *celCustomScanner) Scan(ctx context.Context, c client.Client, _ *securityv1alpha1.ComplianceScanRunSpec) (*ScanOutcome, error) {
	out := &ScanOutcome{Summary: map[string]int{"pass": 0, "fail": 0, "warn": 0, "skip": 0}}

	// Check 1: every Pod runs as non-root.
	var podList corev1.PodList
	if err := c.List(ctx, &podList); err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	rootPods := 0
	for i := range podList.Items {
		p := &podList.Items[i]
		if isRoot(p) {
			rootPods++
		}
	}
	check1 := securityv1alpha1.ComplianceCheckResult{
		CheckID: "ugallu.cel.pods-run-as-non-root",
		Title:   "Every Pod must run with a non-root securityContext.",
		Outcome: "pass",
	}
	if rootPods > 0 {
		check1.Outcome = "fail"
		check1.Severity = securityv1alpha1.SeverityHigh
		check1.Detail = fmt.Sprintf("%d pods run as root or with no securityContext.runAsNonRoot=true", rootPods)
	}
	out.Checks = append(out.Checks, check1)
	out.Summary[check1.Outcome]++

	// Check 2: every Pod sets readOnlyRootFilesystem=true on every
	// container. Skipped on init containers (they often need to
	// write to the rootfs to bootstrap).
	rwroot := 0
	for i := range podList.Items {
		p := &podList.Items[i]
		for j := range p.Spec.Containers {
			if !rorootFs(&p.Spec.Containers[j]) {
				rwroot++
			}
		}
	}
	check2 := securityv1alpha1.ComplianceCheckResult{
		CheckID: "ugallu.cel.read-only-root-fs",
		Title:   "Every Pod container must set securityContext.readOnlyRootFilesystem=true.",
		Outcome: "pass",
	}
	if rwroot > 0 {
		check2.Outcome = "fail"
		check2.Severity = securityv1alpha1.SeverityMedium
		check2.Detail = fmt.Sprintf("%d containers have a writable rootfs", rwroot)
	}
	out.Checks = append(out.Checks, check2)
	out.Summary[check2.Outcome]++

	// Check 3: NetworkPolicy / CiliumNetworkPolicy is present in
	// at least one namespace. The CEL backend only flags absence,
	// not the per-namespace coverage gap (a follow-up).
	check3 := securityv1alpha1.ComplianceCheckResult{
		CheckID:  "ugallu.cel.netpol-present",
		Title:    "Cluster has at least one NetworkPolicy or CiliumNetworkPolicy.",
		Outcome:  "skip",
		Severity: securityv1alpha1.SeverityInfo,
		Detail:   "v0.1.0 stub: full NetworkPolicy enumeration requires the SDK's network-policy adapter (lands post-Wave-4).",
	}
	out.Checks = append(out.Checks, check3)
	out.Summary[check3.Outcome]++

	return out, nil
}

// kubeBenchScanner shells out to the upstream kube-bench binary.
// v0.1.0 ships a stub: kube-bench needs a privileged Pod with
// hostPath access to /etc/kubernetes — the operator deployment runs
// non-privileged. Real integration uses a Job that the operator
// templates per scan.
type kubeBenchScanner struct{}

func (s *kubeBenchScanner) Scan(_ context.Context, _ client.Client, spec *securityv1alpha1.ComplianceScanRunSpec) (*ScanOutcome, error) {
	return &ScanOutcome{
		Summary: map[string]int{"skip": 1},
		Checks: []securityv1alpha1.ComplianceCheckResult{
			{
				CheckID:  "ugallu.kube-bench.runner-stub",
				Title:    "kube-bench backend (v0.1.0 stub).",
				Outcome:  "skip",
				Severity: securityv1alpha1.SeverityInfo,
				Detail: fmt.Sprintf(
					"v0.1.0 stub: real kube-bench integration uses a privileged Job templated per scan; profile=%q recorded for follow-up",
					spec.Profile),
			},
		},
	}, nil
}

// falcoScanner queries a running Falco DaemonSet's gRPC output for
// matching events in the scan window. v0.1.0 stub: Falco isn't
// shipped as part of the umbrella chart so the integration depends
// on what the cluster admin already deployed.
type falcoScanner struct{}

func (s *falcoScanner) Scan(_ context.Context, _ client.Client, spec *securityv1alpha1.ComplianceScanRunSpec) (*ScanOutcome, error) {
	return &ScanOutcome{
		Summary: map[string]int{"skip": 1},
		Checks: []securityv1alpha1.ComplianceCheckResult{
			{
				CheckID:  "ugallu.falco.runner-stub",
				Title:    "Falco backend (v0.1.0 stub).",
				Outcome:  "skip",
				Severity: securityv1alpha1.SeverityInfo,
				Detail: fmt.Sprintf(
					"v0.1.0 stub: Falco gRPC integration needs a Falco DaemonSet on the cluster; profile=%q recorded for follow-up",
					spec.Profile),
			},
		},
	}, nil
}

// isRoot reports whether the Pod runs as root or has no explicit
// non-root assertion on PodSecurityContext / first-container
// SecurityContext.
func isRoot(p *corev1.Pod) bool {
	if p.Spec.SecurityContext != nil {
		if rn := p.Spec.SecurityContext.RunAsNonRoot; rn != nil && *rn {
			return false
		}
		if u := p.Spec.SecurityContext.RunAsUser; u != nil && *u != 0 {
			return false
		}
	}
	for i := range p.Spec.Containers {
		c := &p.Spec.Containers[i]
		if c.SecurityContext != nil {
			if rn := c.SecurityContext.RunAsNonRoot; rn != nil && *rn {
				return false
			}
			if u := c.SecurityContext.RunAsUser; u != nil && *u != 0 {
				return false
			}
		}
	}
	return true
}

// rorootFs reports whether a container has readOnlyRootFilesystem=true.
func rorootFs(c *corev1.Container) bool {
	if c == nil || c.SecurityContext == nil {
		return false
	}
	return c.SecurityContext.ReadOnlyRootFilesystem != nil && *c.SecurityContext.ReadOnlyRootFilesystem
}
