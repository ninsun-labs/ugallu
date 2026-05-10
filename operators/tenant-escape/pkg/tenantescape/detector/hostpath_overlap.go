// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"encoding/json"
	"strings"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// CrossTenantHostPathOverlapDetector flags Pod create requests
// where the spec carries a hostPath volume that lies inside ANOTHER
// tenant's HostPathPolicy.Allow set. Fires critical because
// filesystem isolation breach is hard-failure.
type CrossTenantHostPathOverlapDetector struct{}

// NewCrossTenantHostPathOverlapDetector returns a ready detector.
func NewCrossTenantHostPathOverlapDetector() *CrossTenantHostPathOverlapDetector {
	return &CrossTenantHostPathOverlapDetector{}
}

// Name returns the detector name.
func (d *CrossTenantHostPathOverlapDetector) Name() string { return "cross_tenant_hostpath_overlap" }

// Evaluate runs the heuristic. Decodes the audit RequestObject as a
// minimal Pod spec and walks volumes[*].hostPath.path.
func (d *CrossTenantHostPathOverlapDetector) Evaluate(in *AuditInput, b BoundarySet) *Finding {
	if in == nil || b == nil {
		return nil
	}
	if in.ObjectResource != "pods" || in.Verb != "create" {
		return nil
	}
	if in.ObjectNamespace == "" || len(in.RequestObject) == 0 {
		return nil
	}
	actorTenant := b.TenantOf(in.ObjectNamespace)
	if actorTenant == "" {
		// Pod's namespace not under any boundary → can't decide.
		return nil
	}
	paths := extractHostPaths(in.RequestObject)
	if len(paths) == 0 {
		return nil
	}
	for _, p := range paths {
		ownerTenant := b.HostPathTenantOf(p)
		if ownerTenant == "" || ownerTenant == actorTenant {
			continue
		}
		// Cross-tenant overlap: another tenant claims this path.
		return &Finding{
			Type:     securityv1alpha1.TypeCrossTenantHostPathOverlap,
			Severity: Severity(securityv1alpha1.TypeCrossTenantHostPathOverlap),
			Subject: Subject{
				Kind:      "Pod",
				Name:      in.ObjectName,
				Namespace: in.ObjectNamespace,
				UID:       in.ObjectUID,
			},
			Signals: map[string]string{
				"mount.path":        p,
				"tenant_actor":      actorTenant,
				"tenant_owner_path": ownerTenant,
				"pod.namespace":     in.ObjectNamespace,
			},
		}
	}
	return nil
}

// extractHostPaths decodes the Pod spec JSON minimally to pull
// hostPath.path values from spec.volumes[*]. Skips on parse error
// (the audit log occasionally truncates request bodies).
func extractHostPaths(body []byte) []string {
	var pod struct {
		Spec struct {
			Volumes []struct {
				HostPath *struct {
					Path string `json:"path"`
				} `json:"hostPath,omitempty"`
			} `json:"volumes"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &pod); err != nil {
		return nil
	}
	out := make([]string, 0, len(pod.Spec.Volumes))
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			p := strings.TrimSpace(v.HostPath.Path)
			if p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}
