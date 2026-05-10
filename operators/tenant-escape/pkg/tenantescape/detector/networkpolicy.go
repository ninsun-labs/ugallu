// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"encoding/json"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// CrossTenantNetworkPolicyDetector flags NetworkPolicy /
// CiliumNetworkPolicy create events where the policy lives in
// tenant_x but the ingress.from selector targets a namespace owned
// by tenant_y, AND tenant_y is NOT in tenant_x's TrustedNamespaces.
type CrossTenantNetworkPolicyDetector struct{}

// NewCrossTenantNetworkPolicyDetector returns a ready detector.
func NewCrossTenantNetworkPolicyDetector() *CrossTenantNetworkPolicyDetector {
	return &CrossTenantNetworkPolicyDetector{}
}

// Name returns the detector name.
func (d *CrossTenantNetworkPolicyDetector) Name() string { return "cross_tenant_network_policy" }

// Evaluate runs the heuristic.
func (d *CrossTenantNetworkPolicyDetector) Evaluate(in *AuditInput, b BoundarySet) *Finding {
	if in == nil || b == nil {
		return nil
	}
	if in.Verb != "create" && in.Verb != "update" {
		return nil
	}
	if !isNetworkPolicyResource(in.ObjectResource) {
		return nil
	}
	if in.ObjectNamespace == "" || len(in.RequestObject) == 0 {
		return nil
	}
	actorTenant := b.TenantOf(in.ObjectNamespace)
	if actorTenant == "" {
		return nil
	}
	sources := extractNamespaceSelectors(in.RequestObject, in.ObjectResource)
	for _, ns := range sources {
		// We only know namespace when the selector is by exact
		// matchLabels.kubernetes.io/metadata.name. For label-based
		// selectors the operator reconciler lookup happens in the
		// real source layer; pure-logic detector keeps the case
		// list small.
		targetTenant := b.TenantOf(ns)
		if targetTenant == "" || targetTenant == actorTenant {
			continue
		}
		if b.NamespaceTrustedBy(ns, actorTenant) {
			continue
		}
		return &Finding{
			Type:     securityv1alpha1.TypeCrossTenantNetworkPolicy,
			Severity: Severity(securityv1alpha1.TypeCrossTenantNetworkPolicy),
			Subject: Subject{
				Kind:      networkPolicyKind(in.ObjectResource),
				Name:      in.ObjectName,
				Namespace: in.ObjectNamespace,
				UID:       in.ObjectUID,
			},
			Signals: map[string]string{
				"policy.namespace": in.ObjectNamespace,
				"policy.name":      in.ObjectName,
				"target_tenant":    targetTenant,
				"selector_match":   ns,
			},
		}
	}
	return nil
}

// extractNamespaceSelectors pulls every "ingress.from.namespaceSelector
// matchLabels[kubernetes.io/metadata.name]" entry out of the policy
// spec. v1 NetworkPolicy and Cilium policies share enough of the
// shape that a generic JSON decode covers both.
func extractNamespaceSelectors(body []byte, resource string) []string {
	const labelKey = "kubernetes.io/metadata.name"

	switch resource {
	case "networkpolicies":
		var np struct {
			Spec struct {
				Ingress []struct {
					From []struct {
						NamespaceSelector struct {
							MatchLabels map[string]string `json:"matchLabels"`
						} `json:"namespaceSelector,omitempty"`
					} `json:"from"`
				} `json:"ingress"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(body, &np); err != nil {
			return nil
		}
		out := []string{}
		for _, in := range np.Spec.Ingress {
			for _, f := range in.From {
				if v, ok := f.NamespaceSelector.MatchLabels[labelKey]; ok && v != "" {
					out = append(out, v)
				}
			}
		}
		return out
	case "ciliumnetworkpolicies":
		// Cilium has `spec.ingress[*].fromEndpoints[*].matchLabels`
		// where the "ns" magic label is "k8s:io.kubernetes.pod.namespace".
		var cnp struct {
			Spec struct {
				Ingress []struct {
					FromEndpoints []map[string]string `json:"fromEndpoints"`
				} `json:"ingress"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(body, &cnp); err != nil {
			return nil
		}
		out := []string{}
		for _, ig := range cnp.Spec.Ingress {
			for _, ep := range ig.FromEndpoints {
				if v, ok := ep["k8s:io.kubernetes.pod.namespace"]; ok && v != "" {
					out = append(out, v)
				}
			}
		}
		return out
	}
	return nil
}

func isNetworkPolicyResource(r string) bool {
	return r == "networkpolicies" || r == "ciliumnetworkpolicies"
}

func networkPolicyKind(r string) string {
	if r == "ciliumnetworkpolicies" {
		return "CiliumNetworkPolicy"
	}
	return "NetworkPolicy"
}
