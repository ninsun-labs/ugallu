// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// CrossTenantSecretAccessDetector flags audit events where an SA in
// one tenant reads/lists/watches Secrets in another tenant's
// namespace, unless the actor SA is in the target tenant's
// ServiceAccountAllowlist (design 21 §T4.1).
type CrossTenantSecretAccessDetector struct{}

// NewCrossTenantSecretAccessDetector returns a ready detector.
func NewCrossTenantSecretAccessDetector() *CrossTenantSecretAccessDetector {
	return &CrossTenantSecretAccessDetector{}
}

// Name returns the detector name (used in metrics labels).
func (d *CrossTenantSecretAccessDetector) Name() string { return "cross_tenant_secret_access" }

// Evaluate runs the heuristic.
func (d *CrossTenantSecretAccessDetector) Evaluate(in *AuditInput, b BoundarySet) *Finding {
	if in == nil || b == nil {
		return nil
	}
	if in.ObjectResource != "secrets" {
		return nil
	}
	if !isReadVerb(in.Verb) {
		return nil
	}
	if in.UserNamespace == "" || in.ObjectNamespace == "" {
		return nil
	}
	actorTenant := b.TenantOf(in.UserNamespace)
	targetTenant := b.TenantOf(in.ObjectNamespace)
	// Only fire when the actor is recognised AND the target is
	// recognised AND they're different tenants.
	if actorTenant == "" || targetTenant == "" || actorTenant == targetTenant {
		return nil
	}
	if b.SAAllowedFor(in.UserUsername, targetTenant) {
		return nil
	}
	return &Finding{
		Type:     securityv1alpha1.TypeCrossTenantSecretAccess,
		Severity: Severity(securityv1alpha1.TypeCrossTenantSecretAccess),
		Subject: Subject{
			Kind:      "Secret",
			Name:      in.ObjectName,
			Namespace: in.ObjectNamespace,
			UID:       in.ObjectUID,
		},
		Signals: map[string]string{
			"actor.username":   in.UserUsername,
			"actor.namespace":  in.UserNamespace,
			"target.name":      in.ObjectName,
			"target.namespace": in.ObjectNamespace,
			"verb":             in.Verb,
			"tenant_actor":     actorTenant,
			"tenant_target":    targetTenant,
		},
	}
}

// isReadVerb returns true for the read-side audit verbs that
// matter for the Secret-access detector.
func isReadVerb(verb string) bool {
	switch verb {
	case "get", "list", "watch":
		return true
	}
	return false
}
