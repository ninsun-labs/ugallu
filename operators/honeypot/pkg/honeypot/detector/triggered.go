// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/index"
)

// HoneypotTriggeredDetector flags every audit event whose target is
// in the decoy Index, except when the actor SA is in the owning
// HoneypotConfig's allowlist (e.g. backup operator) or when the
// verb is read-side AND the CR has EmitOnRead=false.
//
// Severity: critical - there is no legitimate reason for an actor
// to interact with a decoy resource.
type HoneypotTriggeredDetector struct {
	idx *index.Index
}

// NewHoneypotTriggeredDetector returns a ready detector.
func NewHoneypotTriggeredDetector(idx *index.Index) *HoneypotTriggeredDetector {
	return &HoneypotTriggeredDetector{idx: idx}
}

// Name returns the detector name.
func (d *HoneypotTriggeredDetector) Name() string { return "honeypot_triggered" }

// Evaluate runs the heuristic.
func (d *HoneypotTriggeredDetector) Evaluate(in *AuditInput) *Finding {
	if in == nil || d.idx == nil {
		return nil
	}
	if in.ObjectName == "" || in.ObjectResource == "" {
		return nil
	}

	// Prefer UID-based lookup (immune to name reuse races); fall
	// back to (resource, namespace, name) when the audit event
	// omits objectRef.uid (cluster-scoped resources, list/watch
	// verbs).
	entry := d.idx.LookupUID(in.ObjectUID)
	if entry == nil {
		entry = d.idx.Lookup(in.ObjectResource, in.ObjectNamespace, in.ObjectName)
	}
	if entry == nil {
		return nil
	}

	if !entry.EmitOnRead && isReadVerb(in.Verb) {
		return nil
	}
	if d.idx.IsAllowedActor(entry.HoneypotConfig, in.UserUsername) {
		return nil
	}

	return &Finding{
		Type:     securityv1alpha1.TypeHoneypotTriggered,
		Severity: Severity(securityv1alpha1.TypeHoneypotTriggered),
		Subject: Subject{
			Kind:      kindFromResource(in.ObjectResource),
			Name:      in.ObjectName,
			Namespace: in.ObjectNamespace,
			UID:       in.ObjectUID,
		},
		Signals: map[string]string{
			"actor.username":   in.UserUsername,
			"target.resource":  in.ObjectResource,
			"target.namespace": in.ObjectNamespace,
			"target.name":      in.ObjectName,
			"verb":             in.Verb,
			"honeypot.config":  entry.HoneypotConfig,
		},
	}
}

func isReadVerb(verb string) bool {
	switch verb {
	case "get", "list", "watch":
		return true
	}
	return false
}

func kindFromResource(r string) string {
	switch r {
	case "secrets":
		return "Secret"
	case "serviceaccounts":
		return "ServiceAccount"
	case "configmaps":
		return "ConfigMap"
	case "namespaces":
		return "Namespace"
	}
	return "External"
}
