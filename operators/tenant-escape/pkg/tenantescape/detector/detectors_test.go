// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"strings"
	"testing"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// fakeBoundarySet is a tiny in-memory BoundarySet for tests.
type fakeBoundarySet struct {
	nsToTenant       map[string]string
	hostPathTenant   map[string]string // exact-prefix → tenant
	saAllowed        map[string]map[string]bool
	namespaceTrusted map[string]map[string]bool
}

func newFakeBoundary() *fakeBoundarySet {
	return &fakeBoundarySet{
		nsToTenant:       map[string]string{},
		hostPathTenant:   map[string]string{},
		saAllowed:        map[string]map[string]bool{},
		namespaceTrusted: map[string]map[string]bool{},
	}
}

func (f *fakeBoundarySet) TenantOf(ns string) string { return f.nsToTenant[ns] }

func (f *fakeBoundarySet) HostPathTenantOf(path string) string {
	for prefix, tenant := range f.hostPathTenant {
		if hasPrefix(path, prefix) {
			return tenant
		}
	}
	return ""
}

func (f *fakeBoundarySet) SAAllowedFor(actorSA, targetTenant string) bool {
	return f.saAllowed[targetTenant][actorSA]
}

func (f *fakeBoundarySet) NamespaceTrustedBy(sourceNS, targetTenant string) bool {
	return f.namespaceTrusted[targetTenant][sourceNS]
}

func hasPrefix(s, prefix string) bool { return strings.HasPrefix(s, prefix) }

// --- Secret access ---------------------------------------------------

func TestCrossTenantSecretAccess_Fires(t *testing.T) {
	b := newFakeBoundary()
	b.nsToTenant["team-a"] = "team-a"
	b.nsToTenant["team-b"] = "team-b"

	in := &AuditInput{
		Verb:            "get",
		UserUsername:    "system:serviceaccount:team-a:bot",
		UserNamespace:   "team-a",
		ObjectResource:  "secrets",
		ObjectNamespace: "team-b",
		ObjectName:      "shared-creds",
	}
	got := NewCrossTenantSecretAccessDetector().Evaluate(in, b)
	if !got.Has() {
		t.Fatalf("expected fire, got none")
	}
	if got.Type != securityv1alpha1.TypeCrossTenantSecretAccess {
		t.Errorf("Type = %q, want CrossTenantSecretAccess", got.Type)
	}
}

func TestCrossTenantSecretAccess_AllowlistedSA(t *testing.T) {
	b := newFakeBoundary()
	b.nsToTenant["team-a"] = "team-a"
	b.nsToTenant["team-b"] = "team-b"
	b.saAllowed["team-b"] = map[string]bool{"system:serviceaccount:kube-system:cluster-controller": true}

	in := &AuditInput{
		Verb:            "list",
		UserUsername:    "system:serviceaccount:kube-system:cluster-controller",
		UserNamespace:   "team-a", // pretending the controller's caller namespace
		ObjectResource:  "secrets",
		ObjectNamespace: "team-b",
	}
	got := NewCrossTenantSecretAccessDetector().Evaluate(in, b)
	if got.Has() {
		t.Errorf("allowlisted SA should not fire: %+v", got)
	}
}

func TestCrossTenantSecretAccess_SameTenantSkips(t *testing.T) {
	b := newFakeBoundary()
	b.nsToTenant["team-a"] = "team-a"
	b.nsToTenant["team-a-staging"] = "team-a"

	in := &AuditInput{
		Verb:            "get",
		UserNamespace:   "team-a",
		ObjectResource:  "secrets",
		ObjectNamespace: "team-a-staging",
	}
	if NewCrossTenantSecretAccessDetector().Evaluate(in, b).Has() {
		t.Errorf("same-tenant access should not fire")
	}
}

// --- HostPath overlap ------------------------------------------------

func TestCrossTenantHostPathOverlap_Fires(t *testing.T) {
	b := newFakeBoundary()
	b.nsToTenant["team-a"] = "team-a"
	b.hostPathTenant["/var/lib/team-b/"] = "team-b"

	body := `{"spec":{"volumes":[{"hostPath":{"path":"/var/lib/team-b/secrets"}}]}}`
	in := &AuditInput{
		Verb:            "create",
		ObjectResource:  "pods",
		ObjectNamespace: "team-a",
		ObjectName:      "evil-pod",
		RequestObject:   []byte(body),
	}
	got := NewCrossTenantHostPathOverlapDetector().Evaluate(in, b)
	if !got.Has() {
		t.Fatalf("expected fire on cross-tenant hostPath, got none")
	}
	if got.Severity != string(securityv1alpha1.SeverityCritical) {
		t.Errorf("severity = %q, want critical", got.Severity)
	}
}

func TestCrossTenantHostPathOverlap_OwnPathSkips(t *testing.T) {
	b := newFakeBoundary()
	b.nsToTenant["team-a"] = "team-a"
	b.hostPathTenant["/var/lib/team-a/"] = "team-a"

	body := `{"spec":{"volumes":[{"hostPath":{"path":"/var/lib/team-a/data"}}]}}`
	in := &AuditInput{
		Verb:            "create",
		ObjectResource:  "pods",
		ObjectNamespace: "team-a",
		RequestObject:   []byte(body),
	}
	if NewCrossTenantHostPathOverlapDetector().Evaluate(in, b).Has() {
		t.Errorf("own-tenant hostPath should not fire")
	}
}

// --- NetworkPolicy ---------------------------------------------------

func TestCrossTenantNetworkPolicy_Fires(t *testing.T) {
	b := newFakeBoundary()
	b.nsToTenant["team-a"] = "team-a"
	b.nsToTenant["team-b"] = "team-b"

	body := `{"spec":{"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"team-b"}}}]}]}}`
	in := &AuditInput{
		Verb:            "create",
		ObjectResource:  "networkpolicies",
		ObjectNamespace: "team-a",
		ObjectName:      "open-ingress",
		RequestObject:   []byte(body),
	}
	got := NewCrossTenantNetworkPolicyDetector().Evaluate(in, b)
	if !got.Has() {
		t.Fatalf("expected fire on cross-tenant NetworkPolicy")
	}
	if got.Type != securityv1alpha1.TypeCrossTenantNetworkPolicy {
		t.Errorf("Type = %q", got.Type)
	}
}

func TestCrossTenantNetworkPolicy_TrustedNamespaceSkips(t *testing.T) {
	b := newFakeBoundary()
	b.nsToTenant["team-a"] = "team-a"
	b.nsToTenant["monitoring"] = "monitoring"
	b.namespaceTrusted["team-a"] = map[string]bool{"monitoring": true}

	body := `{"spec":{"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"monitoring"}}}]}]}}`
	in := &AuditInput{
		Verb:            "create",
		ObjectResource:  "networkpolicies",
		ObjectNamespace: "team-a",
		RequestObject:   []byte(body),
	}
	if NewCrossTenantNetworkPolicyDetector().Evaluate(in, b).Has() {
		t.Errorf("trusted-namespace ingress should not fire")
	}
}

// --- Exec ------------------------------------------------------------

func TestCrossTenantExec_Fires(t *testing.T) {
	b := newFakeBoundary()
	b.nsToTenant["team-a"] = "team-a"
	b.nsToTenant["team-b"] = "team-b"

	in := &ExecInput{
		ExecutorPodNamespace: "team-a",
		ExecutorUsername:     "system:serviceaccount:team-a:bot",
		TargetPodNamespace:   "team-b",
		TargetPodName:        "victim",
		Command:              "/bin/sh",
	}
	got := NewCrossTenantExecDetector().Evaluate(in, b)
	if !got.Has() {
		t.Fatalf("expected fire on cross-tenant exec")
	}
	if got.Severity != string(securityv1alpha1.SeverityCritical) {
		t.Errorf("severity = %q, want critical", got.Severity)
	}
}

func TestCrossTenantExec_AllowlistedSkips(t *testing.T) {
	b := newFakeBoundary()
	b.nsToTenant["kube-system"] = "kube-system"
	b.nsToTenant["team-b"] = "team-b"
	b.saAllowed["team-b"] = map[string]bool{"system:serviceaccount:kube-system:debug-bot": true}

	in := &ExecInput{
		ExecutorPodNamespace: "kube-system",
		ExecutorUsername:     "system:serviceaccount:kube-system:debug-bot",
		TargetPodNamespace:   "team-b",
	}
	if NewCrossTenantExecDetector().Evaluate(in, b).Has() {
		t.Errorf("allowlisted SA should not fire")
	}
}

func TestCrossTenantExec_SameNamespaceSkips(t *testing.T) {
	b := newFakeBoundary()
	b.nsToTenant["team-a"] = "team-a"

	in := &ExecInput{
		ExecutorPodNamespace: "team-a",
		TargetPodNamespace:   "team-a",
	}
	if NewCrossTenantExecDetector().Evaluate(in, b).Has() {
		t.Errorf("same-namespace exec should not fire")
	}
}
