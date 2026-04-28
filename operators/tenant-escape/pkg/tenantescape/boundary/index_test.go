// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package boundary

import (
	"sort"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

func tb(name string, matched []string, opts ...func(*securityv1alpha1.TenantBoundary)) securityv1alpha1.TenantBoundary {
	out := securityv1alpha1.TenantBoundary{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     securityv1alpha1.TenantBoundaryStatus{MatchedNamespaces: matched},
	}
	for _, opt := range opts {
		opt(&out)
	}
	return out
}

func withHostPath(allow ...string) func(*securityv1alpha1.TenantBoundary) {
	return func(b *securityv1alpha1.TenantBoundary) {
		b.Spec.HostPathPolicy.Allow = allow
	}
}

func withSAAllowlist(sa ...string) func(*securityv1alpha1.TenantBoundary) {
	return func(b *securityv1alpha1.TenantBoundary) {
		b.Spec.ServiceAccountAllowlist = sa
	}
}

func withTrusted(ns ...string) func(*securityv1alpha1.TenantBoundary) {
	return func(b *securityv1alpha1.TenantBoundary) {
		b.Spec.TrustedNamespaces = ns
	}
}

func TestRefresh_TenantOf(t *testing.T) {
	idx := NewIndex()
	idx.Refresh([]securityv1alpha1.TenantBoundary{
		tb("team-a", []string{"team-a", "team-a-stage"}),
		tb("team-b", []string{"team-b"}),
	})
	if got := idx.TenantOf("team-a"); got != "team-a" {
		t.Errorf("TenantOf(team-a) = %q, want team-a", got)
	}
	if got := idx.TenantOf("team-b"); got != "team-b" {
		t.Errorf("TenantOf(team-b) = %q, want team-b", got)
	}
	if got := idx.TenantOf("kube-system"); got != "" {
		t.Errorf("TenantOf(kube-system) = %q, want empty", got)
	}
}

func TestRefresh_OverlappingNamespacesReported(t *testing.T) {
	idx := NewIndex()
	overlap, _ := idx.Refresh([]securityv1alpha1.TenantBoundary{
		tb("team-a", []string{"shared-ns"}),
		tb("team-b", []string{"shared-ns"}),
	})
	if len(overlap) != 1 || overlap[0] != "shared-ns" {
		t.Errorf("overlap = %v, want [shared-ns]", overlap)
	}
	// Lexicographic min wins → team-a.
	if got := idx.TenantOf("shared-ns"); got != "team-a" {
		t.Errorf("TenantOf(shared-ns) = %q, want team-a (lex min)", got)
	}
}

func TestRefresh_EmptyBoundaryReported(t *testing.T) {
	idx := NewIndex()
	_, empty := idx.Refresh([]securityv1alpha1.TenantBoundary{
		tb("team-a", []string{"team-a"}),
		tb("team-b", nil),
	})
	if len(empty) != 1 || empty[0] != "team-b" {
		t.Errorf("empty = %v, want [team-b]", empty)
	}
}

func TestHostPathTenantOf_LongestPrefixWins(t *testing.T) {
	idx := NewIndex()
	idx.Refresh([]securityv1alpha1.TenantBoundary{
		tb("system", []string{"kube-system"}, withHostPath("/var/lib/")),
		tb("team-a", []string{"team-a"}, withHostPath("/var/lib/team-a/")),
	})
	if got := idx.HostPathTenantOf("/var/lib/team-a/secrets"); got != "team-a" {
		t.Errorf("longest-prefix lookup = %q, want team-a", got)
	}
	if got := idx.HostPathTenantOf("/var/lib/other"); got != "system" {
		t.Errorf("fallback prefix = %q, want system", got)
	}
	if got := idx.HostPathTenantOf("/etc/passwd"); got != "" {
		t.Errorf("non-matching path = %q, want empty", got)
	}
}

func TestSAAllowedFor(t *testing.T) {
	idx := NewIndex()
	idx.Refresh([]securityv1alpha1.TenantBoundary{
		tb("team-a", []string{"team-a"}, withSAAllowlist("system:serviceaccount:kube-system:cluster-controller")),
	})
	if !idx.SAAllowedFor("system:serviceaccount:kube-system:cluster-controller", "team-a") {
		t.Errorf("controller SA must be allowlisted")
	}
	if idx.SAAllowedFor("system:serviceaccount:team-b:bot", "team-a") {
		t.Errorf("non-allowlisted SA must not be allowed")
	}
}

func TestNamespaceTrustedBy(t *testing.T) {
	idx := NewIndex()
	idx.Refresh([]securityv1alpha1.TenantBoundary{
		tb("team-a", []string{"team-a"}, withTrusted("monitoring", "ingress")),
	})
	if !idx.NamespaceTrustedBy("monitoring", "team-a") {
		t.Errorf("monitoring must be trusted by team-a")
	}
	if idx.NamespaceTrustedBy("team-b", "team-a") {
		t.Errorf("team-b must not be trusted")
	}
}

func TestTenants_Sorted(t *testing.T) {
	idx := NewIndex()
	idx.Refresh([]securityv1alpha1.TenantBoundary{
		tb("zoo", []string{"zoo"}),
		tb("alpha", []string{"alpha"}),
		tb("middle", []string{"middle"}),
	})
	got := idx.Tenants()
	sort.Strings(got)
	want := []string{"alpha", "middle", "zoo"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
