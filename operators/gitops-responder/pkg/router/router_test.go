// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package router_test

import (
	"testing"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/gitops-responder/pkg/router"
)

func sampleConfig(rules ...securityv1alpha1.RoutingRule) *securityv1alpha1.GitOpsResponderConfigSpec {
	return &securityv1alpha1.GitOpsResponderConfigSpec{
		DefaultProvider: "noop",
		DefaultRepo: securityv1alpha1.GitRepo{
			Provider: "noop", Owner: "ninsun", Repo: "argocd", Branch: "main",
		},
		Routing: rules,
	}
}

func TestRouter_FallsBackToDefault(t *testing.T) {
	r, err := router.New(sampleConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := r.Route("kube-system", nil)
	if got.Repo != "argocd" {
		t.Errorf("Repo = %q, want argocd", got.Repo)
	}
}

func TestRouter_NamespacePatternMatches(t *testing.T) {
	cfg := sampleConfig(
		securityv1alpha1.RoutingRule{
			MatchNamespacePattern: "^prod-.*$",
			Repo: securityv1alpha1.GitRepo{
				Provider: "noop", Owner: "ninsun", Repo: "prod-policies", Branch: "main",
			},
		},
	)
	r, err := router.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := r.Route("prod-payments", nil); got.Repo != "prod-policies" {
		t.Errorf("prod-* should hit prod-policies, got %q", got.Repo)
	}
	if got := r.Route("dev-shared", nil); got.Repo != "argocd" {
		t.Errorf("non-matching ns should fall through to default, got %q", got.Repo)
	}
}

func TestRouter_LabelMatchSubset(t *testing.T) {
	cfg := sampleConfig(
		securityv1alpha1.RoutingRule{
			MatchLabels: map[string]string{"team": "security"},
			Repo: securityv1alpha1.GitRepo{
				Provider: "noop", Owner: "ninsun", Repo: "security-repo", Branch: "main",
			},
		},
	)
	r, err := router.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := r.Route("anything", map[string]string{"team": "security", "env": "prod"})
	if got.Repo != "security-repo" {
		t.Errorf("matching label should hit security-repo, got %q", got.Repo)
	}
	got = r.Route("anything", map[string]string{"team": "platform"})
	if got.Repo != "argocd" {
		t.Errorf("non-matching label should fall through, got %q", got.Repo)
	}
}

func TestRouter_RejectsBadConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  *securityv1alpha1.GitOpsResponderConfigSpec
	}{
		{"nil cfg", nil},
		{"missing defaultProvider", &securityv1alpha1.GitOpsResponderConfigSpec{
			DefaultRepo: securityv1alpha1.GitRepo{Repo: "x"},
		}},
		{"missing defaultRepo", &securityv1alpha1.GitOpsResponderConfigSpec{
			DefaultProvider: "noop",
		}},
		{"bad regex", &securityv1alpha1.GitOpsResponderConfigSpec{
			DefaultProvider: "noop",
			DefaultRepo:     securityv1alpha1.GitRepo{Repo: "x"},
			Routing: []securityv1alpha1.RoutingRule{
				{MatchNamespacePattern: "([invalid", Repo: securityv1alpha1.GitRepo{Repo: "y"}},
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := router.New(tc.cfg); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

func TestSnapshot_AtomicSwap(t *testing.T) {
	s := router.NewSnapshot()
	if s.Current() != nil {
		t.Error("empty snapshot should return nil")
	}
	r1, _ := router.New(sampleConfig())
	s.Set(r1)
	if s.Current() != r1 {
		t.Error("Set/Current didn't round-trip the router")
	}
	s.Set(nil)
	if s.Current() != nil {
		t.Error("Set(nil) didn't clear the snapshot")
	}
}
