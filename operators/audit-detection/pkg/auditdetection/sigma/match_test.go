// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sigma_test

import (
	"strings"
	"testing"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection"
	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection/sigma"
)

func ptr[T any](v T) *T { return &v }

// helper to make a pre-canned audit event for matchers.
func sampleEvent() *auditdetection.AuditEvent {
	return &auditdetection.AuditEvent{
		Verb: "create",
		User: auditdetection.UserInfo{
			Username: "system:serviceaccount:kube-system:bad-bot",
			Groups:   []string{"system:authenticated", "system:serviceaccounts"},
		},
		ObjectRef: &auditdetection.ObjectReference{
			APIGroup:   "rbac.authorization.k8s.io",
			APIVersion: "v1",
			Resource:   "clusterrolebindings",
			Name:       "evil-binding",
		},
		RequestObject: map[string]any{
			"roleRef": map[string]any{"name": "cluster-admin"},
			"subjects": []any{
				map[string]any{"kind": "User", "name": "alice"},
			},
		},
	}
}

// compile builds a CompiledRule from spec. The parameter is value-typed
// to keep test cases as compact struct literals; the hugeParam lint is
// fine for a test helper.
//
//nolint:gocritic // value semantics keep test literals readable
func compile(t *testing.T, spec securityv1alpha1.SigmaRuleSpec) *sigma.CompiledRule {
	t.Helper()
	rule := &securityv1alpha1.SigmaRule{Spec: spec}
	rule.Name = "test"
	r, err := sigma.Compile(rule)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return r
}

func TestCompile_RejectsUnknownType(t *testing.T) {
	rule := &securityv1alpha1.SigmaRule{Spec: securityv1alpha1.SigmaRuleSpec{
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: "TotallyMadeUpType",
			Severity:          securityv1alpha1.SeverityHigh,
		},
	}}
	if _, err := sigma.Compile(rule); err == nil || !strings.Contains(err.Error(), "catalog") {
		t.Errorf("expected catalog rejection, got %v", err)
	}
}

func TestMatch_VerbAnyOf(t *testing.T) {
	r := compile(t, securityv1alpha1.SigmaRuleSpec{
		Match: securityv1alpha1.SigmaMatch{SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{Verb: []string{"create", "update"}}},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityCritical,
		},
	})
	ev := sampleEvent()
	if !r.Match(ev) {
		t.Error("expected match (verb=create in [create update])")
	}
	ev.Verb = "delete"
	if r.Match(ev) {
		t.Error("expected no match (verb=delete not in [create update])")
	}
}

func TestMatch_ObjectRefAndUserAnded(t *testing.T) {
	r := compile(t, securityv1alpha1.SigmaRuleSpec{
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{
				ObjectRef: &securityv1alpha1.ObjectRefMatch{
					Resource: []string{"clusterrolebindings"},
				},
				User: &securityv1alpha1.UserMatch{
					UsernameGlob: []string{"system:serviceaccount:kube-system:*"},
				},
			},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityCritical,
		},
	})
	if !r.Match(sampleEvent()) {
		t.Error("expected match on ObjectRef + User AND")
	}
	ev := sampleEvent()
	ev.User.Username = "alice@corp"
	if r.Match(ev) {
		t.Error("expected no match — user glob fails")
	}
}

func TestMatch_NameGlob(t *testing.T) {
	r := compile(t, securityv1alpha1.SigmaRuleSpec{
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{
				ObjectRef: &securityv1alpha1.ObjectRefMatch{NameGlob: []string{"evil-*"}},
			},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityCritical,
		},
	})
	if !r.Match(sampleEvent()) {
		t.Error("expected nameGlob match")
	}
}

func TestMatch_RequestObjectGlob(t *testing.T) {
	r := compile(t, securityv1alpha1.SigmaRuleSpec{
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{
				RequestObjectGlob: []securityv1alpha1.GlobMatch{
					{JSONPath: "$.roleRef.name", Patterns: []string{"cluster-admin"}},
				},
			},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityCritical,
		},
	})
	if !r.Match(sampleEvent()) {
		t.Error("expected JSONPath glob match on roleRef.name=cluster-admin")
	}
}

func TestMatch_RequestObjectGlobWildcardArray(t *testing.T) {
	r := compile(t, securityv1alpha1.SigmaRuleSpec{
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{
				RequestObjectGlob: []securityv1alpha1.GlobMatch{
					{JSONPath: "$.subjects[*].name", Patterns: []string{"alice"}},
				},
			},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityCritical,
		},
	})
	if !r.Match(sampleEvent()) {
		t.Error("expected wildcard array JSONPath match")
	}
}

func TestMatch_AnyOfOR(t *testing.T) {
	r := compile(t, securityv1alpha1.SigmaRuleSpec{
		Match: securityv1alpha1.SigmaMatch{
			AnyOf: []securityv1alpha1.SigmaMatchLeaf{
				{Verb: []string{"delete"}},
				{Verb: []string{"create"}},
			},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityCritical,
		},
	})
	if !r.Match(sampleEvent()) {
		t.Error("expected anyOf to match (verb=create matches the second branch)")
	}
}

func TestMatch_NotNegates(t *testing.T) {
	r := compile(t, securityv1alpha1.SigmaRuleSpec{
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{
				ObjectRef: &securityv1alpha1.ObjectRefMatch{Resource: []string{"clusterrolebindings"}},
			},
			Not: &securityv1alpha1.SigmaMatchLeaf{
				User: &securityv1alpha1.UserMatch{UsernameGlob: []string{"system:serviceaccount:kube-system:*"}},
			},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityCritical,
		},
	})
	// sampleEvent's user matches the glob → Not should fire → overall match false
	if r.Match(sampleEvent()) {
		t.Error("expected Not to suppress match")
	}
	// Switch user → Not branch fails → overall match true
	ev := sampleEvent()
	ev.User.Username = "alice@corp"
	if !r.Match(ev) {
		t.Error("expected match when Not branch doesn't fire")
	}
}

func TestGlob_BasicWildcards(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"cluster-*", "cluster-admin", true},
		{"cluster-*", "admin", false},
		{"*-admin", "cluster-admin", true},
		{"*-admin", "view", false},
		{"a*b*c", "axxbyyyc", true},
		{"a*b*c", "axxxxxc", false},
		{"???", "abc", true},
		{"???", "abcd", false},
		{"*", "anything-goes", true},
		{"foo", "foo", true},
		{"foo", "bar", false},
	}
	for _, tc := range cases {
		if got := sigma.Glob(tc.pattern, tc.s); got != tc.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}

func TestValidatePattern_RejectsTooManyWildcards(t *testing.T) {
	if err := sigma.ValidatePattern(strings.Repeat("*", 9)); err == nil {
		t.Error("expected rejection of >MaxGlobWildcards stars")
	}
	if err := sigma.ValidatePattern(strings.Repeat("*", sigma.MaxGlobWildcards)); err != nil {
		t.Errorf("expected accept of MaxGlobWildcards stars, got %v", err)
	}
}

func TestCompileJSONPath_RejectsBadInputs(t *testing.T) {
	bad := []string{
		"",
		"a.b",          // missing $
		"$.",           // empty field after .
		"$..a",         // recursive descent unsupported
		"$.a[",         // missing ]
		"$.a[?@.x==1]", // filter unsupported
	}
	for _, expr := range bad {
		// Roundtrip via Compile to exercise the public path.
		spec := securityv1alpha1.SigmaRuleSpec{
			Emit:  securityv1alpha1.SigmaEmit{SecurityEventType: securityv1alpha1.TypeClusterAdminGranted, Severity: securityv1alpha1.SeverityHigh},
			Match: securityv1alpha1.SigmaMatch{SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{RequestObjectGlob: []securityv1alpha1.GlobMatch{{JSONPath: expr, Patterns: []string{"*"}}}}},
		}
		rule := &securityv1alpha1.SigmaRule{Spec: spec}
		if _, err := sigma.Compile(rule); err == nil {
			t.Errorf("expected rejection of JSONPath %q", expr)
		}
	}
}

func TestMatch_DisabledNoOpAfterCompile(t *testing.T) {
	// Even Enabled=false rules should compile cleanly; the engine
	// (commit C) decides whether to run them. The Match itself
	// should still work — Enabled is policy, not predicate.
	r := compile(t, securityv1alpha1.SigmaRuleSpec{
		Enabled: false,
		Match:   securityv1alpha1.SigmaMatch{SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{Verb: []string{"create"}}},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityHigh,
		},
	})
	if !r.Match(sampleEvent()) {
		t.Error("compiled disabled rule should still evaluate")
	}
}

// avoid unused import warning under !linux test runs
var _ = ptr[string]
