// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor

import (
	"testing"

	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

func TestIgnoreMatcher(t *testing.T) {
	m := NewIgnoreMatcher([]securityv1alpha1.WebhookIgnoreRule{
		{APIVersionGlob: "admissionregistration.k8s.io/v1", NameGlobs: []string{"ugallu.*", "cert-manager-*"}},
	})
	for _, tc := range []struct {
		apiVersion string
		name       string
		want       bool
	}{
		{"admissionregistration.k8s.io/v1", "ugallu.frozen-label-restricted", true},
		{"admissionregistration.k8s.io/v1", "cert-manager-mutating", true},
		{"admissionregistration.k8s.io/v1", "kyverno-policy", false},
		{"some.other.api/v1", "ugallu.frozen-label-restricted", false},
	} {
		if got := m.IsIgnored(tc.apiVersion, tc.name); got != tc.want {
			t.Errorf("IsIgnored(%q, %q) = %v, want %v", tc.apiVersion, tc.name, got, tc.want)
		}
	}
}

func TestDebounceCache(t *testing.T) {
	c := newDebounceCache()
	uid := types.UID("u-1")

	emit, first := c.Decide(uid, 50, "h1")
	if !emit || !first {
		t.Errorf("first Decide: emit=%v first=%v, want both true", emit, first)
	}
	emit, first = c.Decide(uid, 50, "h1")
	if emit || first {
		t.Errorf("repeat Decide: emit=%v first=%v, want both false", emit, first)
	}
	emit, first = c.Decide(uid, 70, "h1")
	if !emit || first {
		t.Errorf("score-change Decide: emit=%v first=%v, want emit=true first=false", emit, first)
	}
	emit, first = c.Decide(uid, 70, "h2")
	if !emit || first {
		t.Errorf("hash-change Decide: emit=%v first=%v, want emit=true first=false", emit, first)
	}
	c.Forget(uid)
	emit, first = c.Decide(uid, 70, "h2")
	if !emit || !first {
		t.Errorf("post-forget Decide: emit=%v first=%v, want both true", emit, first)
	}
}
