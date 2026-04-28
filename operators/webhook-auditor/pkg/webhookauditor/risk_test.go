// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor

import (
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// helper to build a single-webhook MWC with the most common knobs.
type tWebhook struct {
	failurePolicy admissionregistrationv1.FailurePolicyType
	sideEffects   admissionregistrationv1.SideEffectClass
	resources     []string
	caBundle      []byte
	objectSel     bool
	namespaceSel  bool
	reinvoc       *admissionregistrationv1.ReinvocationPolicyType
}

func mkMWC(t *testing.T, hooks ...tWebhook) *admissionregistrationv1.MutatingWebhookConfiguration {
	t.Helper()
	m := &admissionregistrationv1.MutatingWebhookConfiguration{}
	for i := range hooks {
		h := hooks[i]
		w := admissionregistrationv1.MutatingWebhook{
			Name: "h.example",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				CABundle: h.caBundle,
			},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Rule: admissionregistrationv1.Rule{
					Resources: h.resources,
				},
			}},
			ReinvocationPolicy: h.reinvoc,
		}
		if h.failurePolicy != "" {
			fp := h.failurePolicy
			w.FailurePolicy = &fp
		}
		if h.sideEffects != "" {
			se := h.sideEffects
			w.SideEffects = &se
		}
		if h.objectSel {
			w.ObjectSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}}
		}
		if h.namespaceSel {
			w.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "y"}}
		}
		m.Webhooks = append(m.Webhooks, w)
	}
	return m
}

func TestEvaluator_FailurePolicyIgnoreOnCriticalAPI(t *testing.T) {
	e := NewEvaluator(EvaluatorOptions{})
	mwc := mkMWC(t, tWebhook{
		failurePolicy: admissionregistrationv1.Ignore,
		sideEffects:   admissionregistrationv1.SideEffectClassNone,
		resources:     []string{"secrets"},
		caBundle:      generateSelfSignedPEM(t, "trusted-ca"),
	})
	// Trust the bundle to isolate the failure-policy contribution.
	e = NewEvaluator(EvaluatorOptions{TrustedSubjectDNs: []string{"CN=trusted-ca"}})
	br := e.ScoreMutating(mwc)

	if !br.Has(SubScoreFailurePolicy) {
		t.Errorf("expected failure_policy sub-score, breakdown=%v", br.Breakdown)
	}
	if !br.Has(SubScoreCriticalAPI) {
		t.Errorf("expected critical_api sub-score, breakdown=%v", br.Breakdown)
	}
	if br.Has(SubScoreCAUntrusted) {
		t.Errorf("ca_untrusted should be off when caBundle DN is in trust list")
	}
}

func TestEvaluator_NoSelectorOnCriticalAPI(t *testing.T) {
	e := NewEvaluator(EvaluatorOptions{TrustedSubjectDNs: []string{"CN=trusted-ca"}})
	mwc := mkMWC(t, tWebhook{
		failurePolicy: admissionregistrationv1.Fail,
		sideEffects:   admissionregistrationv1.SideEffectClassNone,
		resources:     []string{"clusterrolebindings"},
		caBundle:      generateSelfSignedPEM(t, "trusted-ca"),
		// objectSel and namespaceSel intentionally false → match all
	})
	br := e.ScoreMutating(mwc)
	if !br.Has(SubScoreNoSelector) {
		t.Errorf("expected no_selector sub-score, breakdown=%v", br.Breakdown)
	}
	if br.Has(SubScoreFailurePolicy) {
		t.Errorf("failure_policy should be off when failurePolicy=Fail")
	}
}

func TestEvaluator_CAUntrusted_EmptyBundle(t *testing.T) {
	e := NewEvaluator(EvaluatorOptions{})
	mwc := mkMWC(t, tWebhook{
		failurePolicy: admissionregistrationv1.Fail,
		sideEffects:   admissionregistrationv1.SideEffectClassNone,
		resources:     []string{"pods"},
		caBundle:      nil, // empty
	})
	br := e.ScoreMutating(mwc)
	if !br.Has(SubScoreCAUntrusted) {
		t.Errorf("expected ca_untrusted on empty caBundle, breakdown=%v", br.Breakdown)
	}
}

func TestEvaluator_CAUntrusted_NotInWhitelist(t *testing.T) {
	e := NewEvaluator(EvaluatorOptions{TrustedSubjectDNs: []string{"CN=trusted-ca"}})
	mwc := mkMWC(t, tWebhook{
		failurePolicy: admissionregistrationv1.Fail,
		sideEffects:   admissionregistrationv1.SideEffectClassNone,
		resources:     []string{"pods"},
		caBundle:      generateSelfSignedPEM(t, "evil-issuer"),
	})
	br := e.ScoreMutating(mwc)
	if !br.Has(SubScoreCAUntrusted) {
		t.Errorf("expected ca_untrusted on DN not in whitelist, breakdown=%v", br.Breakdown)
	}
}

func TestEvaluator_SideEffectsUnknown(t *testing.T) {
	e := NewEvaluator(EvaluatorOptions{TrustedSubjectDNs: []string{"CN=trusted-ca"}})
	mwc := mkMWC(t, tWebhook{
		failurePolicy: admissionregistrationv1.Fail,
		sideEffects:   admissionregistrationv1.SideEffectClassUnknown,
		resources:     []string{"pods"},
		caBundle:      generateSelfSignedPEM(t, "trusted-ca"),
	})
	br := e.ScoreMutating(mwc)
	if !br.Has(SubScoreSideEffects) {
		t.Errorf("expected side_effects sub-score, breakdown=%v", br.Breakdown)
	}
}

func TestEvaluator_ReinvocationIfNeededAmplifiesSideEffects(t *testing.T) {
	e := NewEvaluator(EvaluatorOptions{TrustedSubjectDNs: []string{"CN=trusted-ca"}})
	rp := admissionregistrationv1.IfNeededReinvocationPolicy
	mwc := mkMWC(t, tWebhook{
		failurePolicy: admissionregistrationv1.Fail,
		sideEffects:   admissionregistrationv1.SideEffectClassUnknown,
		resources:     []string{"pods"},
		caBundle:      generateSelfSignedPEM(t, "trusted-ca"),
		reinvoc:       &rp,
	})
	br := e.ScoreMutating(mwc)
	if !br.Has(SubScoreReinvocationIfNeeded) {
		t.Errorf("expected reinvocation_if_needed, breakdown=%v", br.Breakdown)
	}
}

func TestEvaluator_TotalCappedAt100(t *testing.T) {
	e := NewEvaluator(EvaluatorOptions{})
	rp := admissionregistrationv1.IfNeededReinvocationPolicy
	mwc := mkMWC(t, tWebhook{
		failurePolicy: admissionregistrationv1.Ignore,
		sideEffects:   admissionregistrationv1.SideEffectClassUnknown,
		resources:     []string{"secrets"}, // critical AND triggers no-selector + critical_api
		caBundle:      nil,                  // ca_untrusted
		reinvoc:       &rp,
		// objectSel, namespaceSel default false → no_selector triggers
	})
	br := e.ScoreMutating(mwc)
	// Sum of all weights: 30+15+20+15+10+10 = 100. Cap test: should hit 100.
	if br.Total != 100 {
		t.Errorf("total = %d, want 100 (full sub-score sweep)", br.Total)
	}
}

func TestSeverityFor(t *testing.T) {
	for _, tc := range []struct {
		score int
		want  securityv1alpha1.Severity
	}{
		{100, securityv1alpha1.SeverityCritical},
		{90, securityv1alpha1.SeverityCritical},
		{85, securityv1alpha1.SeverityCritical},
		{84, securityv1alpha1.SeverityHigh},
		{60, securityv1alpha1.SeverityHigh},
		{59, securityv1alpha1.SeverityMedium},
		{30, securityv1alpha1.SeverityMedium},
		{29, securityv1alpha1.SeverityLow},
		{0, securityv1alpha1.SeverityLow},
	} {
		if got := SeverityFor(tc.score); got != tc.want {
			t.Errorf("SeverityFor(%d) = %q, want %q", tc.score, got, tc.want)
		}
	}
}
