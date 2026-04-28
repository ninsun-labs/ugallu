// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// CriticalAPIResources is the set of resource names whose admission
// path is high-impact (credentials material). A webhook that touches
// these gates the platform's authn/authz layer; failurePolicy=Ignore
// or unscoped match on these resources is the heart of the risk
// score (design 21 §W3).
var CriticalAPIResources = map[string]struct{}{
	"secrets":              {},
	"serviceaccounts":      {},
	"tokenreviews":         {},
	"subjectaccessreviews": {},
	"clusterroles":         {},
	"clusterrolebindings":  {},
	"roles":                {},
	"rolebindings":         {},
}

// SubScoreWeights pins design 21 §W3 weights as code. The order in
// the map literal is the order they're applied in Score(); breakdown
// keys land on the SE Signals so a dashboard can show the same
// breakdown as the design.
const (
	WeightFailurePolicy        = 30
	WeightSideEffects          = 15
	WeightCAUntrusted          = 20
	WeightNoSelector           = 15
	WeightCriticalAPI          = 10
	WeightReinvocationIfNeeded = 10
)

// RiskBreakdown is the per-sub-score result. Total is the sum of
// triggered sub-scores, capped at 100. Breakdown carries each score
// individually for SE Signals.
type RiskBreakdown struct {
	Total     int
	Breakdown map[string]int
}

// Has reports whether sub-score key was triggered (non-zero weight).
// Convenient for the per-component SE emit decisions in §W5.
func (b RiskBreakdown) Has(key string) bool {
	return b.Breakdown[key] > 0
}

// SubScoreKeys are the canonical names exported as SE Signals. The
// admin-facing dashboard groups by these.
const (
	SubScoreFailurePolicy        = "failure_policy"
	SubScoreSideEffects          = "side_effects"
	SubScoreCAUntrusted          = "ca_untrusted"
	SubScoreNoSelector           = "no_selector"
	SubScoreCriticalAPI          = "critical_api"
	SubScoreReinvocationIfNeeded = "reinvocation_if_needed"
)

// EvaluatorOptions configures Evaluator. See design 21 §W3-W4.
type EvaluatorOptions struct {
	// TrustedSubjectDNs is the canonical RFC 4514 DN allowlist for
	// caBundle CAs. Pre-canonicalised at construction; matching is
	// O(1) per webhook.
	TrustedSubjectDNs []string //nolint:revive // DN is X.509 Distinguished Name
}

// Evaluator computes a deterministic RiskBreakdown for an admission
// webhook configuration. Stateless across calls — safe for concurrent
// use.
type Evaluator struct {
	trusted map[string]struct{}
}

// NewEvaluator returns a ready evaluator. trusted DNs are
// canonicalised once.
func NewEvaluator(opts EvaluatorOptions) *Evaluator {
	canon := make(map[string]struct{}, len(opts.TrustedSubjectDNs))
	for _, dn := range opts.TrustedSubjectDNs {
		canon[CanonicalDN(dn)] = struct{}{}
	}
	return &Evaluator{trusted: canon}
}

// ScoreMutating evaluates a MutatingWebhookConfiguration. The result
// is the union of every webhooks[i] sub-score (max-weight per
// sub-score, not sum across webhooks). Two webhooks both triggering
// "failure_policy" still count once: the score is about the policy's
// posture, not its multiplicity.
func (e *Evaluator) ScoreMutating(mwc *admissionregistrationv1.MutatingWebhookConfiguration) RiskBreakdown {
	hooks := make([]webhookView, 0, len(mwc.Webhooks))
	for i := range mwc.Webhooks {
		hooks = append(hooks, fromMutating(&mwc.Webhooks[i]))
	}
	return e.score(hooks)
}

// ScoreValidating evaluates a ValidatingWebhookConfiguration the
// same way as ScoreMutating but on the validating shape.
func (e *Evaluator) ScoreValidating(vwc *admissionregistrationv1.ValidatingWebhookConfiguration) RiskBreakdown {
	hooks := make([]webhookView, 0, len(vwc.Webhooks))
	for i := range vwc.Webhooks {
		hooks = append(hooks, fromValidating(&vwc.Webhooks[i]))
	}
	return e.score(hooks)
}

// SeverityFor maps a RiskBreakdown to a SecurityEvent severity hint.
// The mapping is intentionally coarse: critical at ≥85, high at the
// design threshold (≥60), medium below. Per-sub-score SEs override.
func SeverityFor(total int) securityv1alpha1.Severity {
	switch {
	case total >= 85:
		return securityv1alpha1.SeverityCritical
	case total >= 60:
		return securityv1alpha1.SeverityHigh
	case total >= 30:
		return securityv1alpha1.SeverityMedium
	default:
		return securityv1alpha1.SeverityLow
	}
}

// --- internals -------------------------------------------------------

// webhookView abstracts over the mutating/validating shapes (their
// types share fields but are not identical Go types).
type webhookView struct {
	failurePolicy admissionregistrationv1.FailurePolicyType
	sideEffects   admissionregistrationv1.SideEffectClass
	rules         []admissionregistrationv1.RuleWithOperations
	caBundle      []byte
	objectSel     bool // non-empty selector
	namespaceSel  bool
	reinvocation  *admissionregistrationv1.ReinvocationPolicyType
}

func fromMutating(w *admissionregistrationv1.MutatingWebhook) webhookView {
	v := webhookView{
		rules:        w.Rules,
		caBundle:     w.ClientConfig.CABundle,
		reinvocation: w.ReinvocationPolicy,
	}
	if w.FailurePolicy != nil {
		v.failurePolicy = *w.FailurePolicy
	}
	if w.SideEffects != nil {
		v.sideEffects = *w.SideEffects
	}
	v.objectSel = !isEmptyLabelSelector(w.ObjectSelector)
	v.namespaceSel = !isEmptyLabelSelector(w.NamespaceSelector)
	return v
}

func fromValidating(w *admissionregistrationv1.ValidatingWebhook) webhookView {
	v := webhookView{
		rules:    w.Rules,
		caBundle: w.ClientConfig.CABundle,
		// validating webhooks have no reinvocation field; leave nil
	}
	if w.FailurePolicy != nil {
		v.failurePolicy = *w.FailurePolicy
	}
	if w.SideEffects != nil {
		v.sideEffects = *w.SideEffects
	}
	v.objectSel = !isEmptyLabelSelector(w.ObjectSelector)
	v.namespaceSel = !isEmptyLabelSelector(w.NamespaceSelector)
	return v
}

func (e *Evaluator) score(hooks []webhookView) RiskBreakdown {
	br := make(map[string]int, 6)
	for i := range hooks {
		w := &hooks[i]
		matchesCriticalAPI := webhookMatchesCriticalAPI(w)

		if matchesCriticalAPI && w.failurePolicy == admissionregistrationv1.Ignore {
			br[SubScoreFailurePolicy] = WeightFailurePolicy
		}
		if w.sideEffects == admissionregistrationv1.SideEffectClassUnknown ||
			w.sideEffects == admissionregistrationv1.SideEffectClassSome {
			if cur := br[SubScoreSideEffects]; cur < WeightSideEffects {
				br[SubScoreSideEffects] = WeightSideEffects
			}
		}
		if !e.bundleTrusted(w.caBundle) {
			if cur := br[SubScoreCAUntrusted]; cur < WeightCAUntrusted {
				br[SubScoreCAUntrusted] = WeightCAUntrusted
			}
		}
		if matchesCriticalAPI && !w.objectSel && !w.namespaceSel {
			if cur := br[SubScoreNoSelector]; cur < WeightNoSelector {
				br[SubScoreNoSelector] = WeightNoSelector
			}
		}
		if matchesCriticalAPI {
			if cur := br[SubScoreCriticalAPI]; cur < WeightCriticalAPI {
				br[SubScoreCriticalAPI] = WeightCriticalAPI
			}
		}
		if w.reinvocation != nil &&
			*w.reinvocation == admissionregistrationv1.IfNeededReinvocationPolicy &&
			(w.sideEffects == admissionregistrationv1.SideEffectClassUnknown ||
				w.sideEffects == admissionregistrationv1.SideEffectClassSome) {
			if cur := br[SubScoreReinvocationIfNeeded]; cur < WeightReinvocationIfNeeded {
				br[SubScoreReinvocationIfNeeded] = WeightReinvocationIfNeeded
			}
		}
	}
	total := 0
	for _, v := range br {
		total += v
	}
	if total > 100 {
		total = 100
	}
	return RiskBreakdown{Total: total, Breakdown: br}
}

func (e *Evaluator) bundleTrusted(caBundle []byte) bool {
	a := AnalyzeCABundle(caBundle)
	if a.Empty || a.ParseError != "" {
		return false
	}
	return MatchTrustedDN(a, keysOf(e.trusted))
}

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// webhookMatchesCriticalAPI scans rules.resources for any membership
// in CriticalAPIResources. "*" wildcard is treated as match-all =
// includes critical resources.
func webhookMatchesCriticalAPI(w *webhookView) bool {
	for i := range w.rules {
		for _, r := range w.rules[i].Resources {
			if r == "*" {
				return true
			}
			if _, ok := CriticalAPIResources[r]; ok {
				return true
			}
		}
	}
	return false
}

// isEmptyLabelSelector returns true when the selector is nil or has
// no matchLabels and no matchExpressions. K8s admission treats
// nil/empty equivalently as "match everything".
func isEmptyLabelSelector(sel *metav1.LabelSelector) bool {
	if sel == nil {
		return true
	}
	if len(sel.MatchLabels) > 0 {
		return false
	}
	if len(sel.MatchExpressions) > 0 {
		return false
	}
	return true
}
