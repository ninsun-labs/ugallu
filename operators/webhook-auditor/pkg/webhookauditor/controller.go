// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor

import (
	"context"
	"fmt"
	"path"
	"sync/atomic"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// Reconciler computes a RiskBreakdown for one webhook configuration
// and emits the §W5 SE stream when the cache says the spec changed.
//
// Two reconcilers share the bulk of the logic — one watches
// MutatingWebhookConfiguration, the other ValidatingWebhookConfiguration —
// they hand off through reconcileTarget.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Evaluator *Evaluator
	Emit      EmitOptions
	Cache     *DebounceCache
	Ignore    *IgnoreMatcher

	// Booted flips false → true after the first list of MWCs/VWCs
	// observed at startup, so we can stamp `first_observed=true` on
	// the initial sweep.
	booted atomic.Bool
}

// MutatingReconciler watches admissionregistration.k8s.io/v1
// MutatingWebhookConfiguration objects.
type MutatingReconciler struct {
	*Reconciler
}

// ValidatingReconciler watches admissionregistration.k8s.io/v1
// ValidatingWebhookConfiguration objects.
type ValidatingReconciler struct {
	*Reconciler
}

// Reconcile for MWC.
func (r *MutatingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rlog := log.FromContext(ctx).WithName("webhook-auditor-mwc").WithValues("name", req.Name)

	mwc := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := r.Get(ctx, req.NamespacedName, mwc); err != nil {
		if apierrors.IsNotFound(err) {
			return r.handleDelete(ctx, req.Name, "MutatingWebhookConfiguration")
		}
		return ctrl.Result{}, err
	}
	target := FromMutating(mwc)
	if r.Ignore.IsIgnored("admissionregistration.k8s.io/v1", target.Name) {
		evalSkippedTotal.WithLabelValues("ignored").Inc()
		return ctrl.Result{}, nil
	}

	br, hash, err := r.evalMutating(ctx, mwc)
	if err != nil {
		return ctrl.Result{}, err
	}
	emit, firstObserved := r.Cache.Decide(mwc.UID, br.Total, hash)
	if !emit {
		evalSkippedTotal.WithLabelValues("debounced").Inc()
		return ctrl.Result{}, nil
	}

	evalTotal.Inc()
	scoreDistribution.Observe(float64(br.Total))
	rlog.V(1).Info("emit findings", "score", br.Total, "first", firstObserved)

	opts := r.Emit
	opts.FirstObserved = firstObserved
	if err := EmitFindings(ctx, opts, target, br); err != nil {
		return ctrl.Result{}, err
	}
	r.recordEmits(target.Kind, br)
	return ctrl.Result{}, nil
}

// Reconcile for VWC.
func (r *ValidatingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rlog := log.FromContext(ctx).WithName("webhook-auditor-vwc").WithValues("name", req.Name)

	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := r.Get(ctx, req.NamespacedName, vwc); err != nil {
		if apierrors.IsNotFound(err) {
			return r.handleDelete(ctx, req.Name, "ValidatingWebhookConfiguration")
		}
		return ctrl.Result{}, err
	}
	target := FromValidating(vwc)
	if r.Ignore.IsIgnored("admissionregistration.k8s.io/v1", target.Name) {
		evalSkippedTotal.WithLabelValues("ignored").Inc()
		return ctrl.Result{}, nil
	}

	br, hash, err := r.evalValidating(ctx, vwc)
	if err != nil {
		return ctrl.Result{}, err
	}
	emit, firstObserved := r.Cache.Decide(vwc.UID, br.Total, hash)
	if !emit {
		evalSkippedTotal.WithLabelValues("debounced").Inc()
		return ctrl.Result{}, nil
	}

	evalTotal.Inc()
	scoreDistribution.Observe(float64(br.Total))
	rlog.V(1).Info("emit findings", "score", br.Total, "first", firstObserved)

	opts := r.Emit
	opts.FirstObserved = firstObserved
	if err := EmitFindings(ctx, opts, target, br); err != nil {
		return ctrl.Result{}, err
	}
	r.recordEmits(target.Kind, br)
	return ctrl.Result{}, nil
}

// SetupWithManager wires both reconcilers and shares state via the
// embedded *Reconciler.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("webhook-auditor-mwc").
		For(&admissionregistrationv1.MutatingWebhookConfiguration{}).
		Complete(&MutatingReconciler{Reconciler: r}); err != nil {
		return fmt.Errorf("mwc reconciler: %w", err)
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("webhook-auditor-vwc").
		For(&admissionregistrationv1.ValidatingWebhookConfiguration{}).
		Complete(&ValidatingReconciler{Reconciler: r}); err != nil {
		return fmt.Errorf("vwc reconciler: %w", err)
	}
	return nil
}

// --- internals -------------------------------------------------------

func (r *Reconciler) evalMutating(_ context.Context, mwc *admissionregistrationv1.MutatingWebhookConfiguration) (RiskBreakdown, string, error) {
	br := r.Evaluator.ScoreMutating(mwc)
	hash, err := Hash(mwc.Webhooks)
	return br, hash, err
}

func (r *Reconciler) evalValidating(_ context.Context, vwc *admissionregistrationv1.ValidatingWebhookConfiguration) (RiskBreakdown, string, error) {
	br := r.Evaluator.ScoreValidating(vwc)
	hash, err := Hash(vwc.Webhooks)
	return br, hash, err
}

func (r *Reconciler) handleDelete(ctx context.Context, name, kind string) (ctrl.Result, error) {
	r.Cache.Forget(types.UID(name)) // not actual UID — best effort prune by name
	target := EmitTarget{
		Kind: securityv1alpha1.SubjectKind(kind),
		Name: name,
	}
	if err := EmitDeleted(ctx, r.Emit, target); err != nil {
		return ctrl.Result{}, fmt.Errorf("emit deleted: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) recordEmits(kind securityv1alpha1.SubjectKind, br RiskBreakdown) {
	if br.Total >= r.Emit.Threshold {
		scoreEmitTotal.WithLabelValues(topLevelType(kind), string(SeverityFor(br.Total))).Inc()
	}
	if br.Has(SubScoreCAUntrusted) {
		scoreEmitTotal.WithLabelValues(securityv1alpha1.TypeWebhookCAUntrusted, string(securityv1alpha1.SeverityMedium)).Inc()
	}
	if br.Has(SubScoreFailurePolicy) {
		scoreEmitTotal.WithLabelValues(securityv1alpha1.TypeWebhookFailOpenCriticalAPI, string(securityv1alpha1.SeverityHigh)).Inc()
	}
	if br.Has(SubScoreCriticalAPI) {
		scoreEmitTotal.WithLabelValues(securityv1alpha1.TypeWebhookSecretAccess, string(securityv1alpha1.SeverityHigh)).Inc()
	}
	if br.Has(SubScoreSideEffects) && !br.Has(SubScoreFailurePolicy) {
		scoreEmitTotal.WithLabelValues(securityv1alpha1.TypeWebhookSideEffectsUnknown, string(securityv1alpha1.SeverityMedium)).Inc()
	}
}

// IgnoreMatcher is the design 21 §W4 skip-list. apiVersionGlob is
// matched only when non-empty; nameGlobs accepts shell-style globs
// (`*` wildcard, no regex).
type IgnoreMatcher struct {
	rules []securityv1alpha1.WebhookIgnoreRule
}

// NewIgnoreMatcher builds the matcher from the WebhookAuditorConfig
// spec rules.
func NewIgnoreMatcher(rules []securityv1alpha1.WebhookIgnoreRule) *IgnoreMatcher {
	out := make([]securityv1alpha1.WebhookIgnoreRule, len(rules))
	copy(out, rules)
	return &IgnoreMatcher{rules: out}
}

// IsIgnored reports whether the given (apiVersion, name) pair matches
// any rule.
func (m *IgnoreMatcher) IsIgnored(apiVersion, name string) bool {
	if m == nil {
		return false
	}
	for i := range m.rules {
		r := m.rules[i]
		if r.APIVersionGlob != "" {
			ok, _ := path.Match(r.APIVersionGlob, apiVersion)
			if !ok {
				continue
			}
		}
		for _, ng := range r.NameGlobs {
			if ok, _ := path.Match(ng, name); ok {
				return true
			}
		}
	}
	return false
}
