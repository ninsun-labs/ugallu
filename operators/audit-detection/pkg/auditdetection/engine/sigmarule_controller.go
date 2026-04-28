// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection/sigma"
)

// ConditionTypeCompiled is the SigmaRule status.condition the
// reconciler writes after each compile attempt. Status=True means the
// rule is loaded into the engine; False means ParseError is set.
const ConditionTypeCompiled = "Compiled"

// SigmaRuleReconciler reads SigmaRule CRs, compiles them via
// sigma.Compile, and installs the result in the engine's RuleSet.
// Compile failures are surfaced via Status.ParseError +
// Conditions[Compiled]=False; the rule is also removed from the
// active set so a previously-good version doesn't keep firing after
// a bad edit.
type SigmaRuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Rules *RuleSet
}

// Reconcile implements the controller-runtime contract.
func (r *SigmaRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rlog := log.FromContext(ctx).WithName("sigmarule").WithValues("name", req.Name)

	rule := &securityv1alpha1.SigmaRule{}
	if err := r.Get(ctx, req.NamespacedName, rule); err != nil {
		if apierrors.IsNotFound(err) {
			r.Rules.Delete(req.Name)
			rlog.Info("rule deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	compiled, compileErr := sigma.Compile(rule)
	burst, sustained := rateBudget(rule.Spec.RateLimit)

	parseErr := ""
	if compileErr != nil {
		parseErr = compileErr.Error()
		ruleCompileErrorsTotal.WithLabelValues(rule.Name).Inc()
		r.Rules.AddOrUpdate(rule.Name, false, nil, parseErr, burst, sustained)
		rlog.Info("compile failed", "err", parseErr)
	} else {
		r.Rules.AddOrUpdate(rule.Name, rule.Spec.Enabled, compiled, "", burst, sustained)
		rlog.Info("rule compiled", "enabled", rule.Spec.Enabled)
	}

	if err := r.writeStatus(ctx, rule, compileErr); err != nil {
		return ctrl.Result{}, fmt.Errorf("status update: %w", err)
	}

	// Periodic requeue keeps Status.MatchCount / LastMatchedAt fresh
	// for kubectl-watching humans even when nothing else changed.
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// writeStatus reflects the in-memory rule state back into the CR's
// Status subresource. The reconciler is the sole writer for
// Status.MatchCount / LastMatchedAt / DroppedRateLimit.
func (r *SigmaRuleReconciler) writeStatus(ctx context.Context, rule *securityv1alpha1.SigmaRule, compileErr error) error {
	entry := r.Rules.Get(rule.Name)
	now := metav1.NewTime(time.Now())

	cond := metav1.Condition{
		Type:               ConditionTypeCompiled,
		Status:             metav1.ConditionTrue,
		Reason:             "Compiled",
		Message:            "rule compiled and loaded into engine",
		LastTransitionTime: now,
		ObservedGeneration: rule.Generation,
	}
	if compileErr != nil {
		cond.Status = metav1.ConditionFalse
		cond.Reason = compileReason(compileErr)
		cond.Message = compileErr.Error()
	}

	patch := rule.DeepCopy()
	upsertCondition(&patch.Status.Conditions, &cond)
	if compileErr != nil {
		patch.Status.ParseError = compileErr.Error()
	} else {
		patch.Status.ParseError = ""
	}
	if entry != nil {
		patch.Status.MatchCount = entry.MatchCount.Load()
		patch.Status.DroppedRateLimit = entry.DroppedRateLimit.Load()
		if last := entry.LastMatchedAt.Load(); last != nil {
			t := metav1.NewTime(*last)
			patch.Status.LastMatchedAt = &t
		}
	}
	return r.Status().Patch(ctx, patch, client.MergeFrom(rule))
}

// SetupWithManager wires the reconciler.
func (r *SigmaRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Rules == nil {
		return errors.New("sigmarule reconciler: Rules is required")
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("sigmarule").
		For(&securityv1alpha1.SigmaRule{}).
		Complete(r)
}

// rateBudget pulls (burst, sustained) from spec.rateLimit, falling
// back to the engine defaults when the rule does not override them.
func rateBudget(rl *securityv1alpha1.SigmaRateLimit) (burst, sustained int) {
	if rl == nil {
		return DefaultRuleBurst, DefaultRuleSustainedPerSec
	}
	burst = rl.Burst
	sustained = rl.SustainedPerSec
	if burst <= 0 {
		burst = DefaultRuleBurst
	}
	if sustained <= 0 {
		sustained = DefaultRuleSustainedPerSec
	}
	return burst, sustained
}

// compileReason maps a compile error onto a short condition reason.
// The full text remains in the message; the reason is for tooling
// (kubectl get) that prefers a one-word tag.
func compileReason(err error) string {
	if errors.Is(err, sigma.ErrInvalidJSONPath) {
		return "JSONPath"
	}
	if errors.Is(err, sigma.ErrTooManyWildcards) {
		return "GlobBudget"
	}
	return "CompileError"
}

// upsertCondition replaces the entry whose Type matches cond.Type,
// preserving LastTransitionTime when Status didn't actually change so
// kubectl's "since" stays useful.
func upsertCondition(list *[]metav1.Condition, cond *metav1.Condition) {
	for i := range *list {
		if (*list)[i].Type != cond.Type {
			continue
		}
		if (*list)[i].Status == cond.Status {
			cond.LastTransitionTime = (*list)[i].LastTransitionTime
		}
		(*list)[i] = *cond
		return
	}
	*list = append(*list, *cond)
}
