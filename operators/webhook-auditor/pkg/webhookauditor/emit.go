// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// EmitTarget is the small abstraction the reconciler hands the emit
// helpers. It collapses the mutating/validating shapes to the fields
// emit needs (no resource manipulation past this point).
type EmitTarget struct {
	Kind       securityv1alpha1.SubjectKind // MutatingWebhookConfiguration | ValidatingWebhookConfiguration
	Name       string
	UID        types.UID
	APIGroup   string
	APIVersion string
}

// EmitOptions bundles emit-time context. Reconciler-supplied.
type EmitOptions struct {
	Emitter         *emitterv1alpha1.Emitter
	ClusterIdentity securityv1alpha1.ClusterIdentity
	Threshold       int

	// FirstObserved marks the very first reconcile-after-startup. Only
	// used by §W6 informational signal — no scoring impact.
	FirstObserved bool
}

// FromMutating returns an EmitTarget for a MutatingWebhookConfiguration.
func FromMutating(mwc *admissionregistrationv1.MutatingWebhookConfiguration) *EmitTarget {
	return &EmitTarget{
		Kind:       "MutatingWebhookConfiguration",
		Name:       mwc.Name,
		UID:        mwc.UID,
		APIGroup:   "admissionregistration.k8s.io",
		APIVersion: "v1",
	}
}

// FromValidating returns an EmitTarget for a ValidatingWebhookConfiguration.
func FromValidating(vwc *admissionregistrationv1.ValidatingWebhookConfiguration) *EmitTarget {
	return &EmitTarget{
		Kind:       "ValidatingWebhookConfiguration",
		Name:       vwc.Name,
		UID:        vwc.UID,
		APIGroup:   "admissionregistration.k8s.io",
		APIVersion: "v1",
	}
}

// EmitFindings produces the SE stream §W5 prescribes for one webhook
// configuration evaluation result. Calls the emitter once per applicable
// SE Type; on threshold-cross the top-level *HighRisk SE is emitted with
// the full breakdown signals, and any active sub-score also emits its
// own dedicated SE so dashboards can alert separately.
//
// Emit ordering is deterministic for replay-safety: top-level (if any)
// first, then per-sub-score in CA → failure-policy → secret-access →
// side-effects order.
func EmitFindings(
	ctx context.Context,
	opts EmitOptions,
	target *EmitTarget,
	br RiskBreakdown,
) error {
	if opts.Emitter == nil {
		return fmt.Errorf("emit: nil Emitter")
	}

	signals := buildSignals(br, opts.FirstObserved)

	// Top-level threshold cross.
	if br.Total >= opts.Threshold {
		highRiskType := topLevelType(target.Kind)
		if _, err := opts.Emitter.Emit(ctx, &emitterv1alpha1.EmitOpts{
			Class:           securityv1alpha1.ClassDetection,
			Type:            highRiskType,
			Severity:        SeverityFor(br.Total),
			SubjectKind:     target.Kind,
			SubjectName:     target.Name,
			SubjectUID:      target.UID,
			Signals:         signals,
			ClusterIdentity: opts.ClusterIdentity,
		}); err != nil {
			return fmt.Errorf("emit %s: %w", highRiskType, err)
		}
	}

	// Per-sub-score SEs (severity hint).
	if br.Has(SubScoreCAUntrusted) {
		if err := emitSubScore(ctx, opts, target, signals,
			securityv1alpha1.TypeWebhookCAUntrusted, securityv1alpha1.SeverityMedium); err != nil {
			return err
		}
	}
	if br.Has(SubScoreFailurePolicy) {
		if err := emitSubScore(ctx, opts, target, signals,
			securityv1alpha1.TypeWebhookFailOpenCriticalAPI, securityv1alpha1.SeverityHigh); err != nil {
			return err
		}
	}
	if br.Has(SubScoreCriticalAPI) {
		if err := emitSubScore(ctx, opts, target, signals,
			securityv1alpha1.TypeWebhookSecretAccess, securityv1alpha1.SeverityHigh); err != nil {
			return err
		}
	}
	if br.Has(SubScoreSideEffects) && !br.Has(SubScoreFailurePolicy) {
		// Catch-all only when failure-policy didn't already fire (avoid
		// alert duplication: failure-policy SE already implies the
		// side-effects concern).
		if err := emitSubScore(ctx, opts, target, signals,
			securityv1alpha1.TypeWebhookSideEffectsUnknown, securityv1alpha1.SeverityMedium); err != nil {
			return err
		}
	}
	return nil
}

// EmitDeleted fires on MWC/VWC removal — informational telemetry that
// shows the deletion in the SE stream. Severity:info, no breakdown.
func EmitDeleted(ctx context.Context, opts EmitOptions, target *EmitTarget) error {
	if opts.Emitter == nil {
		return fmt.Errorf("emit: nil Emitter")
	}
	_, err := opts.Emitter.Emit(ctx, &emitterv1alpha1.EmitOpts{
		Class:           securityv1alpha1.ClassAudit,
		Type:            securityv1alpha1.TypeWebhookConfigDeleted,
		Severity:        securityv1alpha1.SeverityInfo,
		SubjectKind:     target.Kind,
		SubjectName:     target.Name,
		SubjectUID:      target.UID,
		ClusterIdentity: opts.ClusterIdentity,
	})
	return err
}

// EmitEvalFailed fires when the evaluator panics on a malformed
// webhook configuration. Class=Anomaly so it reaches the operational
// dashboard, not the security alerting path.
func EmitEvalFailed(ctx context.Context, opts EmitOptions, target *EmitTarget, errMsg string) error {
	if opts.Emitter == nil {
		return fmt.Errorf("emit: nil Emitter")
	}
	_, err := opts.Emitter.Emit(ctx, &emitterv1alpha1.EmitOpts{
		Class:    securityv1alpha1.ClassAnomaly,
		Type:     securityv1alpha1.TypeWebhookEvalFailed,
		Severity: securityv1alpha1.SeverityHigh,
		Signals: map[string]string{
			"error": errMsg,
		},
		SubjectKind:     target.Kind,
		SubjectName:     target.Name,
		SubjectUID:      target.UID,
		ClusterIdentity: opts.ClusterIdentity,
	})
	return err
}

// --- internals -------------------------------------------------------

func emitSubScore(
	ctx context.Context,
	opts EmitOptions,
	target *EmitTarget,
	signals map[string]string,
	seType string,
	severity securityv1alpha1.Severity,
) error {
	_, err := opts.Emitter.Emit(ctx, &emitterv1alpha1.EmitOpts{
		Class:           securityv1alpha1.ClassDetection,
		Type:            seType,
		Severity:        severity,
		SubjectKind:     target.Kind,
		SubjectName:     target.Name,
		SubjectUID:      target.UID,
		Signals:         signals,
		ClusterIdentity: opts.ClusterIdentity,
	})
	if err != nil {
		return fmt.Errorf("emit %s: %w", seType, err)
	}
	return nil
}

func buildSignals(br RiskBreakdown, firstObserved bool) map[string]string {
	out := map[string]string{
		"risk_score":     strconv.Itoa(br.Total),
		"first_observed": strconv.FormatBool(firstObserved),
	}
	for k, v := range br.Breakdown {
		out["risk_breakdown."+k] = strconv.Itoa(v)
	}
	return out
}

func topLevelType(kind securityv1alpha1.SubjectKind) string {
	if strings.EqualFold(string(kind), "ValidatingWebhookConfiguration") {
		return securityv1alpha1.TypeValidatingWebhookHighRisk
	}
	return securityv1alpha1.TypeMutatingWebhookHighRisk
}
