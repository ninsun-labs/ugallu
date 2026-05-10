// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Integration tests for the webhook-auditor reconciler against a real
// apiserver via envtest. Three scenarios cover the Phase 1 close gate:
//
//   1. MWC threshold cross emits MutatingWebhookHighRisk SE
//   2. VWC below threshold but with active sub-score emits the
//      sub-score SE only (no top-level)
//   3. Ignore-policy match skips evaluation entirely

package webhookauditor_test

import (
	"context"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"

	"github.com/ninsun-labs/ugallu/operators/webhook-auditor/pkg/webhookauditor"
)

func requireEnvtest(t *testing.T) {
	t.Helper()
	if envCfg == nil {
		t.Skip("envtest not started; set KUBEBUILDER_ASSETS or run `task envtest:assets`")
	}
}

func newReconciler(t *testing.T, ignoreRules []securityv1alpha1.WebhookIgnoreRule, trustedDNs []string) *webhookauditor.Reconciler { //nolint:revive // DN is X.509 Distinguished Name
	t.Helper()
	em, err := emitterv1alpha1.NewEmitter(&emitterv1alpha1.EmitterOpts{
		Client:          envClient,
		AttestorMeta:    sign.AttestorMeta{Name: "ugallu-webhook-auditor", Version: "integration"},
		BurstPerSec:     1000,
		SustainedPerSec: 1000,
	})
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	return &webhookauditor.Reconciler{
		Client:           envClient,
		Scheme:           envScheme,
		Evaluator:        webhookauditor.NewEvaluator(webhookauditor.EvaluatorOptions{TrustedSubjectDNs: trustedDNs}),
		Cache:            webhookauditor.NewDebounceCacheForTest(),
		Ignore:           webhookauditor.NewIgnoreMatcher(ignoreRules),
		CABundleResolver: webhookauditor.NewCABundleResolver(envClient, []string{"cert-manager"}),
		Emit: webhookauditor.EmitOptions{
			Emitter:         em,
			ClusterIdentity: securityv1alpha1.ClusterIdentity{ClusterID: "envtest"},
			Threshold:       60,
		},
	}
}

func reconcileMWC(t *testing.T, r *webhookauditor.Reconciler, name string) {
	t.Helper()
	mr := &webhookauditor.MutatingReconciler{Reconciler: r}
	if _, err := mr.Reconcile(envCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
		t.Fatalf("MutatingReconciler.Reconcile(%s): %v", name, err)
	}
}

func reconcileVWC(t *testing.T, r *webhookauditor.Reconciler, name string) {
	t.Helper()
	vr := &webhookauditor.ValidatingReconciler{Reconciler: r}
	if _, err := vr.Reconcile(envCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
		t.Fatalf("ValidatingReconciler.Reconcile(%s): %v", name, err)
	}
}

// --- Scenario 1: MWC threshold cross emits HighRisk SE ---------------
func TestIntegration_MWC_HighRiskEmits(t *testing.T) {
	requireEnvtest(t)
	cleanupSEs(t)

	r := newReconciler(t, nil, nil) // empty trust list → ca_untrusted always fires
	// Note: admissionregistration.k8s.io/v1 rejects sideEffects=Unknown
	// at admission (legacy v1beta1). The side_effects sub-score is
	// covered by unit tests; this scenario drives failure_policy +
	// ca_untrusted + critical_api + no_selector = 30+20+10+15 = 75
	// (≥ 60 threshold).
	mwc := makeMWC("evil-mwc", admissionregistrationv1.Ignore, admissionregistrationv1.SideEffectClassNone,
		[]string{"secrets"}, nil)
	mustCreate(t, mwc)
	defer mustDelete(t, mwc)

	reconcileMWC(t, r, "evil-mwc")

	se := waitForSEByType(t, securityv1alpha1.TypeMutatingWebhookHighRisk, 5*time.Second)
	if se == nil {
		t.Fatalf("MutatingWebhookHighRisk SE never appeared")
	}
	if se.Spec.Subject.Kind != "MutatingWebhookConfiguration" {
		t.Errorf("Subject.Kind = %q, want MutatingWebhookConfiguration", se.Spec.Subject.Kind)
	}
	if se.Spec.Severity != securityv1alpha1.SeverityHigh {
		t.Errorf("Severity = %q, want high (score 75 in [60,85))", se.Spec.Severity)
	}
}

// --- Scenario 2: VWC below threshold but ca_untrusted fires its own SE ---
func TestIntegration_VWC_OnlySubScoreEmits(t *testing.T) {
	requireEnvtest(t)
	cleanupSEs(t)

	r := newReconciler(t, nil, nil)
	// Match on pods (not critical) + Fail policy + SideEffectsNone +
	// caBundle empty. Only ca_untrusted (20) fires → below 60 threshold.
	vwc := makeVWC("clean-vwc", admissionregistrationv1.Fail, admissionregistrationv1.SideEffectClassNone,
		[]string{"pods"}, nil)
	mustCreate(t, vwc)
	defer mustDelete(t, vwc)

	reconcileVWC(t, r, "clean-vwc")

	// No top-level *HighRisk expected.
	if se := waitForSEByType(t, securityv1alpha1.TypeValidatingWebhookHighRisk, 1*time.Second); se != nil {
		t.Errorf("unexpected *HighRisk SE for sub-threshold webhook: %s", se.Name)
	}
	// But the ca_untrusted sub-score SE must fire.
	if se := waitForSEByType(t, securityv1alpha1.TypeWebhookCAUntrusted, 5*time.Second); se == nil {
		t.Fatalf("WebhookCAUntrusted SE never appeared on empty caBundle")
	}
}

// --- Scenario 3: Ignore policy match skips entirely ------------------
func TestIntegration_IgnorePolicySkips(t *testing.T) {
	requireEnvtest(t)
	cleanupSEs(t)

	r := newReconciler(t, []securityv1alpha1.WebhookIgnoreRule{
		{APIVersionGlob: "admissionregistration.k8s.io/v1", NameGlobs: []string{"ugallu.*"}},
	}, nil)
	mwc := makeMWC("ugallu.example", admissionregistrationv1.Ignore, admissionregistrationv1.SideEffectClassNone,
		[]string{"secrets"}, nil)
	mustCreate(t, mwc)
	defer mustDelete(t, mwc)

	reconcileMWC(t, r, "ugallu.example")

	if se := waitForSEByType(t, securityv1alpha1.TypeMutatingWebhookHighRisk, 1*time.Second); se != nil {
		t.Errorf("ignored webhook still emitted SE: %s", se.Name)
	}
	if se := waitForSEByType(t, securityv1alpha1.TypeWebhookCAUntrusted, 1*time.Second); se != nil {
		t.Errorf("ignored webhook still emitted sub-score SE: %s", se.Name)
	}
}

// --- helpers ---------------------------------------------------------

func makeMWC(name string, fp admissionregistrationv1.FailurePolicyType, se admissionregistrationv1.SideEffectClass, resources []string, caBundle []byte) *admissionregistrationv1.MutatingWebhookConfiguration {
	fpVal := fp
	seVal := se
	url := "https://example.invalid/admit"
	timeoutSeconds := int32(5)
	admissionReviewVersions := []string{"v1"}
	return &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks: []admissionregistrationv1.MutatingWebhook{{
			Name: "h.example.io",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				URL:      &url,
				CABundle: caBundle,
			},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   resources,
				},
			}},
			FailurePolicy:           &fpVal,
			SideEffects:             &seVal,
			TimeoutSeconds:          &timeoutSeconds,
			AdmissionReviewVersions: admissionReviewVersions,
		}},
	}
}

func makeVWC(name string, fp admissionregistrationv1.FailurePolicyType, se admissionregistrationv1.SideEffectClass, resources []string, caBundle []byte) *admissionregistrationv1.ValidatingWebhookConfiguration {
	fpVal := fp
	seVal := se
	url := "https://example.invalid/admit"
	timeoutSeconds := int32(5)
	admissionReviewVersions := []string{"v1"}
	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name: "h.example.io",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				URL:      &url,
				CABundle: caBundle,
			},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   resources,
				},
			}},
			FailurePolicy:           &fpVal,
			SideEffects:             &seVal,
			TimeoutSeconds:          &timeoutSeconds,
			AdmissionReviewVersions: admissionReviewVersions,
		}},
	}
}

func mustCreate(t *testing.T, obj client.Object) {
	t.Helper()
	if err := envClient.Create(envCtx(), obj); err != nil {
		t.Fatalf("Create %T: %v", obj, err)
	}
}

func mustDelete(t *testing.T, obj client.Object) {
	t.Helper()
	if err := envClient.Delete(envCtx(), obj); err != nil && !apierrors.IsNotFound(err) {
		t.Logf("Delete %T: %v (non-fatal in cleanup)", obj, err)
	}
}

func cleanupSEs(t *testing.T) {
	t.Helper()
	list := &securityv1alpha1.SecurityEventList{}
	if err := envClient.List(envCtx(), list); err != nil {
		t.Fatalf("list SE: %v", err)
	}
	for i := range list.Items {
		_ = envClient.Delete(envCtx(), &list.Items[i])
	}
}

func waitForSEByType(t *testing.T, seType string, timeout time.Duration) *securityv1alpha1.SecurityEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		list := &securityv1alpha1.SecurityEventList{}
		if err := envClient.List(envCtx(), list); err == nil {
			for i := range list.Items {
				if list.Items[i].Spec.Type == seType {
					return &list.Items[i]
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// silence unused import in some build configs
var _ = context.Background
