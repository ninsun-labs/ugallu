// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Integration tests for the SigmaRule reconciler + Engine pair,
// driven against a real apiserver via envtest. These scenarios are
// the lab e2e backbone: every behaviour the operator advertises is
// exercised here so the close gate has no skipped scenarios.

package engine_test

import (
	"context"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"

	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection"
	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection/engine"
)

// requireEnvtest skips when the envtest control plane didn't start
// (e.g. KUBEBUILDER_ASSETS missing on a developer laptop). CI runs
// always have it.
func requireEnvtest(t *testing.T) {
	t.Helper()
	if envCfg == nil {
		t.Skip("envtest not started; set KUBEBUILDER_ASSETS or run `task envtest:assets`")
	}
}

func newReconciler(t *testing.T) (*engine.SigmaRuleReconciler, *engine.Engine) {
	t.Helper()
	em, err := emitterv1alpha1.NewEmitter(&emitterv1alpha1.EmitterOpts{
		Client:          envClient,
		AttestorMeta:    sign.AttestorMeta{Name: "ugallu-audit-detection", Version: "integration"},
		BurstPerSec:     1000,
		SustainedPerSec: 1000,
	})
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	eng, err := engine.New(&engine.Options{
		Emitter:         em,
		ClusterIdentity: securityv1alpha1.ClusterIdentity{ClusterID: "envtest"},
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return &engine.SigmaRuleReconciler{
		Client: envClient,
		Scheme: envScheme,
		Rules:  eng.Rules(),
	}, eng
}

// makeSigmaRule wraps the SigmaRule constructor for test setup. spec
// is value-typed so call sites stay compact; the hugeParam lint is
// fine for a test helper.
//
//nolint:gocritic // value semantics keep test literals readable
func makeSigmaRule(name string, spec securityv1alpha1.SigmaRuleSpec) *securityv1alpha1.SigmaRule {
	return &securityv1alpha1.SigmaRule{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
}

func reconcile(t *testing.T, r *engine.SigmaRuleReconciler, name string) {
	t.Helper()
	if _, err := r.Reconcile(envCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
		t.Fatalf("Reconcile %q: %v", name, err)
	}
}

func waitFor(ctx context.Context, t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("ctx cancelled while waiting")
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("predicate never returned true within 2s")
}

func deleteAllSigmaRules(t *testing.T) {
	t.Helper()
	list := &securityv1alpha1.SigmaRuleList{}
	if err := envClient.List(envCtx(), list); err != nil {
		t.Fatalf("List SigmaRule: %v", err)
	}
	for i := range list.Items {
		_ = envClient.Delete(envCtx(), &list.Items[i])
	}
}

func deleteAllSecurityEvents(t *testing.T) {
	t.Helper()
	list := &securityv1alpha1.SecurityEventList{}
	if err := envClient.List(envCtx(), list); err != nil {
		t.Fatalf("List SecurityEvent: %v", err)
	}
	for i := range list.Items {
		_ = envClient.Delete(envCtx(), &list.Items[i])
	}
}

// --- scenario 1: happy-path compile + match + emit + status ----------------

func TestIntegration_HappyPath_CompileMatchEmitStatus(t *testing.T) {
	requireEnvtest(t)
	deleteAllSigmaRules(t)
	deleteAllSecurityEvents(t)
	deleteAllSigmaRules(t)
	deleteAllSecurityEvents(t)
	t.Cleanup(func() { deleteAllSigmaRules(t); deleteAllSecurityEvents(t) })

	r, eng := newReconciler(t)
	rule := makeSigmaRule("cabg-create", securityv1alpha1.SigmaRuleSpec{
		Enabled: true,
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{
				ObjectRef: &securityv1alpha1.ObjectRefMatch{Resource: []string{"clusterrolebindings"}},
			},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityCritical,
			Signals:           map[string]string{"verb": "${verb}", "user": "${user.username}"},
		},
	})
	if err := envClient.Create(envCtx(), rule); err != nil {
		t.Fatalf("Create rule: %v", err)
	}
	reconcile(t, r, rule.Name)

	got := &securityv1alpha1.SigmaRule{}
	if err := envClient.Get(envCtx(), client.ObjectKey{Name: rule.Name}, got); err != nil {
		t.Fatalf("Get rule: %v", err)
	}
	if !hasCondition(got.Status.Conditions, engine.ConditionTypeCompiled, metav1.ConditionTrue) {
		t.Errorf("Compiled condition not True: %+v", got.Status.Conditions)
	}
	if got.Status.ParseError != "" {
		t.Errorf("ParseError set on happy-path rule: %q", got.Status.ParseError)
	}

	// Drive a matching event through the engine and verify SE creation.
	ctx, cancel := context.WithTimeout(envCtx(), 1500*time.Millisecond)
	defer cancel()
	src := &fakeSource{name: "int-fake", events: []*auditdetection.AuditEvent{newAuditEvent()}}
	if err := eng.Run(ctx, src); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	list := &securityv1alpha1.SecurityEventList{}
	waitFor(envCtx(), t, func() bool {
		_ = envClient.List(envCtx(), list)
		return len(list.Items) > 0
	})
	if list.Items[0].Spec.Type != securityv1alpha1.TypeClusterAdminGranted {
		t.Errorf("SE.Type = %q", list.Items[0].Spec.Type)
	}

	// Reconcile again — counters should now appear in status.
	reconcile(t, r, rule.Name)
	if err := envClient.Get(envCtx(), client.ObjectKey{Name: rule.Name}, got); err != nil {
		t.Fatalf("Get rule (re): %v", err)
	}
	if got.Status.MatchCount < 1 {
		t.Errorf("Status.MatchCount = %d, want >=1", got.Status.MatchCount)
	}
	if got.Status.LastMatchedAt == nil {
		t.Error("Status.LastMatchedAt is nil")
	}
}

// --- scenario 2: bad JSONPath surfaces ParseError --------------------------

func TestIntegration_CompileFailure_SurfacesParseError(t *testing.T) {
	requireEnvtest(t)
	deleteAllSigmaRules(t)
	t.Cleanup(func() { deleteAllSigmaRules(t) })

	r, _ := newReconciler(t)
	rule := makeSigmaRule("bad-jsonpath", securityv1alpha1.SigmaRuleSpec{
		Enabled: true,
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{
				RequestObjectGlob: []securityv1alpha1.GlobMatch{
					{JSONPath: "$..a", Patterns: []string{"x"}}, // recursive descent unsupported
				},
			},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityHigh,
		},
	})
	if err := envClient.Create(envCtx(), rule); err != nil {
		t.Fatalf("Create: %v", err)
	}
	reconcile(t, r, rule.Name)

	got := &securityv1alpha1.SigmaRule{}
	if err := envClient.Get(envCtx(), client.ObjectKey{Name: rule.Name}, got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status.ParseError == "" {
		t.Error("ParseError empty for bad JSONPath rule")
	}
	if !hasCondition(got.Status.Conditions, engine.ConditionTypeCompiled, metav1.ConditionFalse) {
		t.Errorf("Compiled=False not set; conditions=%+v", got.Status.Conditions)
	}
}

// --- scenario 3: disabled rule does not emit -------------------------------

func TestIntegration_DisabledRule_DoesNotEmit(t *testing.T) {
	requireEnvtest(t)
	deleteAllSigmaRules(t)
	deleteAllSecurityEvents(t)
	t.Cleanup(func() { deleteAllSigmaRules(t); deleteAllSecurityEvents(t) })

	r, eng := newReconciler(t)
	rule := makeSigmaRule("disabled", securityv1alpha1.SigmaRuleSpec{
		Enabled: false,
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{Verb: []string{"create"}},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityHigh,
		},
	})
	if err := envClient.Create(envCtx(), rule); err != nil {
		t.Fatalf("Create: %v", err)
	}
	reconcile(t, r, rule.Name)

	ctx, cancel := context.WithTimeout(envCtx(), 500*time.Millisecond)
	defer cancel()
	if err := eng.Run(ctx, &fakeSource{name: "off", events: []*auditdetection.AuditEvent{newAuditEvent()}}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	list := &securityv1alpha1.SecurityEventList{}
	if err := envClient.List(envCtx(), list); err != nil {
		t.Fatalf("List SE: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("SE count = %d, want 0", len(list.Items))
	}
}

// --- scenario 4: deletion removes the rule from the engine -----------------

func TestIntegration_DeleteRemovesRule(t *testing.T) {
	requireEnvtest(t)
	deleteAllSigmaRules(t)
	t.Cleanup(func() { deleteAllSigmaRules(t) })

	r, eng := newReconciler(t)
	rule := makeSigmaRule("ephemeral", securityv1alpha1.SigmaRuleSpec{
		Enabled: true,
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{Verb: []string{"create"}},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityHigh,
		},
	})
	if err := envClient.Create(envCtx(), rule); err != nil {
		t.Fatalf("Create: %v", err)
	}
	reconcile(t, r, rule.Name)
	if eng.Rules().Get(rule.Name) == nil {
		t.Fatal("rule not loaded into engine after first reconcile")
	}

	if err := envClient.Delete(envCtx(), rule); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Wait for the apiserver to flush before reconciling.
	waitFor(envCtx(), t, func() bool {
		err := envClient.Get(envCtx(), client.ObjectKey{Name: rule.Name}, &securityv1alpha1.SigmaRule{})
		return apierrors.IsNotFound(err)
	})
	reconcile(t, r, rule.Name)

	if entry := eng.Rules().Get(rule.Name); entry != nil {
		t.Errorf("rule still in engine after delete: %+v", entry)
	}
}

// --- scenario 5: rate limit drops excess matches ---------------------------

func TestIntegration_RateLimit_DropsExcess(t *testing.T) {
	requireEnvtest(t)
	deleteAllSigmaRules(t)
	deleteAllSecurityEvents(t)
	t.Cleanup(func() { deleteAllSigmaRules(t); deleteAllSecurityEvents(t) })

	r, eng := newReconciler(t)
	rule := makeSigmaRule("rate-limited", securityv1alpha1.SigmaRuleSpec{
		Enabled: true,
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{Verb: []string{"create"}},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityHigh,
		},
		RateLimit: &securityv1alpha1.SigmaRateLimit{Burst: 1, SustainedPerSec: 1},
	})
	if err := envClient.Create(envCtx(), rule); err != nil {
		t.Fatalf("Create: %v", err)
	}
	reconcile(t, r, rule.Name)

	// Burst of 5 events; with burst=1/sustained=1 in a 200ms window
	// the limiter lets ~1 match through and drops ~4.
	events := make([]*auditdetection.AuditEvent, 5)
	for i := range events {
		events[i] = newAuditEvent()
	}
	ctx, cancel := context.WithTimeout(envCtx(), 250*time.Millisecond)
	defer cancel()
	if err := eng.Run(ctx, &fakeSource{name: "burst", events: events}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entry := eng.Rules().Get(rule.Name)
	if entry == nil {
		t.Fatal("rule entry missing")
	}
	if entry.DroppedRateLimit.Load() == 0 {
		t.Errorf("DroppedRateLimit = 0, want > 0 (burst should be exhausted)")
	}

	reconcile(t, r, rule.Name)
	got := &securityv1alpha1.SigmaRule{}
	if err := envClient.Get(envCtx(), client.ObjectKey{Name: rule.Name}, got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status.DroppedRateLimit == 0 {
		t.Errorf("Status.DroppedRateLimit = 0 after reconcile")
	}
}

// --- scenario 6: AnyOf composition -----------------------------------------

func TestIntegration_AnyOfComposition(t *testing.T) {
	requireEnvtest(t)
	deleteAllSigmaRules(t)
	deleteAllSecurityEvents(t)
	t.Cleanup(func() { deleteAllSigmaRules(t); deleteAllSecurityEvents(t) })

	r, eng := newReconciler(t)
	rule := makeSigmaRule("anyof", securityv1alpha1.SigmaRuleSpec{
		Enabled: true,
		Match: securityv1alpha1.SigmaMatch{
			AnyOf: []securityv1alpha1.SigmaMatchLeaf{
				{Verb: []string{"delete"}},
				{Verb: []string{"create"}},
			},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityHigh,
		},
	})
	if err := envClient.Create(envCtx(), rule); err != nil {
		t.Fatalf("Create: %v", err)
	}
	reconcile(t, r, rule.Name)

	ctx, cancel := context.WithTimeout(envCtx(), 1500*time.Millisecond)
	defer cancel()
	if err := eng.Run(ctx, &fakeSource{name: "anyof", events: []*auditdetection.AuditEvent{newAuditEvent()}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	list := &securityv1alpha1.SecurityEventList{}
	waitFor(envCtx(), t, func() bool {
		_ = envClient.List(envCtx(), list)
		return len(list.Items) > 0
	})
}

// --- scenario 7: Not negation ----------------------------------------------

func TestIntegration_NotNegation_SuppressesMatch(t *testing.T) {
	requireEnvtest(t)
	deleteAllSigmaRules(t)
	deleteAllSecurityEvents(t)
	t.Cleanup(func() { deleteAllSigmaRules(t); deleteAllSecurityEvents(t) })

	r, eng := newReconciler(t)
	rule := makeSigmaRule("not-suppress", securityv1alpha1.SigmaRuleSpec{
		Enabled: true,
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
			Severity:          securityv1alpha1.SeverityHigh,
		},
	})
	if err := envClient.Create(envCtx(), rule); err != nil {
		t.Fatalf("Create: %v", err)
	}
	reconcile(t, r, rule.Name)

	ctx, cancel := context.WithTimeout(envCtx(), 500*time.Millisecond)
	defer cancel()
	if err := eng.Run(ctx, &fakeSource{name: "not", events: []*auditdetection.AuditEvent{newAuditEvent()}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	list := &securityv1alpha1.SecurityEventList{}
	if err := envClient.List(envCtx(), list); err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("SE count = %d, want 0 (Not should suppress)", len(list.Items))
	}
}

// --- scenario 8: RequestObject JSONPath match ------------------------------

func TestIntegration_RequestObjectGlob_MatchesAndEmits(t *testing.T) {
	requireEnvtest(t)
	deleteAllSigmaRules(t)
	deleteAllSecurityEvents(t)
	t.Cleanup(func() { deleteAllSigmaRules(t); deleteAllSecurityEvents(t) })

	r, eng := newReconciler(t)
	rule := makeSigmaRule("rolebody", securityv1alpha1.SigmaRuleSpec{
		Enabled: true,
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
	if err := envClient.Create(envCtx(), rule); err != nil {
		t.Fatalf("Create: %v", err)
	}
	reconcile(t, r, rule.Name)

	ctx, cancel := context.WithTimeout(envCtx(), 1500*time.Millisecond)
	defer cancel()
	if err := eng.Run(ctx, &fakeSource{name: "body", events: []*auditdetection.AuditEvent{newAuditEvent()}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	list := &securityv1alpha1.SecurityEventList{}
	waitFor(envCtx(), t, func() bool {
		_ = envClient.List(envCtx(), list)
		return len(list.Items) > 0
	})
}

// --- scenario 9: rule update re-installs compiled state --------------------

func TestIntegration_UpdateRecompiles(t *testing.T) {
	requireEnvtest(t)
	deleteAllSigmaRules(t)
	t.Cleanup(func() { deleteAllSigmaRules(t) })

	r, eng := newReconciler(t)
	rule := makeSigmaRule("evolves", securityv1alpha1.SigmaRuleSpec{
		Enabled: true,
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{Verb: []string{"create"}},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityHigh,
		},
	})
	if err := envClient.Create(envCtx(), rule); err != nil {
		t.Fatalf("Create: %v", err)
	}
	reconcile(t, r, rule.Name)
	first := eng.Rules().Get(rule.Name)
	if first == nil || !first.Enabled {
		t.Fatal("rule not enabled after first reconcile")
	}

	// Disable the rule and reconcile. SigmaRule.Spec.Enabled has the
	// json:"enabled,omitempty" tag, so a MergeFrom patch from
	// {Enabled:true} to {Enabled:false} produces an empty diff —
	// Update (full replace) is the only way to flip the bit through
	// the typed client.
	got := &securityv1alpha1.SigmaRule{}
	if err := envClient.Get(envCtx(), client.ObjectKey{Name: rule.Name}, got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got.Spec.Enabled = false
	if err := envClient.Update(envCtx(), got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	reconcile(t, r, rule.Name)
	second := eng.Rules().Get(rule.Name)
	if second == nil {
		t.Fatal("rule entry vanished after disable")
	}
	if second.Enabled {
		t.Error("rule still enabled after spec.enabled=false")
	}
}

// --- helpers ----------------------------------------------------------------

func hasCondition(conds []metav1.Condition, t string, want metav1.ConditionStatus) bool {
	for i := range conds {
		if conds[i].Type == t {
			return conds[i].Status == want
		}
	}
	return false
}

// containsErr is a tiny helper so test failures print readable
// substrings of the error message without dragging in testify.
func containsErr(err error, sub string) bool {
	return err != nil && strings.Contains(err.Error(), sub)
}

var _ = containsErr // keep available for future scenarios
