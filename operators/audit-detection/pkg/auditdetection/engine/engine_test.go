// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"

	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection"
	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection/engine"
	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection/sigma"
)

// fakeSource is a minimal Source that pushes a fixed slice of events
// then closes its channel. Run blocks until ctx is done so the engine
// observes the same shutdown semantics as the real File/Webhook
// sources.
type fakeSource struct {
	name   string
	events []*auditdetection.AuditEvent
}

func (s *fakeSource) Name() string { return s.name }

func (s *fakeSource) Run(ctx context.Context) (<-chan *auditdetection.AuditEvent, error) {
	out := make(chan *auditdetection.AuditEvent, len(s.events))
	go func() {
		defer close(out)
		for _, ev := range s.events {
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
		<-ctx.Done()
	}()
	return out, nil
}

func newFakeClient(t *testing.T) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return ctrlfake.NewClientBuilder().WithScheme(scheme).Build()
}

func newEmitter(t *testing.T, c client.Client) *emitterv1alpha1.Emitter {
	t.Helper()
	e, err := emitterv1alpha1.NewEmitter(&emitterv1alpha1.EmitterOpts{
		Client:          c,
		AttestorMeta:    sign.AttestorMeta{Name: "ugallu-audit-detection", Version: "test"},
		BurstPerSec:     1000,
		SustainedPerSec: 1000,
	})
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	return e
}

// compileRule wraps sigma.Compile for test setup. spec is value-typed
// to keep call sites compact; the hugeParam lint is fine for a test
// helper.
//
//nolint:gocritic // value semantics keep test literals readable
func compileRule(t *testing.T, name string, spec securityv1alpha1.SigmaRuleSpec) *sigma.CompiledRule {
	t.Helper()
	rule := &securityv1alpha1.SigmaRule{Spec: spec}
	rule.Name = name
	cr, err := sigma.Compile(rule)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return cr
}

func newAuditEvent() *auditdetection.AuditEvent {
	return &auditdetection.AuditEvent{
		AuditID: "test-audit-1",
		Verb:    "create",
		User:    auditdetection.UserInfo{Username: "system:serviceaccount:kube-system:bad-bot"},
		ObjectRef: &auditdetection.ObjectReference{
			APIGroup:   "rbac.authorization.k8s.io",
			APIVersion: "v1",
			Resource:   "clusterrolebindings",
			Name:       "evil-binding",
		},
		RequestObject: map[string]any{
			"roleRef": map[string]any{"name": "cluster-admin"},
		},
	}
}

func TestEngine_HappyPath_EmitsSecurityEvent(t *testing.T) {
	c := newFakeClient(t)
	em := newEmitter(t, c)

	eng, err := engine.New(&engine.Options{
		Emitter:         em,
		ClusterIdentity: securityv1alpha1.ClusterIdentity{ClusterID: "test"},
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	cr := compileRule(t, "rule-cabg", securityv1alpha1.SigmaRuleSpec{
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
	eng.Rules().AddOrUpdate("rule-cabg", true, cr, "", 0, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	src := &fakeSource{name: "fake", events: []*auditdetection.AuditEvent{newAuditEvent()}}
	if err := eng.Run(ctx, src); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	entry := eng.Rules().Get("rule-cabg")
	if entry == nil {
		t.Fatal("rule entry missing")
	}
	if got := entry.MatchCount.Load(); got != 1 {
		t.Errorf("MatchCount = %d, want 1", got)
	}

	list := &securityv1alpha1.SecurityEventList{}
	if err := c.List(context.Background(), list); err != nil {
		t.Fatalf("List SE: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("SE count = %d, want 1", len(list.Items))
	}
	se := list.Items[0]
	if se.Spec.Type != securityv1alpha1.TypeClusterAdminGranted {
		t.Errorf("SE.Type = %q", se.Spec.Type)
	}
	if se.Spec.Subject.Kind != "ClusterRoleBinding" {
		t.Errorf("SE.Subject.Kind = %q, want ClusterRoleBinding", se.Spec.Subject.Kind)
	}
	if got := se.Spec.Signals["verb"]; got != "create" {
		t.Errorf("SE.Signals.verb = %q, want create", got)
	}
	if got := se.Spec.Signals["user"]; got != "system:serviceaccount:kube-system:bad-bot" {
		t.Errorf("SE.Signals.user = %q", got)
	}
}

func TestEngine_DisabledRule_DoesNotEmit(t *testing.T) {
	c := newFakeClient(t)
	em := newEmitter(t, c)
	eng, _ := engine.New(&engine.Options{Emitter: em, ClusterIdentity: securityv1alpha1.ClusterIdentity{ClusterID: "t"}})

	cr := compileRule(t, "off", securityv1alpha1.SigmaRuleSpec{
		Enabled: false,
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{Verb: []string{"create"}},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityHigh,
		},
	})
	eng.Rules().AddOrUpdate("off", false, cr, "", 0, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := eng.Run(ctx, &fakeSource{name: "fake", events: []*auditdetection.AuditEvent{newAuditEvent()}}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	list := &securityv1alpha1.SecurityEventList{}
	if err := c.List(context.Background(), list); err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("SE count = %d, want 0 (rule disabled)", len(list.Items))
	}
}

func TestEngine_RateLimit_DropsExtraMatches(t *testing.T) {
	c := newFakeClient(t)
	em := newEmitter(t, c)
	eng, _ := engine.New(&engine.Options{Emitter: em, ClusterIdentity: securityv1alpha1.ClusterIdentity{ClusterID: "t"}})

	cr := compileRule(t, "burst", securityv1alpha1.SigmaRuleSpec{
		Enabled: true,
		Match: securityv1alpha1.SigmaMatch{
			SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{Verb: []string{"create"}},
		},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityHigh,
		},
	})
	// burst=2, sustained=1 - first two events go through, the rest
	// land in the dropped bucket within the test window.
	eng.Rules().AddOrUpdate("burst", true, cr, "", 2, 1)

	events := []*auditdetection.AuditEvent{newAuditEvent(), newAuditEvent(), newAuditEvent(), newAuditEvent(), newAuditEvent()}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := eng.Run(ctx, &fakeSource{name: "burst-src", events: events}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entry := eng.Rules().Get("burst")
	if entry.MatchCount.Load() < 2 {
		t.Errorf("MatchCount = %d, want >= 2", entry.MatchCount.Load())
	}
	if entry.DroppedRateLimit.Load() == 0 {
		t.Errorf("DroppedRateLimit = 0, want > 0")
	}
}

func TestRuleSet_AddDeleteSnapshot(t *testing.T) {
	rs := engine.NewRuleSet()
	if got := len(rs.Snapshot()); got != 0 {
		t.Errorf("empty snapshot len = %d", got)
	}
	cr := compileRule(t, "r1", securityv1alpha1.SigmaRuleSpec{
		Match: securityv1alpha1.SigmaMatch{SigmaMatchLeaf: securityv1alpha1.SigmaMatchLeaf{Verb: []string{"create"}}},
		Emit: securityv1alpha1.SigmaEmit{
			SecurityEventType: securityv1alpha1.TypeClusterAdminGranted,
			Severity:          securityv1alpha1.SeverityHigh,
		},
	})
	rs.AddOrUpdate("r1", true, cr, "", 0, 0)
	if got := len(rs.Snapshot()); got != 1 {
		t.Errorf("snapshot len after add = %d", got)
	}
	rs.Delete("r1")
	if got := len(rs.Snapshot()); got != 0 {
		t.Errorf("snapshot len after delete = %d", got)
	}
}
