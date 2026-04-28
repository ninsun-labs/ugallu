// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Integration tests for the tenant-escape dispatcher against a real
// apiserver via envtest. Drives the dispatcher with synthesised
// AuditInput / ExecInput envelopes (the audit-bus + Tetragon
// sources are exercised via unit tests; this suite covers the
// reconciler → BoundarySet → dispatcher → emitter chain end-to-end).

package tenantescape_test

import (
	"context"
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

	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape"
	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/boundary"
	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/detector"
	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/dispatch"
)

func requireEnvtest(t *testing.T) {
	t.Helper()
	if envCfg == nil {
		t.Skip("envtest not started; set KUBEBUILDER_ASSETS or run `task envtest:assets`")
	}
}

func newDispatcher(t *testing.T, idx detector.BoundarySet) *dispatch.Dispatcher {
	t.Helper()
	em, err := emitterv1alpha1.NewEmitter(&emitterv1alpha1.EmitterOpts{
		Client:          envClient,
		AttestorMeta:    sign.AttestorMeta{Name: "ugallu-tenant-escape", Version: "integration"},
		BurstPerSec:     1000,
		SustainedPerSec: 1000,
	})
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	auditDetectors := []detector.AuditDetector{
		detector.NewCrossTenantSecretAccessDetector(),
		detector.NewCrossTenantHostPathOverlapDetector(),
		detector.NewCrossTenantNetworkPolicyDetector(),
	}
	execDetectors := []detector.ExecDetector{detector.NewCrossTenantExecDetector()}
	return dispatch.New(auditDetectors, execDetectors, idx, em, securityv1alpha1.ClusterIdentity{ClusterID: "envtest"})
}

func cleanupSEs(t *testing.T) {
	t.Helper()
	var ses securityv1alpha1.SecurityEventList
	if err := envClient.List(envCtx(), &ses); err != nil {
		t.Logf("cleanup list: %v", err)
		return
	}
	for ix := range ses.Items {
		_ = envClient.Delete(envCtx(), &ses.Items[ix])
	}
	var tbs securityv1alpha1.TenantBoundaryList
	if err := envClient.List(envCtx(), &tbs); err != nil {
		return
	}
	for ix := range tbs.Items {
		_ = envClient.Delete(envCtx(), &tbs.Items[ix])
	}
}

func waitForSE(t *testing.T, seType string, timeout time.Duration) *securityv1alpha1.SecurityEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var list securityv1alpha1.SecurityEventList
		if err := envClient.List(envCtx(), &list); err == nil {
			for ix := range list.Items {
				if list.Items[ix].Spec.Type == seType {
					return &list.Items[ix]
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for SE type %q", seType)
	return nil
}

func TestDispatcher_CrossTenantSecretAccess_EmitsSE(t *testing.T) {
	requireEnvtest(t)
	t.Cleanup(func() { cleanupSEs(t) })

	idx := boundary.NewIndex()
	idx.Refresh([]securityv1alpha1.TenantBoundary{
		{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}, Status: securityv1alpha1.TenantBoundaryStatus{MatchedNamespaces: []string{"team-a"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "team-b"}, Status: securityv1alpha1.TenantBoundaryStatus{MatchedNamespaces: []string{"team-b"}}},
	})
	disp := newDispatcher(t, idx)

	ch := make(chan *detector.AuditInput, 1)
	ch <- &detector.AuditInput{
		Verb:            "get",
		UserUsername:    "system:serviceaccount:team-a:bot",
		UserNamespace:   "team-a",
		ObjectResource:  "secrets",
		ObjectNamespace: "team-b",
		ObjectName:      "shared-creds",
	}
	close(ch)

	ctx, cancel := context.WithTimeout(envCtx(), 5*time.Second)
	defer cancel()
	disp.RunAudit(ctx, ch)

	se := waitForSE(t, securityv1alpha1.TypeCrossTenantSecretAccess, 3*time.Second)
	if se.Spec.Severity != securityv1alpha1.SeverityHigh {
		t.Errorf("severity = %q, want high", se.Spec.Severity)
	}
}

func TestDispatcher_CrossTenantHostPathOverlap_EmitsSE(t *testing.T) {
	requireEnvtest(t)
	t.Cleanup(func() { cleanupSEs(t) })

	idx := boundary.NewIndex()
	idx.Refresh([]securityv1alpha1.TenantBoundary{
		{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}, Status: securityv1alpha1.TenantBoundaryStatus{MatchedNamespaces: []string{"team-a"}}},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "team-b"},
			Spec:       securityv1alpha1.TenantBoundarySpec{HostPathPolicy: securityv1alpha1.HostPathPolicy{Allow: []string{"/var/lib/team-b/"}}},
			Status:     securityv1alpha1.TenantBoundaryStatus{MatchedNamespaces: []string{"team-b"}},
		},
	})
	disp := newDispatcher(t, idx)

	body := []byte(`{"spec":{"volumes":[{"hostPath":{"path":"/var/lib/team-b/secrets"}}]}}`)
	ch := make(chan *detector.AuditInput, 1)
	ch <- &detector.AuditInput{
		Verb:            "create",
		ObjectResource:  "pods",
		ObjectNamespace: "team-a",
		ObjectName:      "evil-pod",
		RequestObject:   body,
	}
	close(ch)
	ctx, cancel := context.WithTimeout(envCtx(), 5*time.Second)
	defer cancel()
	disp.RunAudit(ctx, ch)

	se := waitForSE(t, securityv1alpha1.TypeCrossTenantHostPathOverlap, 3*time.Second)
	if se.Spec.Severity != securityv1alpha1.SeverityCritical {
		t.Errorf("severity = %q, want critical", se.Spec.Severity)
	}
}

func TestDispatcher_CrossTenantExec_EmitsSE(t *testing.T) {
	requireEnvtest(t)
	t.Cleanup(func() { cleanupSEs(t) })

	idx := boundary.NewIndex()
	idx.Refresh([]securityv1alpha1.TenantBoundary{
		{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}, Status: securityv1alpha1.TenantBoundaryStatus{MatchedNamespaces: []string{"team-a"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "team-b"}, Status: securityv1alpha1.TenantBoundaryStatus{MatchedNamespaces: []string{"team-b"}}},
	})
	disp := newDispatcher(t, idx)

	ch := make(chan *detector.ExecInput, 1)
	ch <- &detector.ExecInput{
		ExecutorPodNamespace: "team-a",
		ExecutorUsername:     "system:serviceaccount:team-a:bot",
		TargetPodNamespace:   "team-b",
		TargetPodName:        "victim",
		Command:              "/bin/sh",
	}
	close(ch)
	ctx, cancel := context.WithTimeout(envCtx(), 5*time.Second)
	defer cancel()
	disp.RunExec(ctx, ch)

	se := waitForSE(t, securityv1alpha1.TypeCrossTenantExec, 3*time.Second)
	if se.Spec.Severity != securityv1alpha1.SeverityCritical {
		t.Errorf("severity = %q, want critical", se.Spec.Severity)
	}
}

func TestReconciler_RefreshesIndexFromCRs(t *testing.T) {
	requireEnvtest(t)
	t.Cleanup(func() { cleanupSEs(t) })

	tb := &securityv1alpha1.TenantBoundary{
		ObjectMeta: metav1.ObjectMeta{Name: "tb-reconcile-test"},
		Spec: securityv1alpha1.TenantBoundarySpec{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "tb-reconcile-test"}},
			HostPathPolicy:    securityv1alpha1.HostPathPolicy{Allow: []string{"/var/lib/tb-reconcile-test/"}},
		},
	}
	if err := envClient.Create(envCtx(), tb); err != nil {
		t.Fatalf("create tb: %v", err)
	}

	idx := boundary.NewIndex()
	r := &tenantescape.TenantBoundaryReconciler{
		Client: envClient,
		Scheme: envScheme,
		Index:  idx,
	}

	if _, err := r.Reconcile(envCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: tb.Name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// HostPath prefix should now be claimed by tb-reconcile-test.
	if got := idx.HostPathTenantOf("/var/lib/tb-reconcile-test/data"); got != "tb-reconcile-test" {
		t.Errorf("HostPathTenantOf = %q, want tb-reconcile-test", got)
	}

	// Status should have been written back.
	var got securityv1alpha1.TenantBoundary
	if err := envClient.Get(envCtx(), client.ObjectKey{Name: tb.Name}, &got); err != nil {
		if !apierrors.IsNotFound(err) {
			t.Fatalf("get tb: %v", err)
		}
	}
	if got.Status.LastReconcileAt == nil {
		t.Errorf("LastReconcileAt should be set after Reconcile")
	}
}

func TestDispatcher_AllowlistedSAFilters(t *testing.T) {
	requireEnvtest(t)
	t.Cleanup(func() { cleanupSEs(t) })

	idx := boundary.NewIndex()
	idx.Refresh([]securityv1alpha1.TenantBoundary{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "team-a"},
			Spec:       securityv1alpha1.TenantBoundarySpec{ServiceAccountAllowlist: []string{"system:serviceaccount:kube-system:cluster-controller"}},
			Status:     securityv1alpha1.TenantBoundaryStatus{MatchedNamespaces: []string{"team-a"}},
		},
		{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}, Status: securityv1alpha1.TenantBoundaryStatus{MatchedNamespaces: []string{"kube-system"}}},
	})
	disp := newDispatcher(t, idx)

	ch := make(chan *detector.AuditInput, 1)
	ch <- &detector.AuditInput{
		Verb:            "get",
		UserUsername:    "system:serviceaccount:kube-system:cluster-controller",
		UserNamespace:   "kube-system",
		ObjectResource:  "secrets",
		ObjectNamespace: "team-a",
	}
	close(ch)
	ctx, cancel := context.WithTimeout(envCtx(), 2*time.Second)
	defer cancel()
	disp.RunAudit(ctx, ch)

	// Give the (no-)emit goroutine a window to settle, then assert
	// no SE was created.
	time.Sleep(500 * time.Millisecond)
	var list securityv1alpha1.SecurityEventList
	if err := envClient.List(envCtx(), &list); err != nil {
		t.Fatalf("list ses: %v", err)
	}
	for ix := range list.Items {
		if list.Items[ix].Spec.Type == securityv1alpha1.TypeCrossTenantSecretAccess {
			t.Errorf("allowlisted SA must not produce a CrossTenantSecretAccess SE")
		}
	}
}
