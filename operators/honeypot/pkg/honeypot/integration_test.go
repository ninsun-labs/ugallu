// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Integration tests against a real apiserver via envtest. Cover:
//   - the deployer end-to-end (HoneypotConfig → live Secret/SA);
//   - the dispatcher end-to-end (synthesised AuditInput → SE emit
//     via the real Emitter SDK);
//   - the index refresh after a Reconcile (Status.DeployedDecoys
//     populated → Index lookup returns the entry).

package honeypot_test

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"

	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/deployer"
	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/detector"
	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/dispatch"
	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/index"
)

func requireEnvtest(t *testing.T) {
	t.Helper()
	if envCfg == nil {
		t.Skip("envtest not started; set KUBEBUILDER_ASSETS or run `task envtest:assets`")
	}
}

func newDispatcher(t *testing.T, idx *index.Index) *dispatch.Dispatcher {
	t.Helper()
	em, err := emitterv1alpha1.NewEmitter(&emitterv1alpha1.EmitterOpts{
		Client:          envClient,
		AttestorMeta:    sign.AttestorMeta{Name: "ugallu-honeypot", Version: "integration"},
		BurstPerSec:     1000,
		SustainedPerSec: 1000,
	})
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	return dispatch.New(
		[]detector.AuditDetector{
			detector.NewHoneypotTriggeredDetector(idx),
			detector.NewHoneypotMisplacedDetector(idx),
		},
		em,
		securityv1alpha1.ClusterIdentity{ClusterID: "envtest"},
	)
}

func cleanup(t *testing.T) {
	t.Helper()
	var ses securityv1alpha1.SecurityEventList
	if err := envClient.List(envCtx(), &ses); err == nil {
		for ix := range ses.Items {
			_ = envClient.Delete(envCtx(), &ses.Items[ix])
		}
	}
	var hps securityv1alpha1.HoneypotConfigList
	if err := envClient.List(envCtx(), &hps); err == nil {
		for ix := range hps.Items {
			_ = envClient.Delete(envCtx(), &hps.Items[ix])
		}
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

// --- Deployer reconcile ---------------------------------------------

func TestReconciler_MaterialisesDecoysAndRefreshesIndex(t *testing.T) {
	requireEnvtest(t)
	t.Cleanup(func() { cleanup(t) })

	// Pre-create the namespace where the decoy lands.
	ns := "honeypot-decoy-ns-1"
	_ = envClient.Create(envCtx(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})

	cfg := &securityv1alpha1.HoneypotConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "hp-1"},
		Spec: securityv1alpha1.HoneypotConfigSpec{
			EmitOnRead: true,
			Decoys: []securityv1alpha1.HoneypotDecoy{
				{Kind: "Secret", Name: "decoy-creds", Namespace: ns, Data: map[string]string{"foo": "bar"}},
				{Kind: "ServiceAccount", Name: "decoy-uploader", Namespace: ns},
			},
		},
	}
	if err := envClient.Create(envCtx(), cfg); err != nil {
		t.Fatalf("create hp-1: %v", err)
	}

	idx := index.New()
	r := &deployer.HoneypotConfigReconciler{
		Client: envClient,
		Scheme: envScheme,
		Index:  idx,
	}
	if _, err := r.Reconcile(envCtx(), ctrl.Request{NamespacedName: types.NamespacedName{Name: cfg.Name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Decoy Secret created.
	var sec corev1.Secret
	if err := envClient.Get(envCtx(), client.ObjectKey{Name: "decoy-creds", Namespace: ns}, &sec); err != nil {
		t.Fatalf("decoy Secret missing: %v", err)
	}
	if sec.Labels["ugallu.io/decoy"] != "true" {
		t.Errorf("decoy label not set: %v", sec.Labels)
	}
	if sec.Annotations["ugallu.io/honeypot-config"] != "hp-1" {
		t.Errorf("honeypot-config annotation not set: %v", sec.Annotations)
	}

	// Decoy ServiceAccount created.
	var sa corev1.ServiceAccount
	if err := envClient.Get(envCtx(), client.ObjectKey{Name: "decoy-uploader", Namespace: ns}, &sa); err != nil {
		t.Fatalf("decoy SA missing: %v", err)
	}

	// Index refreshed.
	if e := idx.Lookup("secrets", ns, "decoy-creds"); e == nil {
		t.Errorf("Index missing decoy secret entry")
	}
	if e := idx.Lookup("serviceaccounts", ns, "decoy-uploader"); e == nil {
		t.Errorf("Index missing decoy SA entry")
	}

	// Status populated.
	var got securityv1alpha1.HoneypotConfig
	if err := envClient.Get(envCtx(), client.ObjectKey{Name: cfg.Name}, &got); err != nil {
		t.Fatalf("get hp-1: %v", err)
	}
	if len(got.Status.DeployedDecoys) != 2 {
		t.Errorf("DeployedDecoys = %d, want 2", len(got.Status.DeployedDecoys))
	}
	if got.Status.LastReconcileAt == nil {
		t.Errorf("LastReconcileAt should be set")
	}
}

// --- Dispatcher → emitter ---------------------------------------------

func TestDispatcher_HoneypotTriggered_EmitsSE(t *testing.T) {
	requireEnvtest(t)
	t.Cleanup(func() { cleanup(t) })

	idx := index.New()
	idx.Set([]*index.Entry{
		{
			Key:            index.Key{Resource: "secrets", Namespace: "team-a", Name: "decoy-creds"},
			HoneypotConfig: "hp-1",
			EmitOnRead:     true,
		},
	})
	disp := newDispatcher(t, idx)

	ch := make(chan *detector.AuditInput, 1)
	ch <- &detector.AuditInput{
		Verb:            "get",
		UserUsername:    "system:serviceaccount:attacker:bot",
		ObjectResource:  "secrets",
		ObjectNamespace: "team-a",
		ObjectName:      "decoy-creds",
	}
	close(ch)

	ctx, cancel := context.WithTimeout(envCtx(), 5*time.Second)
	defer cancel()
	disp.RunAudit(ctx, ch)

	se := waitForSE(t, securityv1alpha1.TypeHoneypotTriggered, 3*time.Second)
	if se.Spec.Severity != securityv1alpha1.SeverityCritical {
		t.Errorf("severity = %q, want critical", se.Spec.Severity)
	}
}

func TestDispatcher_HoneypotMisplaced_EmitsSE(t *testing.T) {
	requireEnvtest(t)
	t.Cleanup(func() { cleanup(t) })

	idx := index.New()
	idx.Set([]*index.Entry{
		{
			Key:            index.Key{Resource: "secrets", Namespace: "team-a", Name: "decoy-creds"},
			HoneypotConfig: "hp-1",
			EmitOnRead:     true,
		},
	})
	disp := newDispatcher(t, idx)

	body := []byte(`{"spec":{"volumes":[{"name":"x","secret":{"secretName":"decoy-creds"}}]}}`)
	ch := make(chan *detector.AuditInput, 1)
	ch <- &detector.AuditInput{
		Verb:            "create",
		ObjectResource:  "pods",
		ObjectNamespace: "team-a",
		ObjectName:      "exfil-pod",
		RequestObject:   body,
	}
	close(ch)
	ctx, cancel := context.WithTimeout(envCtx(), 5*time.Second)
	defer cancel()
	disp.RunAudit(ctx, ch)

	se := waitForSE(t, securityv1alpha1.TypeHoneypotMisplaced, 3*time.Second)
	if se.Spec.Severity != securityv1alpha1.SeverityHigh {
		t.Errorf("severity = %q, want high", se.Spec.Severity)
	}
}

func TestDispatcher_AllowlistedSAFilters(t *testing.T) {
	requireEnvtest(t)
	t.Cleanup(func() { cleanup(t) })

	idx := index.New()
	idx.Set([]*index.Entry{
		{
			Key:            index.Key{Resource: "secrets", Namespace: "team-a", Name: "decoy-creds"},
			HoneypotConfig: "hp-1",
			AllowedActors:  map[string]bool{"system:serviceaccount:backup:operator": true},
			EmitOnRead:     true,
		},
	})
	disp := newDispatcher(t, idx)

	ch := make(chan *detector.AuditInput, 1)
	ch <- &detector.AuditInput{
		Verb:            "get",
		UserUsername:    "system:serviceaccount:backup:operator",
		ObjectResource:  "secrets",
		ObjectNamespace: "team-a",
		ObjectName:      "decoy-creds",
	}
	close(ch)
	ctx, cancel := context.WithTimeout(envCtx(), 2*time.Second)
	defer cancel()
	disp.RunAudit(ctx, ch)

	time.Sleep(500 * time.Millisecond)
	var list securityv1alpha1.SecurityEventList
	if err := envClient.List(envCtx(), &list); err != nil {
		t.Fatalf("list ses: %v", err)
	}
	for ix := range list.Items {
		if list.Items[ix].Spec.Type == securityv1alpha1.TypeHoneypotTriggered {
			t.Errorf("allowlisted SA must not produce a HoneypotTriggered SE")
		}
	}
}
