// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Integration tests for the dns-detect dispatcher against a real
// apiserver via envtest. The plugin/Tetragon source backends are
// stubs in Sprint 3, so the dispatcher is driven directly with
// synthesised DNSEvent values - no real DNS in the loop. This
// covers the SDK plumbing (config load → detector build → dispatch
// → SE emit) end-to-end against an envtest control plane.

package dnsdetect_test

import (
	"context"
	"net"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsdetect"
	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsdetect/detector"
	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsevent"
)

func requireEnvtest(t *testing.T) {
	t.Helper()
	if envCfg == nil {
		t.Skip("envtest not started; set KUBEBUILDER_ASSETS or run `task envtest:assets`")
	}
}

func newDispatcher(t *testing.T) *dnsdetect.Dispatcher {
	t.Helper()
	em, err := emitterv1alpha1.NewEmitter(&emitterv1alpha1.EmitterOpts{
		Client:          envClient,
		AttestorMeta:    sign.AttestorMeta{Name: "ugallu-dns-detect", Version: "integration"},
		BurstPerSec:     1000,
		SustainedPerSec: 1000,
	})
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	det := []detector.Detector{
		detector.NewExfiltrationDetector(detector.ExfiltrationConfig{
			MinLabelLen: 16, MinEntropy: 3.5, ConsecutiveTriggers: 1,
		}),
		detector.NewAnomalousPortDetector(),
	}
	return dnsdetect.NewDispatcher(det, em, securityv1alpha1.ClusterIdentity{ClusterID: "envtest"})
}

func cleanupSEs(t *testing.T) {
	t.Helper()
	list := &securityv1alpha1.SecurityEventList{}
	if err := envClient.List(envCtx(), list); err != nil && !apierrors.IsNotFound(err) {
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

func mkEvent(qname, qtype string, dstPort uint16) *dnsevent.DNSEvent {
	return &dnsevent.DNSEvent{
		Source:     dnsevent.SourceCoreDNSPlugin,
		Timestamp:  time.Now(),
		QName:      qname,
		QType:      qtype,
		DstIP:      net.IPv4(10, 0, 0, 53),
		DstPort:    dstPort,
		SrcIP:      net.IPv4(10, 244, 1, 5),
		PayloadLen: len(qname),
		Pod:        types.NamespacedName{Namespace: "team-a", Name: "client-pod"},
		SubjectUID: types.UID("pod-uid-int-1"),
	}
}

// --- Scenario 1: AnomalousPort fires + SE emitted via real SDK ------
func TestIntegration_AnomalousPort_EmitsSE(t *testing.T) {
	requireEnvtest(t)
	cleanupSEs(t)

	disp := newDispatcher(t)

	ctx, cancel := context.WithCancel(envCtx())
	defer cancel()
	src := make(chan *dnsevent.DNSEvent, 1)
	go disp.Run(ctx, src)

	src <- mkEvent("normal.example.com", "A", 5353)
	close(src)

	se := waitForSEByType(t, securityv1alpha1.TypeDNSAnomalousPort, 5*time.Second)
	if se == nil {
		t.Fatalf("DNSAnomalousPort SE never emitted")
	}
	if se.Spec.Severity != securityv1alpha1.SeverityMedium {
		t.Errorf("Severity = %q, want medium", se.Spec.Severity)
	}
}

// --- Scenario 2: Exfiltration fires after consecutive high-entropy --
func TestIntegration_Exfiltration_EmitsSE(t *testing.T) {
	requireEnvtest(t)
	cleanupSEs(t)

	disp := newDispatcher(t)
	ctx, cancel := context.WithCancel(envCtx())
	defer cancel()
	src := make(chan *dnsevent.DNSEvent, 4)
	go disp.Run(ctx, src)

	// 3 high-entropy queries from same Subject; ConsecutiveTriggers=1
	// in newDispatcher fires on the first.
	highEntropy := "abcdefghijklmnopqrstuvwxyz0123456789abcdef.example.com"
	src <- mkEvent(highEntropy, "TXT", 53)
	close(src)

	se := waitForSEByType(t, securityv1alpha1.TypeDNSExfiltration, 5*time.Second)
	if se == nil {
		t.Fatalf("DNSExfiltration SE never emitted")
	}
}

// --- Scenario 3: DNSDetectConfig load round-trip ---------------------
func TestIntegration_DNSDetectConfigLifecycle(t *testing.T) {
	requireEnvtest(t)

	cfg := &securityv1alpha1.DNSDetectConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: securityv1alpha1.DNSDetectConfigSpec{
			Source: securityv1alpha1.DNSSourceConfig{
				Primary: securityv1alpha1.DNSDetectSourceCoreDNSPlugin,
				Plugin: &securityv1alpha1.DNSPluginEndpoint{
					GRPCEndpoint: "coredns.kube-system.svc.cluster.local:8443",
				},
			},
			Detectors: securityv1alpha1.DNSDetectorsConfig{
				AnomalousPort: securityv1alpha1.AnomalousPortDetectorConfig{Enabled: true},
			},
		},
	}
	if err := envClient.Create(envCtx(), cfg); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("Create DNSDetectConfig: %v", err)
	}
	defer func() {
		_ = envClient.Delete(envCtx(), cfg)
	}()

	got := &securityv1alpha1.DNSDetectConfig{}
	if err := envClient.Get(envCtx(), types.NamespacedName{Name: "default"}, got); err != nil {
		t.Fatalf("Get DNSDetectConfig: %v", err)
	}
	if got.Spec.Source.Primary != securityv1alpha1.DNSDetectSourceCoreDNSPlugin {
		t.Errorf("Spec.Source.Primary = %q, want coredns_plugin", got.Spec.Source.Primary)
	}
}
