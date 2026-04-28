// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitter "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
	resolverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/clientv1"
	"google.golang.org/grpc"
)

// fakeResolver is a minimal ResolverClient that returns a stubbed
// SubjectResponse on ResolveByPodUID. Other methods are unimplemented.
type fakeResolver struct {
	resolverv1.ResolverClient
	calls    atomic.Int32
	response *resolverv1.SubjectResponse
	err      error
}

func (f *fakeResolver) ResolveByPodUID(_ context.Context, _ *resolverv1.PodUIDRequest, _ ...grpc.CallOption) (*resolverv1.SubjectResponse, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return f.response, nil
}

func newK8sClient(t *testing.T) client.Client {
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

func mustEmitter(t *testing.T, c client.Client, r resolverv1.ResolverClient) *emitter.Emitter {
	t.Helper()
	e, err := emitter.NewEmitter(&emitter.EmitterOpts{
		Client:          c,
		Resolver:        r,
		AttestorMeta:    sign.AttestorMeta{Name: "test-source", Version: "v0.0.1"},
		BurstPerSec:     1000,
		SustainedPerSec: 1000,
	})
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	return e
}

func ptrOf[T any](v T) *T { return &v }

func sampleOpts() emitter.EmitOpts {
	return emitter.EmitOpts{
		Class:            securityv1alpha1.ClassDetection,
		Type:             securityv1alpha1.TypeAnonymousAccess,
		Severity:         securityv1alpha1.SeverityHigh,
		SubjectKind:      securityv1alpha1.SubjectKind("Pod"),
		SubjectName:      "nginx",
		SubjectNamespace: "default",
		SubjectUID:       "test-uid-001",
		ClusterIdentity:  securityv1alpha1.ClusterIdentity{ClusterID: "test"},
	}
}

func TestEmit_HappyPath(t *testing.T) {
	c := newK8sClient(t)
	e := mustEmitter(t, c, nil)
	se, err := e.Emit(context.Background(), ptrOf(sampleOpts()))
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if se.Spec.Type != securityv1alpha1.TypeAnonymousAccess {
		t.Errorf("type = %q", se.Spec.Type)
	}
	if se.Spec.CorrelationID == "" {
		t.Error("correlationID empty")
	}
	if se.Name == "" {
		t.Error("name empty (deterministic name expected)")
	}
}

func TestEmit_RejectsUnknownType(t *testing.T) {
	c := newK8sClient(t)
	e := mustEmitter(t, c, nil)
	opts := sampleOpts()
	opts.Type = "TotallyMadeUpType"
	if _, err := e.Emit(context.Background(), &opts); !errors.Is(err, emitter.ErrInvalidType) {
		t.Errorf("expected ErrInvalidType, got %v", err)
	}
}

func TestEmit_RejectsMissingSubject(t *testing.T) {
	c := newK8sClient(t)
	e := mustEmitter(t, c, nil)
	opts := sampleOpts()
	opts.SubjectName = ""
	opts.SubjectUID = ""
	if _, err := e.Emit(context.Background(), &opts); !errors.Is(err, emitter.ErrSubjectMissing) {
		t.Errorf("expected ErrSubjectMissing, got %v", err)
	}
}

func TestEmit_IdempotentWithinCorrelationWindow(t *testing.T) {
	c := newK8sClient(t)
	e := mustEmitter(t, c, nil)
	se1, err := e.Emit(context.Background(), ptrOf(sampleOpts()))
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	se2, err := e.Emit(context.Background(), ptrOf(sampleOpts()))
	if err != nil {
		t.Fatalf("second Emit: %v", err)
	}
	if se1.Name != se2.Name {
		t.Errorf("name should match (idempotent): %s vs %s", se1.Name, se2.Name)
	}
	// Only one SE actually exists in the cluster.
	list := &securityv1alpha1.SecurityEventList{}
	if err := c.List(context.Background(), list); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Errorf("expected 1 SE in cluster, got %d", len(list.Items))
	}
}

func TestEmit_DistinctCorrelationIDPerBucket(t *testing.T) {
	c := newK8sClient(t)
	e := mustEmitter(t, c, nil)
	opts1 := sampleOpts()
	opts1.CorrelationID = "explicit-corr-1"
	opts2 := sampleOpts()
	opts2.CorrelationID = "explicit-corr-2"

	se1, err := e.Emit(context.Background(), &opts1)
	if err != nil {
		t.Fatalf("Emit 1: %v", err)
	}
	se2, err := e.Emit(context.Background(), &opts2)
	if err != nil {
		t.Fatalf("Emit 2: %v", err)
	}
	if se1.Name == se2.Name {
		t.Errorf("different correlationIDs should yield different SE names")
	}
}

func TestEmit_ResolverEnrichment_HappyPath(t *testing.T) {
	c := newK8sClient(t)
	enriched := securityv1alpha1.SubjectTier1{
		Kind:      securityv1alpha1.SubjectKind("Pod"),
		Name:      "enriched-pod",
		Namespace: "kube-system",
		UID:       "enriched-uid-999",
		Pod:       &securityv1alpha1.PodSubject{NodeName: "node-x"},
	}
	tier1JSON, err := json.Marshal(enriched)
	if err != nil {
		t.Fatalf("marshal enriched: %v", err)
	}
	resolver := &fakeResolver{
		response: &resolverv1.SubjectResponse{
			Tier1Json: tier1JSON,
		},
	}
	e := mustEmitter(t, c, resolver)
	opts := sampleOpts()
	opts.EnrichVia = emitter.EnrichByPodUID
	opts.EnrichKey = "enriched-uid-999"
	se, err := e.Emit(context.Background(), &opts)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := resolver.calls.Load(); got != 1 {
		t.Errorf("resolver calls = %d, want 1", got)
	}
	if se.Spec.Subject.Name != "enriched-pod" {
		t.Errorf("subject.name = %q, want enriched-pod", se.Spec.Subject.Name)
	}
	if se.Spec.Subject.Pod == nil || se.Spec.Subject.Pod.NodeName != "node-x" {
		t.Errorf("expected enriched Pod discriminator with nodeName=node-x")
	}
}

func TestEmit_ResolverFailure_FlagsPartial(t *testing.T) {
	c := newK8sClient(t)
	resolver := &fakeResolver{err: errors.New("boom")}
	e := mustEmitter(t, c, resolver)
	opts := sampleOpts()
	opts.EnrichVia = emitter.EnrichByPodUID
	opts.EnrichKey = "uid-x"
	se, err := e.Emit(context.Background(), &opts)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !se.Spec.Subject.Partial {
		t.Error("expected Subject.Partial=true on resolver failure")
	}
}

func TestEmit_DetectedAtPropagated(t *testing.T) {
	c := newK8sClient(t)
	e := mustEmitter(t, c, nil)
	opts := sampleOpts()
	custom := metav1.NewTime(time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC))
	opts.DetectedAt = custom
	se, err := e.Emit(context.Background(), &opts)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !se.Spec.DetectedAt.Equal(&custom) {
		t.Errorf("DetectedAt = %v, want %v", se.Spec.DetectedAt, custom)
	}
}

func TestEmit_NewEmitterRejectsBadOpts(t *testing.T) {
	cases := []struct {
		name string
		opts *emitter.EmitterOpts
	}{
		{"nil", nil},
		{"missing Client", &emitter.EmitterOpts{AttestorMeta: sign.AttestorMeta{Name: "x"}}},
		{"missing AttestorMeta.Name", &emitter.EmitterOpts{Client: newK8sClient(t)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := emitter.NewEmitter(tc.opts); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

// rejectingClient simulates a transient apiserver failure to exercise
// the buffer enqueue path. The first N Create calls return a 503;
// later ones succeed.
type rejectingClient struct {
	client.Client
	failsLeft atomic.Int32
}

func (r *rejectingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if r.failsLeft.Add(-1) >= 0 {
		return apierrors.NewServiceUnavailable("simulated outage")
	}
	return r.Client.Create(ctx, obj, opts...)
}

// avoid unused-imports.
var _ schema.GroupVersionKind = securityv1alpha1.GroupVersion.WithKind("SecurityEvent")

func TestEmit_TransientErrorEnqueuesForRetry(t *testing.T) {
	inner := newK8sClient(t)
	rc := &rejectingClient{Client: inner}
	rc.failsLeft.Store(3)
	e, err := emitter.NewEmitter(&emitter.EmitterOpts{
		Client:          rc,
		AttestorMeta:    sign.AttestorMeta{Name: "test"},
		BufferSize:      4,
		BurstPerSec:     100,
		SustainedPerSec: 100,
	})
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	se, err := e.Emit(context.Background(), ptrOf(sampleOpts()))
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	// Either way the caller got a populated SE; the buffer takes the
	// retry. With no Start() the buffer just holds it — only the
	// happy-path assertion (no error + populated name) is checked.
	if se.Name == "" {
		t.Error("se.Name should be set for transient enqueue")
	}
}
