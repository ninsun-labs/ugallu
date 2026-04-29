// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"errors"
	"net"
	"testing"

	dnseventv1 "github.com/ninsun-labs/coredns-ugallu/proto/v1"
	"google.golang.org/grpc"

	resolverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/clientv1"
)

// fakeResolver records calls and returns the configured response. The
// per-method err/resp fields make it easy to model both miss and
// success paths in a single test.
type fakeResolver struct {
	cgroupResp *resolverv1.SubjectResponse
	cgroupErr  error
	ipResp     *resolverv1.SubjectResponse
	ipErr      error

	cgroupCalls int
	ipCalls     int
	lastCgroup  uint64
	lastIP      string
}

func (f *fakeResolver) ResolveByCgroupID(_ context.Context, in *resolverv1.CgroupIDRequest, _ ...grpc.CallOption) (*resolverv1.SubjectResponse, error) {
	f.cgroupCalls++
	f.lastCgroup = in.GetCgroupId()
	return f.cgroupResp, f.cgroupErr
}

func (f *fakeResolver) ResolveByPodIP(_ context.Context, in *resolverv1.PodIPRequest, _ ...grpc.CallOption) (*resolverv1.SubjectResponse, error) {
	f.ipCalls++
	f.lastIP = in.GetIp()
	return f.ipResp, f.ipErr
}

// TestToEnriched_CgroupHit verifies the fast UDS path: cgroup lookup
// returns a Pod, IP fallback is not invoked.
func TestToEnriched_CgroupHit(t *testing.T) {
	fr := &fakeResolver{
		cgroupResp: &resolverv1.SubjectResponse{
			Kind: "Pod", Name: "client-pod", Namespace: "team-a", Uid: "pod-uid-cg-1",
		},
	}
	s, err := NewCoreDNSPluginSource(&CoreDNSPluginConfig{GRPCEndpoint: "x:1", Resolver: fr})
	if err != nil {
		t.Fatalf("NewCoreDNSPluginSource: %v", err)
	}
	ev := &dnseventv1.DNSEvent{
		Qname:       "example.com",
		Qtype:       "A",
		SrcIp:       net.IPv4(10, 244, 1, 5).To4(),
		SrcCgroupId: 4242,
	}
	out := s.toEnriched(context.Background(), ev)
	if out == nil {
		t.Fatal("toEnriched returned nil")
	}
	if out.Pod.Namespace != "team-a" || out.Pod.Name != "client-pod" {
		t.Errorf("Pod = %+v, want team-a/client-pod", out.Pod)
	}
	if string(out.SubjectUID) != "pod-uid-cg-1" {
		t.Errorf("SubjectUID = %q, want pod-uid-cg-1", out.SubjectUID)
	}
	if fr.cgroupCalls != 1 {
		t.Errorf("cgroupCalls = %d, want 1", fr.cgroupCalls)
	}
	if fr.ipCalls != 0 {
		t.Errorf("ipCalls = %d, want 0 (cgroup hit should short-circuit)", fr.ipCalls)
	}
	if fr.lastCgroup != 4242 {
		t.Errorf("lastCgroup = %d, want 4242", fr.lastCgroup)
	}
}

// TestToEnriched_CgroupMissThenIPHit covers the fallback chain: the
// cgroup lookup misses (Unresolved), the Pod-IP lookup succeeds.
func TestToEnriched_CgroupMissThenIPHit(t *testing.T) {
	fr := &fakeResolver{
		cgroupResp: &resolverv1.SubjectResponse{Unresolved: true},
		ipResp: &resolverv1.SubjectResponse{
			Kind: "Pod", Name: "client-pod", Namespace: "team-b", Uid: "pod-uid-ip-1",
		},
	}
	s, _ := NewCoreDNSPluginSource(&CoreDNSPluginConfig{GRPCEndpoint: "x:1", Resolver: fr})
	ev := &dnseventv1.DNSEvent{
		SrcIp:       net.IPv4(10, 244, 7, 7).To4(),
		SrcCgroupId: 99,
	}
	out := s.toEnriched(context.Background(), ev)
	if out.Pod.Namespace != "team-b" {
		t.Errorf("Pod.Namespace = %q, want team-b", out.Pod.Namespace)
	}
	if fr.ipCalls != 1 {
		t.Errorf("ipCalls = %d, want 1", fr.ipCalls)
	}
	if fr.lastIP != "10.244.7.7" {
		t.Errorf("lastIP = %q", fr.lastIP)
	}
}

// TestToEnriched_BothMiss leaves Pod empty so the detector layer can
// fall back to its SrcIP-derived synthetic UID.
func TestToEnriched_BothMiss(t *testing.T) {
	fr := &fakeResolver{
		cgroupErr: errors.New("connection refused"),
		ipResp:    &resolverv1.SubjectResponse{Unresolved: true},
	}
	s, _ := NewCoreDNSPluginSource(&CoreDNSPluginConfig{GRPCEndpoint: "x:1", Resolver: fr})
	ev := &dnseventv1.DNSEvent{
		SrcIp:       net.IPv4(10, 0, 0, 1).To4(),
		SrcCgroupId: 1,
	}
	out := s.toEnriched(context.Background(), ev)
	if out.Pod.Namespace != "" || out.Pod.Name != "" {
		t.Errorf("Pod should be empty on both-miss; got %+v", out.Pod)
	}
	if out.SubjectUID != "" {
		t.Errorf("SubjectUID should be empty on both-miss; got %q", out.SubjectUID)
	}
	if fr.cgroupCalls != 1 || fr.ipCalls != 1 {
		t.Errorf("expected one call to each resolver method; got cgroup=%d ip=%d", fr.cgroupCalls, fr.ipCalls)
	}
}

// TestToEnriched_NoResolver leaves the event untouched and the source
// must still translate the wire shape correctly.
func TestToEnriched_NoResolver(t *testing.T) {
	s, _ := NewCoreDNSPluginSource(&CoreDNSPluginConfig{GRPCEndpoint: "x:1"})
	ev := &dnseventv1.DNSEvent{
		Qname:       "example.com",
		Qtype:       "A",
		SrcIp:       net.IPv4(10, 1, 1, 1).To4(),
		SrcCgroupId: 7,
	}
	out := s.toEnriched(context.Background(), ev)
	if out == nil {
		t.Fatal("toEnriched returned nil")
	}
	if out.Pod.Namespace != "" || out.Pod.Name != "" {
		t.Errorf("Pod should be empty when Resolver is nil; got %+v", out.Pod)
	}
	if out.SrcCgroup != 7 {
		t.Errorf("SrcCgroup = %d, want 7 (pbToInternal must still run)", out.SrcCgroup)
	}
}
