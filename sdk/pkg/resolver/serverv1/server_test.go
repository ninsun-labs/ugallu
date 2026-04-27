// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	resolverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/clientv1"
	serverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/serverv1"
)

// fixturePod builds a sample Pod with two IPs, two containers, an SA,
// and a hostPath volume so the Tier-1 builder has something to chew on.
func fixturePod() *corev1.Pod {
	autoMount := true
	priority := int32(1000)
	hostPathType := corev1.HostPathType("Directory")
	mountProp := corev1.MountPropagationHostToContainer
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "web-abc",
			Namespace:       "default",
			UID:             "pod-uid-001",
			ResourceVersion: "42",
			Labels:          map[string]string{"app": "web"},
		},
		Spec: corev1.PodSpec{
			NodeName:                     "node1",
			ServiceAccountName:           "default",
			HostNetwork:                  false,
			HostPID:                      false,
			HostIPC:                      false,
			AutomountServiceAccountToken: &autoMount,
			PriorityClassName:            "burstable",
			Priority:                     &priority,
			DNSPolicy:                    corev1.DNSClusterFirst,
			Hostname:                     "web-abc",
			Containers: []corev1.Container{
				{
					Name:  "app",
					Image: "ghcr.io/example/app:v1",
					VolumeMounts: []corev1.VolumeMount{
						{Name: "host-data", MountPath: "/data", ReadOnly: true, MountPropagation: &mountProp},
					},
					Env: []corev1.EnvVar{{Name: "FOO"}, {Name: "BAR"}},
				},
			},
			Volumes: []corev1.Volume{
				{Name: "host-data", VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/var/data", Type: &hostPathType},
				}},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.244.3.5",
			PodIPs: []corev1.PodIP{
				{IP: "10.244.3.5"},
				{IP: "fd00::1"},
			},
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ContainerID: "containerd://abc1234567890def", ImageID: "sha256:beef"},
			},
		},
	}
}

func fixtureSA() *corev1.ServiceAccount {
	autoMount := true
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "audit-bot",
			Namespace: "default",
			UID:       "sa-uid-001",
		},
		AutomountServiceAccountToken: &autoMount,
		ImagePullSecrets:             []corev1.LocalObjectReference{{Name: "ghcr-pull"}},
	}
}

func fixtureNode() *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
			UID:  "node-uid-001",
			Labels: map[string]string{
				"node-role.kubernetes.io/control-plane": "",
			},
		},
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{
				{Key: "node-role.kubernetes.io/control-plane", Value: "", Effect: corev1.TaintEffectNoSchedule},
			},
		},
		Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{
				KernelVersion:           "6.19.13-200.fc43.x86_64",
				OSImage:                 "Fedora",
				KubeletVersion:          "v1.32.0",
				ContainerRuntimeVersion: "containerd://1.7.0",
				Architecture:            "amd64",
				OperatingSystem:         "linux",
			},
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
			},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				{Type: corev1.NodeHostName, Address: "node1"},
			},
		},
	}
}

// bootstrap returns a Server backed by a fake clientset seeded with
// the given objects, with informers fully synced.
func bootstrap(t *testing.T, objects ...runtime.Object) *serverv1.Server {
	t.Helper()
	client := fake.NewClientset(objects...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	srv, err := serverv1.Bootstrap(ctx, &serverv1.Options{
		Client:            client,
		TombstoneGrace:    2 * time.Second,
		TombstoneInterval: 500 * time.Millisecond,
		SkipCgroupWalk:    true,
	})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	return srv
}

// decodeTier1 unwraps the JSON Tier-1 payload from a SubjectResponse.
func decodeTier1(t *testing.T, resp *resolverv1.SubjectResponse) *securityv1alpha1.SubjectTier1 {
	t.Helper()
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp.Tier1Json) == 0 {
		return nil
	}
	subj := &securityv1alpha1.SubjectTier1{}
	if err := json.Unmarshal(resp.Tier1Json, subj); err != nil {
		t.Fatalf("decode tier1_json: %v", err)
	}
	return subj
}

// TestResolveByPodUID exercises the primary index lookup.
func TestResolveByPodUID(t *testing.T) {
	srv := bootstrap(t, fixturePod())
	resp, err := srv.ResolveByPodUID(context.Background(), &resolverv1.PodUIDRequest{Uid: "pod-uid-001"})
	if err != nil {
		t.Fatalf("ResolveByPodUID: %v", err)
	}
	if resp.Unresolved {
		t.Fatalf("expected resolved, got unresolved: %s", resp.Diagnostic)
	}
	if resp.Kind != "Pod" || resp.Name != "web-abc" || resp.Namespace != "default" {
		t.Errorf("identity = %+v, want web-abc/default", resp)
	}
	subj := decodeTier1(t, resp)
	if subj.Pod == nil || subj.Pod.NodeName != "node1" {
		t.Errorf("PodSubject.NodeName = %v, want node1", subj.Pod)
	}
	if len(subj.Pod.Containers) != 1 || subj.Pod.Containers[0].Image != "ghcr.io/example/app:v1" {
		t.Errorf("containers = %+v", subj.Pod.Containers)
	}
	if len(subj.Pod.Volumes) != 1 || subj.Pod.Volumes[0].HostPath != "/var/data" {
		t.Errorf("volumes = %+v", subj.Pod.Volumes)
	}
}

// TestResolveByPodIP exercises the IP secondary index for both v4 and v6.
func TestResolveByPodIP(t *testing.T) {
	srv := bootstrap(t, fixturePod())
	for _, ip := range []string{"10.244.3.5", "fd00::1"} {
		t.Run(ip, func(t *testing.T) {
			resp, err := srv.ResolveByPodIP(context.Background(), &resolverv1.PodIPRequest{Ip: ip})
			if err != nil {
				t.Fatalf("ResolveByPodIP: %v", err)
			}
			if resp.Unresolved {
				t.Fatalf("expected resolved, got %s", resp.Diagnostic)
			}
			if resp.Uid != "pod-uid-001" {
				t.Errorf("uid = %q, want pod-uid-001", resp.Uid)
			}
		})
	}
}

// TestResolveByContainerID accepts both prefixed and bare container IDs.
func TestResolveByContainerID(t *testing.T) {
	srv := bootstrap(t, fixturePod())
	for _, id := range []string{"containerd://abc1234567890def", "abc1234567890def"} {
		t.Run(id, func(t *testing.T) {
			resp, err := srv.ResolveByContainerID(context.Background(), &resolverv1.ContainerIDRequest{ContainerId: id})
			if err != nil {
				t.Fatalf("ResolveByContainerID: %v", err)
			}
			if resp.Unresolved {
				t.Fatalf("expected resolved, got %s", resp.Diagnostic)
			}
			if resp.Uid != "pod-uid-001" {
				t.Errorf("uid = %q", resp.Uid)
			}
		})
	}
}

// TestResolveBySAUsername walks the four R4 branches.
func TestResolveBySAUsername(t *testing.T) {
	srv := bootstrap(t, fixtureSA(), fixtureNode())

	cases := []struct {
		name        string
		username    string
		wantKind    string
		wantPartial bool
		wantNs      string
		wantName    string
		wantExtKind string
	}{
		{"sa hit", "system:serviceaccount:default:audit-bot", "ServiceAccount", false, "default", "audit-bot", ""},
		{"sa miss (partial)", "system:serviceaccount:default:ghost", "ServiceAccount", true, "default", "ghost", ""},
		{"node hit", "system:node:node1", "Node", false, "", "node1", ""},
		{"node miss (partial)", "system:node:phantom", "Node", true, "", "phantom", ""},
		{"system:other -> SystemUser external", "system:anonymous", "External", false, "", "system:anonymous", "SystemUser"},
		{"non-system -> ExternalUser", "alice@corp.example", "External", false, "", "alice@corp.example", "ExternalUser"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := srv.ResolveBySAUsername(context.Background(), &resolverv1.SAUsernameRequest{Username: tc.username})
			if err != nil {
				t.Fatalf("ResolveBySAUsername: %v", err)
			}
			if resp.Unresolved {
				t.Fatalf("got unresolved: %s", resp.Diagnostic)
			}
			if resp.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q", resp.Kind, tc.wantKind)
			}
			if resp.Namespace != tc.wantNs {
				t.Errorf("Namespace = %q, want %q", resp.Namespace, tc.wantNs)
			}
			if resp.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", resp.Name, tc.wantName)
			}
			if resp.Partial != tc.wantPartial {
				t.Errorf("Partial = %v, want %v", resp.Partial, tc.wantPartial)
			}
			if tc.wantExtKind != "" {
				subj := decodeTier1(t, resp)
				if subj.External == nil || subj.External.Kind != tc.wantExtKind {
					t.Errorf("External.Kind = %+v, want %s", subj.External, tc.wantExtKind)
				}
			}
		})
	}
}

// TestPodUIDMissBeforeIngest exercises the cache-miss path.
func TestPodUIDMissBeforeIngest(t *testing.T) {
	srv := bootstrap(t)
	resp, err := srv.ResolveByPodUID(context.Background(), &resolverv1.PodUIDRequest{Uid: "ghost"})
	if err != nil {
		t.Fatalf("ResolveByPodUID: %v", err)
	}
	if !resp.Unresolved {
		t.Errorf("expected Unresolved, got %+v", resp)
	}
}

// TestTombstoneOnDelete asserts the GC marks deleted pods as
// tombstoned during the grace window, then purges them.
func TestTombstoneOnDelete(t *testing.T) {
	pod := fixturePod()
	srv := bootstrap(t, pod)

	// Sanity: resolved + not tombstoned.
	resp, _ := srv.ResolveByPodUID(context.Background(), &resolverv1.PodUIDRequest{Uid: "pod-uid-001"})
	if resp.Tombstone {
		t.Fatal("fresh pod is tombstoned")
	}

	// Trigger DELETE through the cache directly (the fake clientset's
	// informer wouldn't reliably send DELETE within the test budget).
	srv.Cache.MarkTombstone(types.UID("pod-uid-001"), time.Now())
	resp, _ = srv.ResolveByPodUID(context.Background(), &resolverv1.PodUIDRequest{Uid: "pod-uid-001"})
	if !resp.Tombstone {
		t.Errorf("expected Tombstone after delete, got %+v", resp)
	}

	// After grace + GC tick, the entry is purged.
	time.Sleep(3 * time.Second)
	resp, _ = srv.ResolveByPodUID(context.Background(), &resolverv1.PodUIDRequest{Uid: "pod-uid-001"})
	if !resp.Unresolved {
		t.Errorf("expected Unresolved after grace, got %+v", resp)
	}
}

// TestResolveByCgroupID_MissAndHit exercises the cgroup-ID index.
func TestResolveByCgroupID_MissAndHit(t *testing.T) {
	srv := bootstrap(t, fixturePod())

	// Miss before indexing.
	resp, _ := srv.ResolveByCgroupID(context.Background(), &resolverv1.CgroupIDRequest{CgroupId: 4242})
	if !resp.Unresolved {
		t.Errorf("expected Unresolved before index, got %+v", resp)
	}

	// Index then hit.
	srv.Cache.IndexCgroup(4242, types.UID("pod-uid-001"), "abc")
	resp, _ = srv.ResolveByCgroupID(context.Background(), &resolverv1.CgroupIDRequest{CgroupId: 4242})
	if resp.Unresolved {
		t.Fatalf("expected Resolved after index, got %s", resp.Diagnostic)
	}
	if resp.Uid != "pod-uid-001" {
		t.Errorf("uid = %q, want pod-uid-001", resp.Uid)
	}
}

// TestResolveByCgroupID_RejectsZero ensures we don't silently treat 0
// as a valid cgroup id.
func TestResolveByCgroupID_RejectsZero(t *testing.T) {
	srv := bootstrap(t)
	resp, _ := srv.ResolveByCgroupID(context.Background(), &resolverv1.CgroupIDRequest{CgroupId: 0})
	if !resp.Unresolved {
		t.Errorf("expected Unresolved for cgroup_id=0, got %+v", resp)
	}
}

// TestResolveByPID_MissOnUnknownPID covers the cross-platform
// "no /proc entry" path.
func TestResolveByPID_MissOnUnknownPID(t *testing.T) {
	srv := bootstrap(t)
	resp, _ := srv.ResolveByPID(context.Background(), &resolverv1.PIDRequest{Pid: 1})
	// On non-Linux this returns the unsupported diag; on Linux a
	// pid=1 read may succeed but won't match a kubepods cgroup. In
	// either case we expect Unresolved=true.
	if !resp.Unresolved {
		t.Errorf("expected Unresolved, got %+v", resp)
	}
}
