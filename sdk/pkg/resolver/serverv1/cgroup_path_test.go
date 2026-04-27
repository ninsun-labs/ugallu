// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1_test

import (
	"testing"

	serverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/serverv1"
)

func TestParseCgroupPath(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		wantOK  bool
		wantUID string
		wantCtr string
		wantQOS string
	}{
		{
			name:    "burstable container scope (containerd)",
			path:    "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123abc_456def_789.slice/cri-containerd-deadbeef.scope",
			wantOK:  true,
			wantUID: "123abc-456def-789",
			wantCtr: "deadbeef",
			wantQOS: "burstable",
		},
		{
			name:    "besteffort scope (crio)",
			path:    "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod99887766.slice/crio-cafef00d.scope",
			wantOK:  true,
			wantUID: "99887766",
			wantCtr: "cafef00d",
			wantQOS: "besteffort",
		},
		{
			name:    "guaranteed pod (no qos parent)",
			path:    "/kubepods.slice/kubepods-pod_aabbcc.slice/cri-containerd-12345.scope",
			wantOK:  true,
			wantUID: "-aabbcc",
			wantCtr: "12345",
			wantQOS: "guaranteed",
		},
		{
			name:    "pod-level slice (no container scope yet)",
			path:    "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc_def.slice",
			wantOK:  true,
			wantUID: "abc-def",
			wantCtr: "",
			wantQOS: "burstable",
		},
		{
			name:    "absolute /sys/fs/cgroup-prefixed path",
			path:    "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-x.scope",
			wantOK:  true,
			wantUID: "123",
			wantCtr: "x",
			wantQOS: "burstable",
		},
		{
			name:   "non-kubepods path",
			path:   "/system.slice/sshd.service",
			wantOK: false,
		},
		{
			name:   "empty",
			path:   "",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, ok := serverv1.ParseCgroupPath(tc.path)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if info.PodUID != tc.wantUID {
				t.Errorf("PodUID = %q, want %q", info.PodUID, tc.wantUID)
			}
			if info.ContainerID != tc.wantCtr {
				t.Errorf("ContainerID = %q, want %q", info.ContainerID, tc.wantCtr)
			}
			if info.QOSClass != tc.wantQOS {
				t.Errorf("QOSClass = %q, want %q", info.QOSClass, tc.wantQOS)
			}
		})
	}
}
