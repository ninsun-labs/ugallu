// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package seccompgen

import (
	"encoding/json"
	"fmt"
)

// BuildSeccompProfile renders a runtime-spec-style seccomp profile
// from a Capture. The output is the JSON byte slice persisted on
// SeccompTrainingProfile.Spec.ProfileJSON. defaultAction is whatever
// the run requested (SCMP_ACT_ERRNO etc.).
func BuildSeccompProfile(capture *Capture, defaultAction string) ([]byte, error) {
	if capture == nil {
		return nil, fmt.Errorf("nil capture")
	}
	prof := seccompProfile{
		DefaultAction: defaultAction,
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		Syscalls: []seccompSyscall{
			{
				Names:  capture.Syscalls,
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
	return json.MarshalIndent(prof, "", "  ")
}

// seccompProfile mirrors the OCI runtime-spec LinuxSeccomp shape that
// containerd / cri-o consume when a Pod points to a localhost profile.
type seccompProfile struct {
	DefaultAction string           `json:"defaultAction"`
	Architectures []string         `json:"architectures,omitempty"`
	Syscalls      []seccompSyscall `json:"syscalls,omitempty"`
}

type seccompSyscall struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}
