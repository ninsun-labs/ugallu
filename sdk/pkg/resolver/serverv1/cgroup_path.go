// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1

import "strings"

// CRI runtime prefixes that may decorate the container .scope segment
// of a cgroup path. Order doesn't matter; the first match is stripped.
var criScopePrefixes = []string{
	"cri-containerd-",
	"crio-",
	"docker-",
	"containerd-",
}

// CgroupPathInfo carries everything extracted from a cgroup directory
// path with no further filesystem access.
type CgroupPathInfo struct {
	// PodUID is the K8s Pod UID with hyphens (cgroup paths use
	// underscores). Empty when the path is not a kubepods slice.
	PodUID string

	// ContainerID is the bare hex container ID (no CRI scheme,
	// no .scope suffix). Empty when the path describes a pod-level
	// slice without a container scope.
	ContainerID string

	// QOSClass is one of "guaranteed", "burstable", "besteffort", or
	// empty when the path doesn't carry a QoS hint (Guaranteed pods
	// land directly under kubepods.slice in cgroup v2).
	QOSClass string
}

// ParseCgroupPath extracts pod UID, container ID, and QoS class from
// a cgroup path. Accepts both the raw kernel path
// ("/kubepods.slice/...") and a /sys/fs/cgroup-relative path; the
// leading "/sys/fs/cgroup" prefix is stripped if present.
//
// Examples (cgroup v2 with systemd):
//
//	/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123_456.slice/cri-containerd-abc.scope
//	/sys/fs/cgroup/kubepods.slice/kubepods-pod123_456.slice/cri-containerd-abc.scope
//
// Returns ok=false when no kubepods pod slice is present in the path.
func ParseCgroupPath(p string) (CgroupPathInfo, bool) {
	if i := strings.Index(p, "/kubepods"); i >= 0 {
		p = p[i:]
	} else {
		return CgroupPathInfo{}, false
	}
	parts := strings.Split(p, "/")
	var info CgroupPathInfo
	for _, seg := range parts {
		switch {
		case strings.HasPrefix(seg, "kubepods-burstable"):
			info.QOSClass = "burstable"
		case strings.HasPrefix(seg, "kubepods-besteffort"):
			info.QOSClass = "besteffort"
		}
		if uid, ok := podUIDFromSegment(seg); ok {
			info.PodUID = uid
		}
		if id, ok := containerIDFromScope(seg); ok {
			info.ContainerID = id
		}
	}
	if info.PodUID == "" {
		return CgroupPathInfo{}, false
	}
	if info.QOSClass == "" {
		// Guaranteed pods sit directly under kubepods.slice with no
		// QoS-specific parent; mark explicitly so callers can tell.
		info.QOSClass = "guaranteed"
	}
	return info, true
}

// podUIDFromSegment recognises the pod slice convention:
//
//	kubepods-pod<UID>.slice
//	kubepods-burstable-pod<UID>.slice
//	kubepods-besteffort-pod<UID>.slice
//
// The UID in cgroup paths uses underscores in place of hyphens; this
// function restores the canonical hyphenated form.
func podUIDFromSegment(seg string) (string, bool) {
	if !strings.HasSuffix(seg, ".slice") {
		return "", false
	}
	stripped := strings.TrimSuffix(seg, ".slice")
	idx := strings.Index(stripped, "-pod")
	if idx < 0 {
		return "", false
	}
	uid := stripped[idx+len("-pod"):]
	if uid == "" {
		return "", false
	}
	return strings.ReplaceAll(uid, "_", "-"), true
}

// containerIDFromScope recognises a container scope segment of the
// form "<runtime-prefix>-<id>.scope" (or the bare "<id>.scope" used by
// some runtimes) and returns the lowercase hex id.
func containerIDFromScope(seg string) (string, bool) {
	if !strings.HasSuffix(seg, ".scope") {
		return "", false
	}
	rest := strings.TrimSuffix(seg, ".scope")
	for _, prefix := range criScopePrefixes {
		if strings.HasPrefix(rest, prefix) {
			rest = strings.TrimPrefix(rest, prefix)
			break
		}
	}
	if rest == "" {
		return "", false
	}
	return strings.ToLower(rest), true
}
