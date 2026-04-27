// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: GPL-2.0
//
// ugallu cgroup tracker: live updates of the resolver's cgroup-ID
// index via raw tracepoints on cgroup_mkdir / cgroup_rmdir
// (design 03 R3, Phase 3).
//
// Each event submits {cgroup_id, op, path[256]} to a ring buffer the
// Go consumer drains in serverv1/cgroup_ebpf_linux.go. CO-RE
// relocations make the program portable across kernel 5.5+ regardless
// of struct layout drift.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define UGALLU_PATH_MAX 256

enum cgroup_op {
	OP_MKDIR = 1,
	OP_RMDIR = 2,
};

struct event {
	__u64 cgroup_id;
	__u32 op;
	__u32 _pad;
	char  path[UGALLU_PATH_MAX];
};

// 1 MiB ring buffer; sized for ~30k events at 32-byte average payload,
// enough headroom for spike of pod start/stop on a busy node.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int submit(struct cgroup *cgrp, const char *path, __u32 op)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->cgroup_id = BPF_CORE_READ(cgrp, kn, id);
	e->op = op;
	e->_pad = 0;
	bpf_probe_read_kernel_str(&e->path, sizeof(e->path), path);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("raw_tp/cgroup_mkdir")
int BPF_PROG(handle_mkdir, struct cgroup *cgrp, const char *path)
{
	return submit(cgrp, path, OP_MKDIR);
}

SEC("raw_tp/cgroup_rmdir")
int BPF_PROG(handle_rmdir, struct cgroup *cgrp, const char *path)
{
	return submit(cgrp, path, OP_RMDIR);
}
