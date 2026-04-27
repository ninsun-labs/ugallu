// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serverv1

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"k8s.io/apimachinery/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Wno-unused-function" -target amd64,arm64 cgroupTracker bpf/cgroup_tracker.bpf.c -- -I bpf -I /usr/include/bpf

// cgroup_tracker.bpf.c keeps these in sync with the C `enum cgroup_op`.
const (
	cgroupOpMkdir uint32 = 1
	cgroupOpRmdir uint32 = 2
)

// ebpfPathMax mirrors the C UGALLU_PATH_MAX constant. The C event
// struct lays out as: u64 cgroup_id, u32 op, u32 pad, char path[256].
const ebpfPathMax = 256

// cgroupEvent is the wire-compatible Go layout of `struct event` from
// cgroup_tracker.bpf.c. binary.LittleEndian decodes it directly into
// this struct (the kernel emits in host byte order; we restrict the
// generated objects to little-endian targets via -target amd64,arm64).
type cgroupEvent struct {
	CgroupID uint64
	Op       uint32
	_        uint32
	Path     [ebpfPathMax]byte
}

// CgroupTracker owns the loaded BPF objects, the attached tracepoint
// links, and the ring-buffer reader goroutine. Callers drive it via
// Run(ctx) and Close().
type CgroupTracker struct {
	objs   cgroupTrackerObjects
	mkdir  link.Link
	rmdir  link.Link
	reader *ringbuf.Reader
	cache  *Cache
	log    *slog.Logger
}

// LoadCgroupTracker loads the embedded BPF program, attaches it to
// cgroup_mkdir / cgroup_rmdir raw tracepoints, and opens the ring
// buffer. Errors land cleanly so callers can fall back to the
// rescan-only path when CAP_BPF is missing or the kernel doesn't
// support raw tracepoints.
func LoadCgroupTracker(c *Cache, log *slog.Logger) (*CgroupTracker, error) {
	if c == nil {
		return nil, fmt.Errorf("Cache is required")
	}
	if log == nil {
		log = slog.Default()
	}

	// Lift the RLIMIT_MEMLOCK ceiling so the verifier can lock
	// program + map memory. No-op on kernel 5.11+ (which uses
	// memcg-based accounting) but harmless.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit RLIMIT_MEMLOCK: %w", err)
	}

	t := &CgroupTracker{cache: c, log: log}
	if err := loadCgroupTrackerObjects(&t.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	mkdir, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "cgroup_mkdir",
		Program: t.objs.HandleMkdir,
	})
	if err != nil {
		_ = t.objs.Close()
		return nil, fmt.Errorf("attach cgroup_mkdir: %w", err)
	}
	t.mkdir = mkdir

	rmdir, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "cgroup_rmdir",
		Program: t.objs.HandleRmdir,
	})
	if err != nil {
		_ = mkdir.Close()
		_ = t.objs.Close()
		return nil, fmt.Errorf("attach cgroup_rmdir: %w", err)
	}
	t.rmdir = rmdir

	reader, err := ringbuf.NewReader(t.objs.Events)
	if err != nil {
		_ = rmdir.Close()
		_ = mkdir.Close()
		_ = t.objs.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	t.reader = reader

	return t, nil
}

// Run drains the ring buffer until ctx is cancelled or Close() is
// called. Each event refreshes Cache.IndexCgroup (mkdir) or evicts
// the cgroup_id from the index (rmdir) so resolver lookups stay
// fresh without polling.
func (t *CgroupTracker) Run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		// Closing the reader unblocks Read() with os.ErrClosed.
		_ = t.reader.Close()
	}()

	for {
		rec, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			t.log.Warn("ebpf ringbuf read", "err", err.Error())
			continue
		}
		if len(rec.RawSample) < 16 {
			metricEbpfDrops.WithLabelValues("short_record").Inc()
			continue
		}
		var ev cgroupEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			metricEbpfDrops.WithLabelValues("decode_error").Inc()
			continue
		}
		t.handle(&ev)
	}
}

// handle applies a single tracepoint event to the cache.
func (t *CgroupTracker) handle(ev *cgroupEvent) {
	path := nullTerminated(ev.Path[:])
	switch ev.Op {
	case cgroupOpMkdir:
		info, ok := ParseCgroupPath(path)
		if !ok {
			metricEbpfEvents.WithLabelValues("mkdir", "non_kubepods").Inc()
			return
		}
		t.cache.IndexCgroup(ev.CgroupID, types.UID(info.PodUID), info.ContainerID)
		metricEbpfEvents.WithLabelValues("mkdir", "indexed").Inc()
		updateCgroupIndexSize(t.cache)
	case cgroupOpRmdir:
		t.cache.EvictCgroupID(ev.CgroupID)
		metricEbpfEvents.WithLabelValues("rmdir", "evicted").Inc()
		updateCgroupIndexSize(t.cache)
	default:
		metricEbpfDrops.WithLabelValues("unknown_op").Inc()
	}
}

// Close detaches every tracepoint and frees the BPF objects.
func (t *CgroupTracker) Close() error {
	var errs []string
	if t.reader != nil {
		if err := t.reader.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			errs = append(errs, fmt.Sprintf("reader: %v", err))
		}
	}
	if t.mkdir != nil {
		if err := t.mkdir.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("mkdir link: %v", err))
		}
	}
	if t.rmdir != nil {
		if err := t.rmdir.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("rmdir link: %v", err))
		}
	}
	if err := t.objs.Close(); err != nil {
		errs = append(errs, fmt.Sprintf("objects: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("close cgroup tracker: %s", strings.Join(errs, "; "))
	}
	return nil
}

// nullTerminated trims a fixed-size byte buffer at the first NUL.
func nullTerminated(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// IsBPFSupported is a cheap kernel-feature probe used by Bootstrap to
// decide whether to attempt a BPF load. Returns nil when the kernel
// has BTF (CO-RE prerequisite); otherwise an error callers can log
// and gracefully fall back to rescan-only mode.
func IsBPFSupported() error {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return fmt.Errorf("kernel BTF unavailable: %w", err)
	}
	return nil
}
