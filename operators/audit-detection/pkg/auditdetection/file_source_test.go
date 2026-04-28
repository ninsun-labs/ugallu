// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package auditdetection_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection"
)

// writeAuditLine appends a JSON-encoded audit event to path.
func writeAuditLine(t *testing.T, path string, ev map[string]any) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	if err := enc.Encode(ev); err != nil {
		t.Fatalf("encode: %v", err)
	}
}

// drainOne reads from ch with a deadline; t.Fatalf on timeout.
func drainOne(t *testing.T, ch <-chan *auditdetection.AuditEvent, timeout time.Duration) *auditdetection.AuditEvent {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for event")
	}
	return nil
}

func TestFileSource_TailsAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	src, err := auditdetection.NewFileSource(&auditdetection.FileSourceOpts{
		Path:         path,
		PollInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, err := src.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	writeAuditLine(t, path, map[string]any{
		"auditID":    "id-1",
		"verb":       "create",
		"requestURI": "/api/v1/namespaces/default/pods",
		"user":       map[string]any{"username": "system:serviceaccount:default:test"},
	})

	ev := drainOne(t, out, 3*time.Second)
	if ev.AuditID != "id-1" {
		t.Errorf("AuditID = %q, want id-1", ev.AuditID)
	}
	if ev.Verb != "create" {
		t.Errorf("Verb = %q, want create", ev.Verb)
	}
	if ev.User.Username != "system:serviceaccount:default:test" {
		t.Errorf("User = %+v", ev.User)
	}
}

func TestFileSource_HandlesRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	src, _ := auditdetection.NewFileSource(&auditdetection.FileSourceOpts{
		Path:         path,
		PollInterval: 50 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, err := src.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	writeAuditLine(t, path, map[string]any{"auditID": "pre-rotate"})
	first := drainOne(t, out, 3*time.Second)
	if first.AuditID != "pre-rotate" {
		t.Fatalf("first event: %+v", first)
	}

	// Rotate: rename the current file then create a fresh empty one
	// (mimics what logrotate does with copytruncate=false).
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	// Allow the watcher to react to CREATE.
	time.Sleep(150 * time.Millisecond)
	writeAuditLine(t, path, map[string]any{"auditID": "post-rotate"})
	second := drainOne(t, out, 3*time.Second)
	if second.AuditID != "post-rotate" {
		t.Errorf("second event after rotation: %+v", second)
	}
}

func TestFileSource_DropsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	src, _ := auditdetection.NewFileSource(&auditdetection.FileSourceOpts{
		Path:         path,
		PollInterval: 50 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, err := src.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if appendErr := appendBytes(path, []byte("not-json\n")); appendErr != nil {
		t.Fatalf("append malformed: %v", appendErr)
	}
	writeAuditLine(t, path, map[string]any{"auditID": "valid-after-bad"})
	ev := drainOne(t, out, 3*time.Second)
	if ev.AuditID != "valid-after-bad" {
		t.Errorf("expected to skip malformed and read next valid event, got %+v", ev)
	}
}

func TestNewFileSource_RejectsBadOpts(t *testing.T) {
	if _, err := auditdetection.NewFileSource(nil); err == nil {
		t.Error("expected error for nil opts")
	}
	if _, err := auditdetection.NewFileSource(&auditdetection.FileSourceOpts{}); err == nil {
		t.Error("expected error for empty Path")
	}
}

func appendBytes(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(b)
	return err
}
