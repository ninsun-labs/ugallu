// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package worm_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/worm"
)

func TestStubUploader_Put_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	u, err := worm.NewStubUploader(dir)
	if err != nil {
		t.Fatalf("NewStubUploader: %v", err)
	}

	payload := []byte(`{"hello":"world"}`)
	ref, err := u.Put(context.Background(), "attestations/test/2026/04/abc.json", bytes.NewReader(payload), worm.PutOpts{
		LockUntil: time.Now().Add(7 * 24 * time.Hour),
		MediaType: "application/json",
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !strings.HasPrefix(ref.URL, "file://"+dir) {
		t.Errorf("URL = %q, want file://%s* prefix", ref.URL, dir)
	}
	if !strings.HasPrefix(ref.SHA256, "sha256:") || len(ref.SHA256) != 7+64 {
		t.Errorf("SHA256 = %q, want sha256:<64 hex>", ref.SHA256)
	}
	if ref.Size != int64(len(payload)) {
		t.Errorf("Size = %d, want %d", ref.Size, len(payload))
	}
	if ref.MediaType != "application/json" {
		t.Errorf("MediaType = %q", ref.MediaType)
	}

	// File on disk should match the payload byte-for-byte.
	got, err := os.ReadFile(filepath.Join(dir, "attestations", "test", "2026", "04", "abc.json"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("on-disk payload mismatch")
	}
}

func TestStubUploader_Put_RejectsUnsafeKeys(t *testing.T) {
	dir := t.TempDir()
	u, err := worm.NewStubUploader(dir)
	if err != nil {
		t.Fatalf("NewStubUploader: %v", err)
	}
	cases := []string{
		"",
		"/etc/passwd",
		"..",
		"../escape",
		"a/b/../../escape",
	}
	for _, k := range cases {
		t.Run(k, func(t *testing.T) {
			if _, err := u.Put(context.Background(), k, bytes.NewReader([]byte("x")), worm.PutOpts{}); err == nil {
				t.Errorf("Put(%q) accepted, want error", k)
			}
		})
	}
}

func TestStubUploader_NilContentErrors(t *testing.T) {
	dir := t.TempDir()
	u, _ := worm.NewStubUploader(dir)
	if _, err := u.Put(context.Background(), "k", nil, worm.PutOpts{}); err == nil {
		t.Fatal("Put(nil) accepted, want error")
	}
}

func TestStubUploader_Endpoint(t *testing.T) {
	dir := t.TempDir()
	u, _ := worm.NewStubUploader(dir)
	if !strings.HasPrefix(u.Endpoint(), "stub:dev:") {
		t.Errorf("Endpoint = %q, want stub:dev: prefix", u.Endpoint())
	}
}

func TestStubUploader_NewStubUploader_RejectsEmpty(t *testing.T) {
	if _, err := worm.NewStubUploader(""); err == nil {
		t.Fatal("NewStubUploader('') accepted, want error")
	}
}
