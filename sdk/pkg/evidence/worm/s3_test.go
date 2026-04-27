// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package worm_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/worm"
)

// fakeS3 captures the last received PUT request so tests can assert on
// the path, headers, and body without spinning up real S3.
type fakeS3 struct {
	method       string
	path         string
	body         []byte
	headers      http.Header
	statusToSend int
}

func (f *fakeS3) handler(w http.ResponseWriter, r *http.Request) {
	f.method = r.Method
	f.path = r.URL.Path
	f.headers = r.Header.Clone()
	body, _ := io.ReadAll(r.Body)
	f.body = body
	w.Header().Set("ETag", `"abc123"`)
	if f.statusToSend == 0 {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(f.statusToSend)
	}
}

func newS3Uploader(t *testing.T, srv *httptest.Server, opts func(*worm.S3UploaderOptions)) *worm.S3Uploader {
	t.Helper()
	o := worm.S3UploaderOptions{
		Bucket:       "ugallu-evidence",
		Region:       "us-east-1",
		EndpointURL:  srv.URL,
		UsePathStyle: true,
		AccessKey:    "test",
		SecretKey:    "test-secret",
	}
	if opts != nil {
		opts(&o)
	}
	u, err := worm.NewS3Uploader(context.Background(), &o)
	if err != nil {
		t.Fatalf("NewS3Uploader: %v", err)
	}
	return u
}

// TestS3Uploader_PutSetsObjectLockHeaders verifies the PUT request
// includes Compliance-mode Object Lock and the retain-until date.
func TestS3Uploader_PutSetsObjectLockHeaders(t *testing.T) {
	f := &fakeS3{}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()

	u := newS3Uploader(t, srv, nil)

	lockUntil := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second)
	payload := []byte(`{"hello":"world"}`)
	ref, err := u.Put(context.Background(), "attestations/2026/04/abc.json",
		bytes.NewReader(payload), worm.PutOpts{
			MediaType: "application/json",
			LockUntil: lockUntil,
			Metadata:  map[string]string{"bundleUID": "uid-123"},
		})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	if f.method != http.MethodPut {
		t.Errorf("method = %q, want PUT", f.method)
	}
	if !strings.Contains(f.path, "ugallu-evidence/attestations/2026/04/abc.json") {
		t.Errorf("path = %q, want bucket+key", f.path)
	}
	if got := f.headers.Get("X-Amz-Object-Lock-Mode"); got != "COMPLIANCE" {
		t.Errorf("Object-Lock-Mode = %q, want COMPLIANCE", got)
	}
	if got := f.headers.Get("X-Amz-Object-Lock-Retain-Until-Date"); got == "" {
		t.Error("Retain-Until-Date header missing")
	}
	if got := f.headers.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := f.headers.Get("X-Amz-Meta-Bundleuid"); got != "uid-123" {
		t.Errorf("X-Amz-Meta-Bundleuid = %q, want uid-123", got)
	}
	if got := f.headers.Get("X-Amz-Meta-Sha256"); got == "" {
		t.Error("X-Amz-Meta-Sha256 missing (uploader didn't auto-stamp digest)")
	}

	if !bytes.Equal(f.body, payload) {
		t.Errorf("body mismatch on the wire")
	}

	if !strings.HasPrefix(ref.URL, "s3://ugallu-evidence/") {
		t.Errorf("URL = %q, want s3:// prefix", ref.URL)
	}
	if !strings.HasPrefix(ref.SHA256, "sha256:") || len(ref.SHA256) != 7+64 {
		t.Errorf("SHA256 = %q", ref.SHA256)
	}
	if ref.Size != int64(len(payload)) {
		t.Errorf("Size = %d, want %d", ref.Size, len(payload))
	}
}

// TestS3Uploader_PutNoLockWhenLockUntilZero verifies that Object Lock
// headers are omitted when LockUntil is the zero time.
func TestS3Uploader_PutNoLockWhenLockUntilZero(t *testing.T) {
	f := &fakeS3{}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()

	u := newS3Uploader(t, srv, nil)
	if _, err := u.Put(context.Background(), "k", bytes.NewReader([]byte("x")), worm.PutOpts{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := f.headers.Get("X-Amz-Object-Lock-Mode"); got != "" {
		t.Errorf("Object-Lock-Mode = %q, want empty (no LockUntil)", got)
	}
}

// TestS3Uploader_KeyPrefix verifies the configured prefix is prepended
// to every key.
func TestS3Uploader_KeyPrefix(t *testing.T) {
	f := &fakeS3{}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()

	u := newS3Uploader(t, srv, func(o *worm.S3UploaderOptions) {
		o.KeyPrefix = "ugallu/prod"
	})
	ref, err := u.Put(context.Background(), "x.json", bytes.NewReader([]byte("x")), worm.PutOpts{
		MediaType: "application/json",
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !strings.Contains(f.path, "ugallu-evidence/ugallu/prod/x.json") {
		t.Errorf("path = %q, want bucket+prefix+key", f.path)
	}
	if !strings.HasSuffix(ref.URL, "ugallu/prod/x.json") {
		t.Errorf("URL = %q, want ...ugallu/prod/x.json", ref.URL)
	}
}

// TestS3Uploader_PutErrorOnBadServer verifies a non-2xx propagates an
// error.
func TestS3Uploader_PutErrorOnBadServer(t *testing.T) {
	f := &fakeS3{statusToSend: http.StatusInternalServerError}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()

	u := newS3Uploader(t, srv, nil)
	_, err := u.Put(context.Background(), "k", bytes.NewReader([]byte("x")), worm.PutOpts{})
	if err == nil {
		t.Fatal("Put accepted a 500 response, want error")
	}
}

// TestS3Uploader_NewRequiresBucket verifies bucket validation.
func TestS3Uploader_NewRequiresBucket(t *testing.T) {
	_, err := worm.NewS3Uploader(context.Background(), &worm.S3UploaderOptions{})
	if err == nil {
		t.Fatal("NewS3Uploader without bucket accepted, want error")
	}
}

// TestS3Uploader_NewRejectsUnknownLockMode verifies invalid lock mode
// fails at construction time.
func TestS3Uploader_NewRejectsUnknownLockMode(t *testing.T) {
	_, err := worm.NewS3Uploader(context.Background(), &worm.S3UploaderOptions{
		Bucket:         "b",
		ObjectLockMode: "BAD",
	})
	if err == nil {
		t.Fatal("NewS3Uploader with invalid lock mode accepted, want error")
	}
}

// TestS3Uploader_PutRejectsUnsafeKey verifies traversal-prevention
// cooperation between safeKey and S3Uploader.
func TestS3Uploader_PutRejectsUnsafeKey(t *testing.T) {
	f := &fakeS3{}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()

	u := newS3Uploader(t, srv, nil)
	cases := []string{"", "/abs", "..", "a/../b"}
	for _, k := range cases {
		t.Run(k, func(t *testing.T) {
			if _, err := u.Put(context.Background(), k, bytes.NewReader([]byte("x")), worm.PutOpts{}); err == nil {
				t.Errorf("Put(%q) accepted, want error", k)
			}
		})
	}
}
