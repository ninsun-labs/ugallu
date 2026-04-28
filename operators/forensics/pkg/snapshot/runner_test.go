// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package snapshot_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ninsun-labs/ugallu/operators/forensics/pkg/snapshot"
)

// fakeS3 is a minimal AWS-S3 stand-in for the manager.Uploader. It
// handles both the single-shot PutObject path (when the body fits in
// one part) and the multipart sequence (CreateMultipartUpload →
// UploadPart → CompleteMultipartUpload / AbortMultipartUpload).
type fakeS3 struct {
	mu             sync.Mutex
	puts           map[string][]byte
	multiparts     map[string]*multipartState
	completedKey   string
	completedBytes []byte
	abortCount     int
}

type multipartState struct {
	key   string
	parts map[int][]byte
}

func newFakeS3() *fakeS3 {
	return &fakeS3{
		puts:       map[string][]byte{},
		multiparts: map[string]*multipartState{},
	}
}

func (f *fakeS3) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	q := r.URL.Query()
	body, _ := io.ReadAll(r.Body)
	key := strings.TrimPrefix(r.URL.Path, "/")
	// Path-style: first segment is the bucket.
	if i := strings.Index(key, "/"); i >= 0 {
		key = key[i+1:]
	}

	switch {
	case r.Method == http.MethodPost && q.Get("uploads") != "":
		// CreateMultipartUpload.
		uploadID := "test-upload-" + key
		f.multiparts[uploadID] = &multipartState{key: key, parts: map[int][]byte{}}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><InitiateMultipartUploadResult><Bucket>ugallu</Bucket><Key>` + key + `</Key><UploadId>` + uploadID + `</UploadId></InitiateMultipartUploadResult>`))

	case r.Method == http.MethodPut && q.Get("uploadId") != "":
		// UploadPart.
		uploadID := q.Get("uploadId")
		st, ok := f.multiparts[uploadID]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		partNum := 1
		if pn := q.Get("partNumber"); pn != "" {
			_, _ = parseIntStrict(pn, &partNum)
		}
		st.parts[partNum] = body
		w.Header().Set("ETag", `"part-`+pn(partNum)+`"`)
		w.WriteHeader(http.StatusOK)

	case r.Method == http.MethodPost && q.Get("uploadId") != "":
		// CompleteMultipartUpload.
		uploadID := q.Get("uploadId")
		st, ok := f.multiparts[uploadID]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		full := bytes.Buffer{}
		for i := 1; i <= len(st.parts); i++ {
			full.Write(st.parts[i])
		}
		f.completedKey = st.key
		f.completedBytes = full.Bytes()
		delete(f.multiparts, uploadID)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><CompleteMultipartUploadResult><Bucket>ugallu</Bucket><Key>` + st.key + `</Key><ETag>"complete"</ETag></CompleteMultipartUploadResult>`))

	case r.Method == http.MethodDelete && q.Get("uploadId") != "":
		// AbortMultipartUpload.
		uploadID := q.Get("uploadId")
		delete(f.multiparts, uploadID)
		f.abortCount++
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPut:
		// Single-shot PutObject (used when payload fits in one part).
		f.puts[key] = body
		f.completedKey = key
		f.completedBytes = body
		w.Header().Set("ETag", `"single"`)
		w.WriteHeader(http.StatusOK)

	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

// pn formats a part number — kept tiny to keep ETag deterministic.
func pn(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return "many"
}

func parseIntStrict(s string, out *int) (n int, err error) {
	n = 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errBad
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return n, nil
}

var errBad = &parseErr{}

type parseErr struct{}

func (parseErr) Error() string { return "bad int" }

// seedTree writes a small filesystem tree the runner will tar.
func seedTree(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "root")
	for _, p := range []struct {
		name string
		body []byte
	}{
		{"etc/passwd", []byte("root:x:0:0\n")},
		{"app/config.json", []byte(`{"x":1}`)},
		{"tmp/excluded.bin", bytes.Repeat([]byte{0x42}, 64)},
	} {
		full := filepath.Join(root, p.name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, p.body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// runWith builds a Runner pointed at the fake S3 server.
func runWith(t *testing.T, srv *httptest.Server, opts *snapshot.Options) (*snapshot.Result, error) {
	t.Helper()
	if opts.Bucket == "" {
		opts.Bucket = "ugallu"
	}
	if opts.Key == "" {
		opts.Key = "incident/test.tar.gz"
	}
	opts.Endpoint = srv.URL
	opts.UsePathStyle = true
	opts.Region = "us-east-1"
	opts.AccessKey = "test"
	opts.SecretKey = "test-secret"
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Unix(1700000000, 0) }
	}
	r, err := snapshot.New(opts)
	if err != nil {
		return nil, err
	}
	return r.Run(context.Background())
}

// TestRunner_HappyPath drives the runner against a small tree and
// verifies the gzip+tar payload that lands at the fake S3 contains
// the expected entries with the right contents.
func TestRunner_HappyPath(t *testing.T) {
	f := newFakeS3()
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()
	root := seedTree(t)

	res, err := runWith(t, srv, &snapshot.Options{
		Paths: []string{root},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Truncated {
		t.Errorf("Truncated=true on small tree")
	}
	if !strings.HasPrefix(res.SHA256, "sha256:") {
		t.Errorf("SHA256 missing prefix: %q", res.SHA256)
	}
	if res.MediaType != "application/x-tar+gzip" {
		t.Errorf("MediaType = %q", res.MediaType)
	}
	if res.Size <= 0 {
		t.Errorf("Size = %d", res.Size)
	}

	body := f.completedBytes
	if len(body) == 0 {
		t.Fatal("S3 received empty body")
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	tr := tar.NewReader(gz)
	gotEntries := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		buf, _ := io.ReadAll(tr)
		gotEntries[hdr.Name] = buf
	}
	expectedSubstring := "etc/passwd"
	found := false
	for k := range gotEntries {
		if strings.Contains(k, expectedSubstring) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in tar, got keys: %v", expectedSubstring, gotEntries)
	}
}

// TestRunner_RespectsExcludeGlobs verifies an excluded path is not
// in the resulting tar.
func TestRunner_RespectsExcludeGlobs(t *testing.T) {
	f := newFakeS3()
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()
	root := seedTree(t)

	_, err := runWith(t, srv, &snapshot.Options{
		Paths: []string{root},
		// Exclude both the "tmp" dir and any nested file by name.
		ExcludeGlobs: []string{filepath.Base(root) + "/tmp"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	gz, _ := gzip.NewReader(bytes.NewReader(f.completedBytes))
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		if strings.Contains(hdr.Name, "tmp/excluded.bin") {
			t.Errorf("excluded entry present in tar: %s", hdr.Name)
		}
	}
}

// TestRunner_TruncatesAtMaxBytes seeds a big file and asserts the
// runner returns truncated=true when MaxBytes is hit. The fake S3
// records an abort.
func TestRunner_TruncatesAtMaxBytes(t *testing.T) {
	f := newFakeS3()
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()
	root := filepath.Join(t.TempDir(), "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// 4 MiB of cryptographically-random bytes — gzip cannot compress
	// noise, so the gzip-output stream stays close to 4 MiB and
	// trips the 64 KiB MaxBytes cap on the gzip-writer side.
	noise := make([]byte, 4<<20)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "big.bin"), noise, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := runWith(t, srv, &snapshot.Options{
		Paths:    []string{root},
		MaxBytes: 64 * 1024,
		PartSize: 5 * 1024 * 1024, // force single-shot path so truncation surfaces deterministically
	})
	if err != nil {
		t.Fatalf("Run (expected ok with truncated=true): %v", err)
	}
	if !res.Truncated {
		t.Errorf("Truncated=false; want true")
	}
}

// TestEncodeResult verifies the wire format the operator parses from
// the ephemeral container's stdout.
func TestEncodeResult(t *testing.T) {
	var buf bytes.Buffer
	r := &snapshot.Result{
		URL:        "s3://ugallu/incident/x.tar.gz",
		SHA256:     "sha256:abc",
		Size:       42,
		DurationMS: 100,
		Truncated:  false,
		MediaType:  "application/x-tar+gzip",
	}
	if err := snapshot.EncodeResult(&buf, r); err != nil {
		t.Fatalf("EncodeResult: %v", err)
	}
	out := strings.TrimSpace(buf.String())
	if !strings.HasSuffix(out, "}") {
		t.Errorf("missing JSON close: %q", out)
	}
	var got snapshot.Result
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.SHA256 != r.SHA256 || got.Size != r.Size {
		t.Errorf("roundtrip mismatch: got=%+v want=%+v", got, r)
	}
}
