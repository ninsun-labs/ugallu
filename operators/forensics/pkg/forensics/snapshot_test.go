// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"errors"
	"testing"
)

// TestParseSnapshotResult_Success covers the legacy happy path.
func TestParseSnapshotResult_Success(t *testing.T) {
	logs := `{"url":"s3://ugallu/x.tar.gz","sha256":"sha256:abc","size":42,"durationMs":100,"truncated":false,"mediaType":"application/x-tar+gzip"}`
	res, err := parseSnapshotResult(logs)
	if err != nil {
		t.Fatalf("parseSnapshotResult: %v", err)
	}
	if res.SHA256 != "sha256:abc" {
		t.Errorf("SHA256 = %q", res.SHA256)
	}
}

// TestParseSnapshotResult_Failure decodes the failure record the
// snapshot binary emits on os.Exit(1) and asserts that the
// orchestrator gets back a SnapshotFailureError it can errors.As
// against.
func TestParseSnapshotResult_Failure(t *testing.T) {
	logs := `{"failure":{"step":"creds","error":"WORM credentials missing","detail":"creds: WORM credentials missing"}}`
	res, err := parseSnapshotResult(logs)
	if res != nil {
		t.Errorf("expected nil Result, got %+v", res)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var sf *SnapshotFailureError
	if !errors.As(err, &sf) {
		t.Fatalf("expected SnapshotFailureError, got %T: %v", err, err)
	}
	if sf.Failure.Step != "creds" {
		t.Errorf("Step = %q, want creds", sf.Failure.Step)
	}
	if sf.Failure.Error != "WORM credentials missing" {
		t.Errorf("Error mismatch")
	}
}

// TestParseSnapshotResult_FailureLineMixedWithStderr verifies that
// when the binary emits chatter on stderr (which kubelet may merge
// into the container log) plus the JSON failure on stdout, the
// parser still finds the JSON line.
func TestParseSnapshotResult_FailureLineMixedWithStderr(t *testing.T) {
	logs := `random log noise from a library
ugallu-forensics-snapshot: creds: WORM credentials missing
{"failure":{"step":"creds","error":"WORM credentials missing"}}`
	_, err := parseSnapshotResult(logs)
	var sf *SnapshotFailureError
	if !errors.As(err, &sf) {
		t.Fatalf("expected SnapshotFailureError, got %T: %v", err, err)
	}
	if sf.Failure.Step != "creds" {
		t.Errorf("Step = %q", sf.Failure.Step)
	}
}
