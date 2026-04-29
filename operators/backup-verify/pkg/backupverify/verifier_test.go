// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package backupverify

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// TestEtcdSnapshotVerify_HappyPath writes a temp file, hashes it
// independently, and confirms the verifier produces the same digest.
func TestEtcdSnapshotVerify_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap-1")
	body := []byte("etcd-snapshot-bytes")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	want := sha256.Sum256(body)

	v := &etcdSnapshotVerifier{snapshotDir: dir}
	out, err := v.Verify(&securityv1alpha1.BackupVerifyRunSpec{
		Backend:   securityv1alpha1.BackupVerifyBackendEtcdSnapshot,
		BackupRef: securityv1alpha1.BackupVerifyBackupRef{Name: "snap-1"},
		Mode:      securityv1alpha1.BackupVerifyModeChecksumOnly,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := out.Checksum; got != hex.EncodeToString(want[:]) {
		t.Errorf("Checksum mismatch:\n  got  %s\n  want %s", got, hex.EncodeToString(want[:]))
	}
	if len(out.Findings) != 0 {
		t.Errorf("checksum-only mode should produce no findings; got %+v", out.Findings)
	}
}

// TestEtcdSnapshotVerify_FullRestoreEmitsFollowupFinding documents
// the v0.1.0 stub behaviour for the full-restore path.
func TestEtcdSnapshotVerify_FullRestoreEmitsFollowupFinding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap-1")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	v := &etcdSnapshotVerifier{snapshotDir: dir}
	out, err := v.Verify(&securityv1alpha1.BackupVerifyRunSpec{
		Backend:   securityv1alpha1.BackupVerifyBackendEtcdSnapshot,
		BackupRef: securityv1alpha1.BackupVerifyBackupRef{Name: "snap-1"},
		Mode:      securityv1alpha1.BackupVerifyModeFullRestore,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(out.Findings) != 1 || out.Findings[0].Code != "full-restore-not-implemented" {
		t.Errorf("expected full-restore-not-implemented finding; got %+v", out.Findings)
	}
}

// TestEtcdSnapshotVerify_PathEscapeRejected guards against
// directory-traversal in BackupRef.Name.
func TestEtcdSnapshotVerify_PathEscapeRejected(t *testing.T) {
	dir := t.TempDir()
	v := &etcdSnapshotVerifier{snapshotDir: dir}
	_, err := v.Verify(&securityv1alpha1.BackupVerifyRunSpec{
		Backend:   securityv1alpha1.BackupVerifyBackendEtcdSnapshot,
		BackupRef: securityv1alpha1.BackupVerifyBackupRef{Name: "../../etc/passwd"},
	})
	if err == nil {
		t.Fatal("expected error on path escape")
	}
}

// TestVerifierFor_VeleroBackend smoke-checks the dispatcher.
func TestVerifierFor_VeleroBackend(t *testing.T) {
	v, err := VerifierFor(&securityv1alpha1.BackupVerifyRunSpec{
		Backend: securityv1alpha1.BackupVerifyBackendVelero,
	}, "/var/snapshot", nil)
	if err != nil || v == nil {
		t.Fatalf("VerifierFor velero: v=%v err=%v", v, err)
	}
	if _, ok := v.(*realVeleroVerifier); !ok {
		t.Errorf("expected *realVeleroVerifier, got %T", v)
	}
}
