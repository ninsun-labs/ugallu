// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package backupverify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// VerifyOutcome is what the verifier returns to the reconciler — the
// raw materials the run needs to write a BackupVerifyResult.
type VerifyOutcome struct {
	Checksum            string
	RestoredObjectCount int
	Findings            []securityv1alpha1.BackupVerifyFinding
}

// Verifier is the backend-agnostic interface every supported backend
// implements. v0.1.0 ships realVeleroVerifier + etcdSnapshotVerifier.
type Verifier interface {
	Verify(spec *securityv1alpha1.BackupVerifyRunSpec) (*VerifyOutcome, error)
}

// VerifierFor returns the right backend for the given spec. The
// Kubernetes client is required for backends that read CRDs from the
// apiserver (Velero); pass nil for the etcd-snapshot path.
func VerifierFor(spec *securityv1alpha1.BackupVerifyRunSpec, etcdDir string, c client.Client) (Verifier, error) {
	switch spec.Backend {
	case securityv1alpha1.BackupVerifyBackendVelero:
		return &realVeleroVerifier{client: c}, nil
	case securityv1alpha1.BackupVerifyBackendEtcdSnapshot:
		return &etcdSnapshotVerifier{snapshotDir: etcdDir}, nil
	default:
		return nil, fmt.Errorf("unsupported backend %q", spec.Backend)
	}
}

// etcdSnapshotVerifier handles the raw etcd snapshot backend
// (k3s/RKE2 snapshot files on disk). The verifier opens the file,
// streams it through SHA-256, and reports the hash. Full-restore
// mode produces a "full-restore-not-implemented" warning finding —
// the actual restore needs etcdutl which isn't packaged in the
// scratch operator image yet.
type etcdSnapshotVerifier struct {
	snapshotDir string
}

func (v *etcdSnapshotVerifier) Verify(spec *securityv1alpha1.BackupVerifyRunSpec) (*VerifyOutcome, error) {
	if v.snapshotDir == "" {
		return nil, errors.New("etcd-snapshot verifier: empty snapshot dir")
	}
	path := filepath.Join(v.snapshotDir, spec.BackupRef.Name)
	if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(v.snapshotDir)) {
		return nil, fmt.Errorf("snapshot path escapes configured dir")
	}
	f, err := os.Open(path) //nolint:gosec // path is constrained to the operator-managed snapshot dir; checked above
	if err != nil {
		return nil, fmt.Errorf("open snapshot %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("hash snapshot: %w", err)
	}
	out := &VerifyOutcome{Checksum: hex.EncodeToString(h.Sum(nil))}

	if spec.Mode == securityv1alpha1.BackupVerifyModeFullRestore {
		// etcdutl-based restore is a follow-up — for v0.1.0 the
		// verifier reports a low-severity finding so the operator
		// stays honest about what it actually verified.
		out.Findings = append(out.Findings, securityv1alpha1.BackupVerifyFinding{
			Code:     "full-restore-not-implemented",
			Severity: securityv1alpha1.SeverityLow,
			Detail:   "etcd-snapshot full-restore requires etcdutl in the operator image; v0.1.0 verifies checksum only",
		})
	}
	return out, nil
}

// (Velero backend implementation lives in velero.go — uses the
// controller-runtime client to look up the Backup + BSL CRs and
// surface their state as findings.)
