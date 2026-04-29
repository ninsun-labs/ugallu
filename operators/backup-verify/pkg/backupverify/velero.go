// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package backupverify

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// realVeleroVerifier looks the Velero Backup CR up via the
// controller-runtime client and surfaces the relevant fields as
// findings. It supersedes the v0.1.0 stub.
type realVeleroVerifier struct {
	client client.Client
}

func (v *realVeleroVerifier) Verify(spec *securityv1alpha1.BackupVerifyRunSpec) (*VerifyOutcome, error) {
	if v.client == nil {
		return nil, fmt.Errorf("velero verifier: nil client")
	}
	ns := spec.BackupRef.Namespace
	if ns == "" {
		ns = "velero"
	}
	var backup velerov1.Backup
	err := v.client.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: spec.BackupRef.Name}, &backup)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return &VerifyOutcome{
				Findings: []securityv1alpha1.BackupVerifyFinding{{
					Code:     "velero-backup-not-found",
					Severity: securityv1alpha1.SeverityHigh,
					Detail:   fmt.Sprintf("Velero Backup %s/%s not found", ns, spec.BackupRef.Name),
				}},
			}, nil
		}
		return nil, fmt.Errorf("get Velero Backup: %w", err)
	}

	out := &VerifyOutcome{}
	if backup.Status.Progress != nil {
		out.RestoredObjectCount = backup.Status.Progress.ItemsBackedUp
	}

	// Phase mapping: anything not Completed counts as a finding.
	switch backup.Status.Phase {
	case velerov1.BackupPhaseCompleted:
		// Healthy backup — no finding to surface.
	case velerov1.BackupPhasePartiallyFailed:
		out.Findings = append(out.Findings, securityv1alpha1.BackupVerifyFinding{
			Code:     "velero-backup-partially-failed",
			Severity: securityv1alpha1.SeverityHigh,
			Detail: fmt.Sprintf("Velero Backup phase=%s, errors=%d, warnings=%d",
				backup.Status.Phase, backup.Status.Errors, backup.Status.Warnings),
		})
	case velerov1.BackupPhaseFailed, velerov1.BackupPhaseFailedValidation:
		out.Findings = append(out.Findings, securityv1alpha1.BackupVerifyFinding{
			Code:     "velero-backup-failed",
			Severity: securityv1alpha1.SeverityCritical,
			Detail:   fmt.Sprintf("Velero Backup phase=%s, errors=%d", backup.Status.Phase, backup.Status.Errors),
		})
	default:
		// In-flight phase (New / FinalizingPartiallyFailed / etc.) —
		// surface as info so ops can re-run when the backup settles.
		out.Findings = append(out.Findings, securityv1alpha1.BackupVerifyFinding{
			Code:     "velero-backup-not-final",
			Severity: securityv1alpha1.SeverityLow,
			Detail:   fmt.Sprintf("Velero Backup phase=%s (still in flight)", backup.Status.Phase),
		})
	}

	// BackupStorageLocation reachability surface — Velero records
	// "Available" / "Unavailable" on the BSL CR; bubble it up so
	// drift between Backup metadata + BSL state shows up.
	bslName := backup.Spec.StorageLocation
	if bslName != "" {
		var bsl velerov1.BackupStorageLocation
		bslErr := v.client.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: bslName}, &bsl)
		switch {
		case apierrors.IsNotFound(bslErr):
			out.Findings = append(out.Findings, securityv1alpha1.BackupVerifyFinding{
				Code: "velero-bsl-missing", Severity: securityv1alpha1.SeverityHigh,
				Detail: fmt.Sprintf("BackupStorageLocation %s/%s referenced by the Backup is missing", ns, bslName),
			})
		case bslErr != nil:
			return nil, fmt.Errorf("get BackupStorageLocation: %w", bslErr)
		case bsl.Status.Phase == velerov1.BackupStorageLocationPhaseUnavailable:
			out.Findings = append(out.Findings, securityv1alpha1.BackupVerifyFinding{
				Code: "velero-bsl-unavailable", Severity: securityv1alpha1.SeverityCritical,
				Detail: fmt.Sprintf("BackupStorageLocation %s/%s is Unavailable", ns, bslName),
			})
		}
	}

	// Full-restore mode is driven by the reconciler via runFullRestoreCycle;
	// see velero_fullrestore.go. The verifier's checksum-only path
	// stops here and the controller takes over the async pipeline.
	return out, nil
}
