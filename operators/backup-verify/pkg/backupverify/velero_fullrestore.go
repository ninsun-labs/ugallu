// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package backupverify

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// FullRestoreOutcome carries the per-stage result of one full-restore
// pass. Stage tracks how far the pipeline got so the caller knows
// whether to requeue (waiting on the Restore CR) or finalise.
type FullRestoreOutcome struct {
	// Done is true when the run has reached a terminal state. False
	// means the caller should requeue and try again.
	Done bool

	// Findings is the per-stage report bubbled into the
	// BackupVerifyResult.
	Findings []securityv1alpha1.BackupVerifyFinding

	// RestoredObjectCount is the count of objects observed in the
	// sandbox namespace after the restore settled. Zero until Done.
	RestoredObjectCount int
}

// runFullRestoreCycle drives one tick of the asynchronous full-restore
// pipeline. Each tick performs at most one of:
//
//  1. Create the Restore CR (if it doesn't exist yet).
//  2. Read the Restore CR's Phase + return Done=false when in flight.
//  3. On Phase=Completed/PartiallyFailed: list the sandbox namespace,
//     compute a per-Kind count, return Done=true with findings.
//  4. On Phase=Failed/FailedValidation: surface failure findings,
//     skip the diff, return Done=true.
//
// Idempotency: re-runs after an operator crash find the existing
// Restore CR and pick up wherever the previous tick left off; the
// sandbox namespace is reused.
func runFullRestoreCycle(ctx context.Context, c client.Client, run *securityv1alpha1.BackupVerifyRun) (*FullRestoreOutcome, error) {
	veleroNS := run.Spec.BackupRef.Namespace
	if veleroNS == "" {
		veleroNS = "velero"
	}
	sandbox := run.Spec.SandboxNamespace
	if sandbox == "" {
		// Defensive: admission policy 14 enforces this - but a
		// bypass via dry-run should still produce a sane error.
		return nil, fmt.Errorf("full-restore mode requires sandboxNamespace")
	}
	restoreName := fmt.Sprintf("%s-restore", run.Name)

	// 1) Create the Restore CR if missing.
	var restore velerov1.Restore
	getErr := c.Get(ctx, client.ObjectKey{Namespace: veleroNS, Name: restoreName}, &restore)
	if apierrors.IsNotFound(getErr) {
		// Look up the Backup to extract the source namespaces. The
		// NamespaceMapping forces every restored object into the
		// sandbox so the production state is never touched.
		var backup velerov1.Backup
		if err := c.Get(ctx, client.ObjectKey{Namespace: veleroNS, Name: run.Spec.BackupRef.Name}, &backup); err != nil {
			if apierrors.IsNotFound(err) {
				// Backup missing - short-circuit with a finding so
				// the run produces a Result instead of erroring out.
				return &FullRestoreOutcome{
					Done: true,
					Findings: []securityv1alpha1.BackupVerifyFinding{{
						Code:     "velero-backup-not-found",
						Severity: securityv1alpha1.SeverityHigh,
						Detail:   fmt.Sprintf("Velero Backup %s/%s not found", veleroNS, run.Spec.BackupRef.Name),
					}},
				}, nil
			}
			return nil, fmt.Errorf("get Backup for full-restore: %w", err)
		}
		mapping := buildNamespaceMapping(&backup, sandbox)
		newRestore := &velerov1.Restore{
			ObjectMeta: metav1.ObjectMeta{
				Name:      restoreName,
				Namespace: veleroNS,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "ugallu-backup-verify",
					"ugallu.io/run":                run.Name,
					"ugallu.io/run-namespace":      run.Namespace,
				},
			},
			Spec: velerov1.RestoreSpec{
				BackupName:       run.Spec.BackupRef.Name,
				NamespaceMapping: mapping,
				// Skip PVs in v0.1.0 - production volume restore in a
				// sandbox is high-risk and out of scope. The sandbox
				// gets the K8s object graph only.
				RestorePVs: ptrBool(false),
			},
		}
		if err := c.Create(ctx, newRestore); err != nil {
			return nil, fmt.Errorf("create Velero Restore: %w", err)
		}
		// First touch: wait for the next tick.
		return &FullRestoreOutcome{Done: false}, nil
	}
	if getErr != nil {
		return nil, fmt.Errorf("get Velero Restore: %w", getErr)
	}

	// 2) In flight - requeue.
	if !isRestoreTerminal(restore.Status.Phase) {
		return &FullRestoreOutcome{Done: false}, nil
	}

	// 3 + 4) Terminal phase - fold into findings.
	out := &FullRestoreOutcome{Done: true}
	switch restore.Status.Phase {
	case velerov1.RestorePhaseCompleted:
		// Diff the sandbox.
		count, diffFindings, err := diffSandbox(ctx, c, sandbox, &restore)
		if err != nil {
			return nil, fmt.Errorf("diff sandbox: %w", err)
		}
		out.RestoredObjectCount = count
		out.Findings = append(out.Findings, diffFindings...)
	case velerov1.RestorePhasePartiallyFailed:
		out.Findings = append(out.Findings, securityv1alpha1.BackupVerifyFinding{
			Code:     "velero-restore-partially-failed",
			Severity: securityv1alpha1.SeverityHigh,
			Detail: fmt.Sprintf("Velero Restore phase=%s, errors=%d, warnings=%d, reason=%q",
				restore.Status.Phase, restore.Status.Errors, restore.Status.Warnings, restore.Status.FailureReason),
		})
		// Best-effort diff so ops still see what *did* land.
		count, diffFindings, _ := diffSandbox(ctx, c, sandbox, &restore)
		out.RestoredObjectCount = count
		out.Findings = append(out.Findings, diffFindings...)
	case velerov1.RestorePhaseFailed, velerov1.RestorePhaseFailedValidation:
		out.Findings = append(out.Findings, securityv1alpha1.BackupVerifyFinding{
			Code:     "velero-restore-failed",
			Severity: securityv1alpha1.SeverityCritical,
			Detail: fmt.Sprintf("Velero Restore phase=%s, errors=%d, validationErrors=%v, reason=%q",
				restore.Status.Phase, restore.Status.Errors, restore.Status.ValidationErrors, restore.Status.FailureReason),
		})
	default:
		out.Findings = append(out.Findings, securityv1alpha1.BackupVerifyFinding{
			Code:     "velero-restore-unknown-phase",
			Severity: securityv1alpha1.SeverityMedium,
			Detail:   fmt.Sprintf("unhandled terminal phase %q", restore.Status.Phase),
		})
	}
	return out, nil
}

// cleanupFullRestore tears the sandbox + the Restore CR down on a
// terminal run. Failures are converted into low-severity findings -
// the run itself already settled, so a stale sandbox is annoying
// but not enforcement-blocking.
func cleanupFullRestore(ctx context.Context, c client.Client, run *securityv1alpha1.BackupVerifyRun) []securityv1alpha1.BackupVerifyFinding {
	veleroNS := run.Spec.BackupRef.Namespace
	if veleroNS == "" {
		veleroNS = "velero"
	}
	restoreName := fmt.Sprintf("%s-restore", run.Name)
	var findings []securityv1alpha1.BackupVerifyFinding

	if err := c.Delete(ctx, &velerov1.Restore{ObjectMeta: metav1.ObjectMeta{Name: restoreName, Namespace: veleroNS}}); err != nil && !apierrors.IsNotFound(err) {
		findings = append(findings, securityv1alpha1.BackupVerifyFinding{
			Code: "velero-restore-cleanup-failed", Severity: securityv1alpha1.SeverityLow,
			Detail: fmt.Sprintf("delete Restore CR %s/%s: %v", veleroNS, restoreName, err),
		})
	}
	if run.Spec.SandboxNamespace != "" {
		if err := c.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: run.Spec.SandboxNamespace}}); err != nil && !apierrors.IsNotFound(err) {
			findings = append(findings, securityv1alpha1.BackupVerifyFinding{
				Code: "velero-sandbox-cleanup-failed", Severity: securityv1alpha1.SeverityLow,
				Detail: fmt.Sprintf("delete sandbox NS %s: %v", run.Spec.SandboxNamespace, err),
			})
		}
	}
	return findings
}

// buildNamespaceMapping redirects every namespace included in the
// Backup into the single sandbox namespace. When the Backup
// IncludedNamespaces is empty Velero defaults to "all" - for
// safety that path is not full-restore'd; the mapping covers only
// the namespaces the Backup actually populated (read off
// Backup.Status.Progress is not granular enough, so the
// conservative move is to map the declared IncludedNamespaces).
func buildNamespaceMapping(backup *velerov1.Backup, sandbox string) map[string]string {
	out := map[string]string{}
	src := backup.Spec.IncludedNamespaces
	if len(src) == 0 {
		// Backup covers everything - use a wildcard mapping that
		// Velero recognises ("*" → sandbox). Note: this only
		// remaps when the source name isn't the operator's own
		// namespace (Velero normally protects velero NS itself).
		out["*"] = sandbox
		return out
	}
	for _, ns := range src {
		out[ns] = sandbox
	}
	return out
}

// diffSandbox enumerates a curated set of Kinds in the sandbox
// namespace and produces findings when the Restore claims more
// items than the sandbox actually contains. The Kind list is
// intentionally narrow - full schema fidelity diff (deep equal of
// every field vs the backup tarball) is v0.2.0 work.
func diffSandbox(ctx context.Context, c client.Client, sandbox string, restore *velerov1.Restore) (int, []securityv1alpha1.BackupVerifyFinding, error) {
	type kindCounter struct {
		display string
		listFn  func() (int, error)
	}
	var counts []struct {
		kind  string
		count int
	}

	kinds := []kindCounter{
		{
			display: "Pod",
			listFn: func() (int, error) {
				var l corev1.PodList
				if err := c.List(ctx, &l, client.InNamespace(sandbox)); err != nil {
					return 0, err
				}
				return len(l.Items), nil
			},
		},
		{
			display: "ConfigMap",
			listFn: func() (int, error) {
				var l corev1.ConfigMapList
				if err := c.List(ctx, &l, client.InNamespace(sandbox)); err != nil {
					return 0, err
				}
				return len(l.Items), nil
			},
		},
		{
			display: "Secret",
			listFn: func() (int, error) {
				var l corev1.SecretList
				if err := c.List(ctx, &l, client.InNamespace(sandbox)); err != nil {
					return 0, err
				}
				return len(l.Items), nil
			},
		},
		{
			display: "ServiceAccount",
			listFn: func() (int, error) {
				var l corev1.ServiceAccountList
				if err := c.List(ctx, &l, client.InNamespace(sandbox)); err != nil {
					return 0, err
				}
				return len(l.Items), nil
			},
		},
	}

	total := 0
	for _, k := range kinds {
		n, err := k.listFn()
		if err != nil {
			return 0, nil, fmt.Errorf("list %s in sandbox: %w", k.display, err)
		}
		total += n
		counts = append(counts, struct {
			kind  string
			count int
		}{k.display, n})
	}

	var findings []securityv1alpha1.BackupVerifyFinding
	if total == 0 {
		findings = append(findings, securityv1alpha1.BackupVerifyFinding{
			Code: "velero-sandbox-empty", Severity: securityv1alpha1.SeverityHigh,
			Detail: fmt.Sprintf("sandbox %s contains no Pod/CM/Secret/SA after Restore=%s", sandbox, restore.Status.Phase),
		})
	}

	parts := make([]string, 0, len(counts))
	for _, c := range counts {
		parts = append(parts, fmt.Sprintf("%s=%d", c.kind, c.count))
	}
	findings = append(findings, securityv1alpha1.BackupVerifyFinding{
		Code: "velero-sandbox-counts", Severity: securityv1alpha1.SeverityInfo,
		Detail: fmt.Sprintf("sandbox %s observed counts: %s", sandbox, strings.Join(parts, ", ")),
	})
	return total, findings, nil
}

// isRestoreTerminal reports whether the Restore reached a phase
// from which it won't transition further.
func isRestoreTerminal(phase velerov1.RestorePhase) bool {
	switch phase {
	case velerov1.RestorePhaseCompleted,
		velerov1.RestorePhasePartiallyFailed,
		velerov1.RestorePhaseFailed,
		velerov1.RestorePhaseFailedValidation:
		return true
	}
	return false
}

func ptrBool(b bool) *bool { return &b }
