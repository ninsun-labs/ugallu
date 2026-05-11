// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"context"
	"fmt"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// PodFreezeStep wraps Freezer for the IR pipeline. The Step itself
// is just a thin adapter - Freezer carries the (Cilium)NetworkPolicy
// + Pod label logic and stays usable directly when the operator
// (e.g. crash recovery in commit C) needs to bypass the ER chain.
type PodFreezeStep struct {
	Freezer *Freezer
}

// Type returns the ER ActionType for this step.
func (s *PodFreezeStep) Type() securityv1alpha1.ActionType {
	return securityv1alpha1.ActionPodFreeze
}

// Run isolates the suspect Pod. Idempotent - re-running on an
// already-frozen Pod is a no-op.
func (s *PodFreezeStep) Run(ctx context.Context, exec *StepExecution) error {
	if err := s.Freezer.Freeze(ctx, exec.Pod); err != nil {
		return err
	}
	exec.Parameters["policy.backend"] = string(s.Freezer.opts.Backend)
	exec.Parameters["policy.name"] = s.Freezer.policyName(exec.Pod)
	exec.Parameters["pod.uid"] = string(exec.Pod.UID)
	return nil
}

// PodUnfreezeStep wraps Freezer.Unfreeze. Used by the manual-
// acknowledge controller and (in commit C) by the auto-unfreeze
// timer.
type PodUnfreezeStep struct {
	Freezer *Freezer
}

// Type returns the ER ActionType for this step.
func (s *PodUnfreezeStep) Type() securityv1alpha1.ActionType {
	return securityv1alpha1.ActionPodUnfreeze
}

// Run reverses the freeze. Idempotent - both delete-if-exists
// (NetworkPolicy) and remove-if-present (Pod label).
func (s *PodUnfreezeStep) Run(ctx context.Context, exec *StepExecution) error {
	if err := s.Freezer.Unfreeze(ctx, exec.Pod); err != nil {
		return err
	}
	exec.Parameters["policy.backend"] = string(s.Freezer.opts.Backend)
	exec.Parameters["policy.name"] = s.Freezer.policyName(exec.Pod)
	exec.Parameters["pod.uid"] = string(exec.Pod.UID)
	return nil
}

// FilesystemSnapshotStep wraps Snapshotter.Capture and propagates
// the resulting JSON Result onto the StepExecution as one
// EvidenceRef (the snapshot blob URL + sha256 + size).
type FilesystemSnapshotStep struct {
	Snapshotter *Snapshotter

	// Config is the per-incident SnapshotConfig (from
	// ForensicsConfig.spec.snapshot, with operator defaults filled
	// in by the pipeline before invoking the step).
	Config *securityv1alpha1.SnapshotConfig
}

// Type returns the ER ActionType for this step.
func (s *FilesystemSnapshotStep) Type() securityv1alpha1.ActionType {
	return securityv1alpha1.ActionFilesystemSnapshot
}

// Run injects the ephemeral snapshot container, polls for its
// termination, and parses the JSON Result on stdout. The blob URL
// + sha256 + size are appended to exec.Evidence so the StepRunner
// stamps them onto the ER.
func (s *FilesystemSnapshotStep) Run(ctx context.Context, exec *StepExecution) error {
	res, err := s.Snapshotter.Capture(ctx, exec.Pod, exec.Incident, s.Config)
	if err != nil {
		return err
	}
	exec.Evidence = append(exec.Evidence, securityv1alpha1.EvidenceRef{
		MediaType: res.MediaType,
		URL:       res.URL,
		SHA256:    res.SHA256,
		Size:      res.Size,
	})
	exec.Parameters["snapshot.duration_ms"] = fmt.Sprintf("%d", res.DurationMS)
	if res.Truncated {
		exec.Parameters["snapshot.truncated"] = "true"
	}
	return nil
}
