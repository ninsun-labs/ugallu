// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// IncidentLabel labels every per-step ER with the incident UID so a
// `kubectl get er -l ugallu.io/incident-uid=<uid>` reconstructs the
// pipeline at-a-glance.
const IncidentLabel = "ugallu.io/incident-uid"

// ParentERLabel labels every step ER with the UID of its predecessor
// in the same incident. Empty on the first step. Walking this chain
// reconstructs the pipeline order purely from the data, independent
// of wall-clock timestamps (which a leader change could skew).
const ParentERLabel = "ugallu.io/parent-er"

// StepLabel labels every per-step ER with the action.type as a
// short string so kubectl filtering ("show me all the freezes")
// works without parsing spec.action.type.
const StepLabel = "ugallu.io/step"

// ResponderName is the value forensics writes into ER.spec.responder
// so the gitops-responder + future responders skip these ERs.
const ResponderName = "ugallu-forensics"

// Step is one atomic IR unit. Each Step is wrapped in an
// EventResponse so the attestor can sign it independently of the
// pipeline's wall-clock progress (the pipeline is sequential; ER
// attestation is async).
//
// Implementations expose:
//   - Type(): the ActionType used in spec.action.type.
//   - Run(ctx, *StepExecution): the actual work. It returns the
//     evidence + parameters via the StepExecution so the runner
//     can stamp them on the ER status without the Step needing
//     direct ER access.
//   - Recover(ctx, *StepExecution): the crash-recovery entry
//     point — Sprint 3 commit C will populate this; Sprint 3
//     commit A leaves a default no-op so the surface is stable.
type Step interface {
	Type() securityv1alpha1.ActionType
	Run(ctx context.Context, exec *StepExecution) error
}

// StepExecution carries the per-incident shared state across every
// Step in the pipeline. It is created once per incident and each
// Step appends to it.
type StepExecution struct {
	// Incident is the in-flight capture record.
	Incident *Incident

	// Pod is the live suspect Pod (fetched once at pipeline start).
	Pod *corev1.Pod

	// Evidence is the per-incident running list of evidence refs.
	// FilesystemSnapshot appends one entry; EvidenceUpload appends
	// the manifest entry. PodFreeze / PodUnfreeze contribute no
	// evidence (they're K8s-object actions, not blob uploads).
	Evidence []securityv1alpha1.EvidenceRef

	// Parameters is per-step and resets between steps. The runner
	// copies it into the ER's spec.action.parameters before Run().
	Parameters map[string]string

	// LastERUID carries the previous step's ER UID forward so the
	// next StepRunner uses it as the ParentERLabel value.
	LastERUID types.UID
}

// StepRunner owns the per-step ER lifecycle: build the ER, Create
// it, invoke Step.Run, patch ER status. Sprint 3 commit C extends
// it with crash-recovery entry points — Sprint 3 commit A keeps
// the lifecycle simple and additive.
type StepRunner struct {
	// Client is the controller-runtime client with cluster-wide
	// EventResponse + EventResponse/status RBAC.
	Client client.Client

	// ClusterIdentity stamps every ER (via the ER spec, not as a
	// distinct field) so the attestor's bundle echoes the cluster
	// the event came from.
	ClusterIdentity securityv1alpha1.ClusterIdentity
}

// NewStepRunner validates inputs and returns a StepRunner.
func NewStepRunner(c client.Client, ci securityv1alpha1.ClusterIdentity) (*StepRunner, error) {
	if c == nil {
		return nil, errors.New("steprunner: Client is required")
	}
	return &StepRunner{Client: c, ClusterIdentity: ci}, nil
}

// Run executes one Step inside the IR pipeline. It is sequential
// with respect to the caller (returns only after the step body
// completes); the per-step ER attestation runs async (the attestor
// picks up the patched-Succeeded ER on its own watch).
//
// Sequence:
//  1. Build ER (deterministic name from incident UID + step type).
//  2. Create. AlreadyExists → recovery entry (caller decides how
//     to proceed; commit C wires the actual recovery).
//  3. Invoke step.Run; collect evidence + parameters via exec.
//  4. Patch ER status to Succeeded / Failed with outcome + evidence.
//  5. Stamp exec.LastERUID so the next step picks it up as parent.
func (r *StepRunner) Run(ctx context.Context, step Step, exec *StepExecution) error {
	if exec == nil || exec.Incident == nil || exec.Pod == nil {
		return errors.New("steprunner: incident + pod are required")
	}
	exec.Parameters = map[string]string{}

	er := r.buildER(step, exec)
	createErr := r.Client.Create(ctx, er)
	switch {
	case createErr == nil:
		// fresh ER, proceed
	case apierrors.IsAlreadyExists(createErr):
		// Recovery scenario: re-fetch the existing ER. Commit C
		// classifies recoverable / permanent based on its phase;
		// commit A keeps the pre-existing object as-is and runs
		// the step body again (idempotent for PodFreeze /
		// PodUnfreeze — non-idempotent steps fall through and
		// the runner records the second attempt's outcome).
		if err := r.Client.Get(ctx, client.ObjectKeyFromObject(er), er); err != nil {
			return fmt.Errorf("steprunner: refetch existing ER %s: %w", er.Name, err)
		}
	default:
		return fmt.Errorf("steprunner: create ER %s: %w", er.Name, createErr)
	}

	now := metav1.NewTime(time.Now())
	r.markStarted(ctx, er, now)

	runErr := step.Run(ctx, exec)
	if runErr != nil {
		r.markFailed(ctx, er, runErr)
		return runErr
	}
	r.markSucceeded(ctx, er, exec, now)
	exec.LastERUID = er.UID
	return nil
}

// buildER constructs the typed ER for a single Step. The name is
// deterministic (`er-<incident-uid>-<step-type>`) so a re-run lands
// on the same object — important for crash recovery in commit C.
func (r *StepRunner) buildER(step Step, exec *StepExecution) *securityv1alpha1.EventResponse {
	stepKey := stepKey(step.Type())
	labels := map[string]string{
		"app.kubernetes.io/managed-by": ManagedByValue,
		IncidentLabel:                  exec.Incident.UID,
		StepLabel:                      stepKey,
	}
	if exec.LastERUID != "" {
		labels[ParentERLabel] = string(exec.LastERUID)
	}
	return &securityv1alpha1.EventResponse{
		ObjectMeta: metav1.ObjectMeta{
			Name:   fmt.Sprintf("er-%s-%s", exec.Incident.UID, stepKey),
			Labels: labels,
		},
		Spec: securityv1alpha1.EventResponseSpec{
			Responder: securityv1alpha1.ResponderRef{
				Kind: "Operator",
				Name: ResponderName,
			},
			Action: securityv1alpha1.Action{
				Type: step.Type(),
				TargetRef: &corev1.ObjectReference{
					APIVersion: "v1",
					Kind:       "Pod",
					Namespace:  exec.Pod.Namespace,
					Name:       exec.Pod.Name,
					UID:        exec.Pod.UID,
				},
				Parameters: copyParams(exec.Parameters),
			},
		},
	}
}

// markStarted patches the ER status with Phase=InProgress and
// StartedAt — the attestor still won't seal until Phase=Succeeded
// or Phase=Failed.
func (r *StepRunner) markStarted(ctx context.Context, er *securityv1alpha1.EventResponse, now metav1.Time) {
	patch := er.DeepCopy()
	patch.Status.Phase = securityv1alpha1.EventResponsePhaseRunning
	patch.Status.StartedAt = &now
	patch.Status.Attempts = er.Status.Attempts + 1
	_ = r.Client.Status().Patch(ctx, patch, client.MergeFrom(er))
}

// markSucceeded patches the ER to Phase=Succeeded with the
// collected evidence + outcome. Evidence is copied off the
// StepExecution so subsequent Steps can append without mutating
// the closed ER.
func (r *StepRunner) markSucceeded(ctx context.Context, er *securityv1alpha1.EventResponse, exec *StepExecution, started metav1.Time) {
	now := metav1.NewTime(time.Now())
	patch := er.DeepCopy()
	patch.Status.Phase = securityv1alpha1.EventResponsePhaseSucceeded
	patch.Status.StartedAt = &started
	patch.Status.CompletedAt = &now
	patch.Status.Outcome = &securityv1alpha1.Outcome{
		Type:    securityv1alpha1.OutcomeActionTaken,
		Message: "step completed",
	}
	if len(exec.Evidence) > 0 {
		patch.Status.Evidence = append([]securityv1alpha1.EvidenceRef(nil), exec.Evidence...)
	}
	if err := r.Client.Status().Patch(ctx, patch, client.MergeFrom(er)); err == nil {
		// Capture the UID off the patched-back object so the next
		// step's parent label is set correctly.
		er.UID = patch.UID
	}
}

// markFailed patches the ER to Phase=Failed with a categorised
// error reason. The attestor still attests the ER (the failure is
// itself an audit fact); the bundle's signed statement records the
// failure outcome.
func (r *StepRunner) markFailed(ctx context.Context, er *securityv1alpha1.EventResponse, runErr error) {
	now := metav1.NewTime(time.Now())
	patch := er.DeepCopy()
	patch.Status.Phase = securityv1alpha1.EventResponsePhaseFailed
	patch.Status.CompletedAt = &now
	patch.Status.Outcome = &securityv1alpha1.Outcome{
		Type:    securityv1alpha1.OutcomeErrored,
		Message: runErr.Error(),
	}
	patch.Status.Error = &securityv1alpha1.ResponseError{
		Type:   classifyError(runErr),
		Reason: classifyReason(runErr),
		Detail: runErr.Error(),
	}
	_ = r.Client.Status().Patch(ctx, patch, client.MergeFrom(er))
}

// classifyError maps a Go error into the typed ER error category.
// Sprint 3 commit C will recognise the transient-vs-permanent
// classes properly; commit A returns a coarse "Permanent" for
// every step failure so the audit trail is honest.
func classifyError(err error) securityv1alpha1.ErrorCategory {
	if err == nil {
		return ""
	}
	return securityv1alpha1.ErrorPermanent
}

// classifyReason returns a short tag describing the failure mode.
// Stub for commit A; commit C extends with per-step reasons
// (psa-rejected, target-deleted, truncated, etc.).
func classifyReason(err error) string {
	if err == nil {
		return ""
	}
	return "step-failed"
}

// stepKey returns the lower-case label-friendly slug for a step
// ActionType. Used in the ER name + StepLabel value.
func stepKey(t securityv1alpha1.ActionType) string {
	switch t {
	case securityv1alpha1.ActionPodFreeze:
		return "podfreeze"
	case securityv1alpha1.ActionPodUnfreeze:
		return "podunfreeze"
	case securityv1alpha1.ActionFilesystemSnapshot:
		return "filesystem-snapshot"
	case securityv1alpha1.ActionEvidenceUpload:
		return "evidence-upload"
	default:
		return "unknown"
	}
}

// copyParams returns a defensive copy so a Step mutating its
// Parameters mid-run does not leak into the previously-stamped ER.
func copyParams(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
