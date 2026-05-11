// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// RetryAttemptsAnnotation tracks how many times the recoverer has
// reattempted a single ER. Counts up; capped at MaxRetryAttempts.
const RetryAttemptsAnnotation = "ugallu.io/retry-attempts"

// MaxRetryAttempts is the cap before the recoverer marks an ER
// `Failed` with `error.type=Permanent, reason=retry-budget-exhausted`.
const MaxRetryAttempts = 3

// RecoveryGraceWindow is the minimum age (creationTime to now) the
// recoverer requires before touching a Pending/Running ER. Younger
// ERs are still owned by the live pipeline goroutine; touching them
// would race the StepRunner.
const RecoveryGraceWindow = 30 * time.Second

// Recoverer is a one-shot manager.Runnable that walks the cluster
// for forensics-managed ERs in Pending/Running phase and either
// reclaims them (idempotent step types) or marks them Permanent
// (non-idempotent that can't be replayed). Runs once at operator
// startup before the main reconcilers come online.
type Recoverer struct {
	Client      client.Client
	Clientset   kubernetes.Interface
	Freezer     *Freezer
	Snapshotter *Snapshotter
	Uploader    *EvidenceUploader
	StepRunner  *StepRunner
	GraceWindow time.Duration
	MaxAttempts int
	Now         func() time.Time
}

// NewRecoverer validates inputs and applies defaults.
func NewRecoverer(c client.Client, cs kubernetes.Interface, freezer *Freezer, snapshotter *Snapshotter, uploader *EvidenceUploader, runner *StepRunner) (*Recoverer, error) {
	if c == nil || freezer == nil || snapshotter == nil || runner == nil {
		return nil, errors.New("recoverer: Client, Freezer, Snapshotter, StepRunner are required")
	}
	return &Recoverer{
		Client:      c,
		Clientset:   cs,
		Freezer:     freezer,
		Snapshotter: snapshotter,
		Uploader:    uploader,
		StepRunner:  runner,
		GraceWindow: RecoveryGraceWindow,
		MaxAttempts: MaxRetryAttempts,
		Now:         time.Now,
	}, nil
}

// Recover walks every forensics-managed ER in Pending/Running and
// applies the per-step recovery policy (see classifyAndRecover).
// Errors per-ER are logged but never abort the whole sweep - the
// goal is to make as much progress as possible at boot.
func (r *Recoverer) Recover(ctx context.Context) error {
	list := &securityv1alpha1.EventResponseList{}
	if err := r.Client.List(ctx, list, client.MatchingLabels{
		"app.kubernetes.io/managed-by": ManagedByValue,
	}); err != nil {
		return fmt.Errorf("recoverer: list ERs: %w", err)
	}

	cutoff := r.Now().Add(-r.GraceWindow)
	for i := range list.Items {
		er := &list.Items[i]
		if !needsRecovery(er) {
			continue
		}
		if er.CreationTimestamp.After(cutoff) {
			// Still inside the grace window - owned by the live
			// pipeline goroutine. Skip; subsequent sweeps catch
			// any ER that stays Pending past the window.
			recoveryTotal.WithLabelValues("skip_grace_window").Inc()
			continue
		}
		if attempts := readAttempts(er); attempts >= r.MaxAttempts {
			r.markPermanent(ctx, er, "retry-budget-exhausted",
				fmt.Sprintf("recoverer attempted %d times; giving up", attempts))
			recoveryTotal.WithLabelValues("budget_exhausted").Inc()
			continue
		}
		r.classifyAndRecover(ctx, er)
	}
	return nil
}

// classifyAndRecover dispatches per Action.Type.
func (r *Recoverer) classifyAndRecover(ctx context.Context, er *securityv1alpha1.EventResponse) {
	r.bumpAttempt(ctx, er)
	switch er.Spec.Action.Type {
	case securityv1alpha1.ActionPodFreeze:
		r.recoverPodFreeze(ctx, er)
	case securityv1alpha1.ActionPodUnfreeze:
		r.recoverPodUnfreeze(ctx, er)
	case securityv1alpha1.ActionFilesystemSnapshot:
		r.recoverFilesystemSnapshot(ctx, er)
	case securityv1alpha1.ActionEvidenceUpload:
		r.recoverEvidenceUpload(ctx, er)
	default:
		r.markPermanent(ctx, er, "unknown-action",
			fmt.Sprintf("recoverer cannot classify action %q", er.Spec.Action.Type))
		recoveryTotal.WithLabelValues("unknown_action").Inc()
	}
}

// recoverPodFreeze re-applies the freeze. Idempotent: Create on
// the (Cilium)NetworkPolicy returns AlreadyExists which the
// freezer treats as success; the Pod label patch is also a no-op
// when the value already matches.
func (r *Recoverer) recoverPodFreeze(ctx context.Context, er *securityv1alpha1.EventResponse) {
	pod, ok := r.fetchTargetPod(ctx, er)
	if !ok {
		r.markPermanent(ctx, er, "target-deleted", "suspect Pod no longer exists")
		recoveryTotal.WithLabelValues("target_deleted").Inc()
		return
	}
	if err := r.Freezer.Freeze(ctx, pod); err != nil {
		recoveryTotal.WithLabelValues("freeze_retry_error").Inc()
		return
	}
	r.markSucceeded(ctx, er)
	recoveryTotal.WithLabelValues("freeze_recovered").Inc()
}

// recoverPodUnfreeze re-runs Unfreeze (delete-if-exists CNP +
// remove-if-present label). Idempotent.
func (r *Recoverer) recoverPodUnfreeze(ctx context.Context, er *securityv1alpha1.EventResponse) {
	pod, ok := r.fetchTargetPod(ctx, er)
	if !ok {
		// Pod gone is fine - unfreeze is implicitly satisfied.
		r.markSucceeded(ctx, er)
		recoveryTotal.WithLabelValues("unfreeze_target_gone").Inc()
		return
	}
	if err := r.Freezer.Unfreeze(ctx, pod); err != nil {
		recoveryTotal.WithLabelValues("unfreeze_retry_error").Inc()
		return
	}
	r.markSucceeded(ctx, er)
	recoveryTotal.WithLabelValues("unfreeze_recovered").Inc()
}

// recoverFilesystemSnapshot is the only non-idempotent step. The
// recovery policy:
//   - If the ephemeral container exists and is Running → wait for
//     completion in the next reconcile cycle (do nothing now).
//   - If Terminated success → fetch logs, parse Result, patch ER.
//   - If absent or Failed → permanent failure (rerunning would
//     append a SECOND ephemeral container, which is wrong).
func (r *Recoverer) recoverFilesystemSnapshot(ctx context.Context, er *securityv1alpha1.EventResponse) {
	pod, ok := r.fetchTargetPod(ctx, er)
	if !ok {
		r.markPermanent(ctx, er, "target-deleted", "suspect Pod no longer exists")
		recoveryTotal.WithLabelValues("snapshot_target_deleted").Inc()
		return
	}
	incidentUID := er.Labels[IncidentLabel]
	if incidentUID == "" {
		r.markPermanent(ctx, er, "missing-incident-label", "ER lacks ugallu.io/incident-uid")
		recoveryTotal.WithLabelValues("snapshot_no_incident").Inc()
		return
	}
	containerName := snapshotContainerName(incidentUID)

	for i := range pod.Status.EphemeralContainerStatuses {
		st := &pod.Status.EphemeralContainerStatuses[i]
		if st.Name != containerName {
			continue
		}
		switch {
		case st.State.Running != nil:
			// Still running - leave it alone, the next reconcile
			// pass picks it up.
			recoveryTotal.WithLabelValues("snapshot_still_running").Inc()
			return
		case st.State.Terminated != nil && st.State.Terminated.ExitCode == 0:
			// Salvage: read logs, parse Result, patch ER.
			if r.salvageSnapshotLogs(ctx, pod, containerName, er) {
				recoveryTotal.WithLabelValues("snapshot_salvaged").Inc()
			} else {
				recoveryTotal.WithLabelValues("snapshot_salvage_failed").Inc()
			}
			return
		case st.State.Terminated != nil:
			r.markPermanent(ctx, er, "interrupted-snapshot",
				fmt.Sprintf("ephemeral container exited %d: %s",
					st.State.Terminated.ExitCode, st.State.Terminated.Reason))
			recoveryTotal.WithLabelValues("snapshot_failed").Inc()
			return
		}
	}
	// Container was never injected - operator died before adding
	// it. The freeze is in place but no snapshot ran. Mark
	// Permanent so the human + IR review can decide whether to
	// open a new incident.
	r.markPermanent(ctx, er, "interrupted-snapshot", "ephemeral container never started")
	recoveryTotal.WithLabelValues("snapshot_never_started").Inc()
}

// recoverEvidenceUpload rebuilds the manifest from the Succeeded
// upstream ERs of the same incident and re-uploads. Idempotent -
// the manifest body is content-addressed so an identical re-run
// produces the same key + same blob; an attempted overwrite of
// existing content is Object-Lock-rejected and the recoverer
// treats that as success.
func (r *Recoverer) recoverEvidenceUpload(ctx context.Context, er *securityv1alpha1.EventResponse) {
	if r.Uploader == nil {
		r.markPermanent(ctx, er, "evidence-upload-disabled", "Uploader nil; manifest cannot be rebuilt")
		recoveryTotal.WithLabelValues("upload_disabled").Inc()
		return
	}
	incidentUID := er.Labels[IncidentLabel]
	if incidentUID == "" {
		r.markPermanent(ctx, er, "missing-incident-label", "ER lacks ugallu.io/incident-uid")
		recoveryTotal.WithLabelValues("upload_no_incident").Inc()
		return
	}
	upstream, err := r.collectIncidentEvidence(ctx, incidentUID, er.Name)
	if err != nil {
		recoveryTotal.WithLabelValues("upload_collect_error").Inc()
		return
	}
	pod, ok := r.fetchTargetPod(ctx, er)
	if !ok {
		r.markPermanent(ctx, er, "target-deleted", "suspect Pod no longer exists")
		recoveryTotal.WithLabelValues("upload_target_deleted").Inc()
		return
	}
	manifest, err := BuildManifest(
		&Incident{
			UID: incidentUID,
			TriggerSE: &securityv1alpha1.SecurityEvent{
				ObjectMeta: metav1.ObjectMeta{UID: types.UID(er.Spec.Action.Parameters["trigger.uid"])},
				Spec:       securityv1alpha1.SecurityEventSpec{Type: er.Spec.Action.Parameters["trigger.type"]},
			},
		},
		pod,
		r.StepRunner.ClusterIdentity,
		upstream,
		stepFromMediaType,
		r.Now(),
	)
	if err != nil {
		recoveryTotal.WithLabelValues("upload_manifest_error").Inc()
		return
	}
	ref, err := r.Uploader.Upload(ctx, manifest)
	if err != nil {
		recoveryTotal.WithLabelValues("upload_retry_error").Inc()
		return
	}
	patch := er.DeepCopy()
	patch.Status.Phase = securityv1alpha1.EventResponsePhaseSucceeded
	now := metav1.NewTime(r.Now())
	patch.Status.CompletedAt = &now
	patch.Status.Outcome = &securityv1alpha1.Outcome{
		Type:    securityv1alpha1.OutcomeActionTaken,
		Message: "evidence upload recovered",
	}
	patch.Status.Evidence = []securityv1alpha1.EvidenceRef{*ref}
	_ = r.Client.Status().Patch(ctx, patch, client.MergeFrom(er))
	recoveryTotal.WithLabelValues("upload_recovered").Inc()
}

// fetchTargetPod resolves the suspect Pod from the ER's
// Action.TargetRef. False return = NotFound; transient errors
// (apiserver hiccup) leave the ER in Pending so the next sweep
// retries.
func (r *Recoverer) fetchTargetPod(ctx context.Context, er *securityv1alpha1.EventResponse) (*corev1.Pod, bool) {
	if er.Spec.Action.TargetRef == nil {
		return nil, false
	}
	pod := &corev1.Pod{}
	key := client.ObjectKey{
		Namespace: er.Spec.Action.TargetRef.Namespace,
		Name:      er.Spec.Action.TargetRef.Name,
	}
	if err := r.Client.Get(ctx, key, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false
		}
		return nil, false
	}
	return pod, true
}

// salvageSnapshotLogs reads the ephemeral container's stdout, parses
// the JSON Result, and patches the ER status. Returns true on
// success.
func (r *Recoverer) salvageSnapshotLogs(ctx context.Context, pod *corev1.Pod, container string, er *securityv1alpha1.EventResponse) bool {
	if r.Clientset == nil || r.Snapshotter == nil {
		return false
	}
	logs, err := r.Snapshotter.readContainerLogs(ctx, pod, container)
	if err != nil {
		return false
	}
	res, err := parseSnapshotResult(logs)
	if err != nil {
		return false
	}
	patch := er.DeepCopy()
	now := metav1.NewTime(r.Now())
	patch.Status.Phase = securityv1alpha1.EventResponsePhaseSucceeded
	patch.Status.CompletedAt = &now
	patch.Status.Outcome = &securityv1alpha1.Outcome{
		Type:    securityv1alpha1.OutcomeActionTaken,
		Message: "snapshot recovered",
	}
	patch.Status.Evidence = []securityv1alpha1.EvidenceRef{{
		MediaType: res.MediaType,
		URL:       res.URL,
		SHA256:    res.SHA256,
		Size:      res.Size,
	}}
	if err := r.Client.Status().Patch(ctx, patch, client.MergeFrom(er)); err != nil {
		return false
	}
	return true
}

// collectIncidentEvidence assembles the EvidenceRef list from every
// Succeeded ER of an incident, excluding selfName (so the
// EvidenceUpload ER doesn't include itself).
func (r *Recoverer) collectIncidentEvidence(ctx context.Context, incidentUID, selfName string) ([]securityv1alpha1.EvidenceRef, error) {
	list := &securityv1alpha1.EventResponseList{}
	if err := r.Client.List(ctx, list, client.MatchingLabels{IncidentLabel: incidentUID}); err != nil {
		return nil, err
	}
	out := make([]securityv1alpha1.EvidenceRef, 0)
	for i := range list.Items {
		er := &list.Items[i]
		if er.Name == selfName {
			continue
		}
		if er.Status.Phase != securityv1alpha1.EventResponsePhaseSucceeded {
			continue
		}
		out = append(out, er.Status.Evidence...)
	}
	return out, nil
}

// markSucceeded patches an ER to Phase=Succeeded after a
// successful recovery retry. Outcome message reflects the recovery
// path so the audit trail records this wasn't a first-try success.
func (r *Recoverer) markSucceeded(ctx context.Context, er *securityv1alpha1.EventResponse) {
	patch := er.DeepCopy()
	now := metav1.NewTime(r.Now())
	patch.Status.Phase = securityv1alpha1.EventResponsePhaseSucceeded
	patch.Status.CompletedAt = &now
	patch.Status.Outcome = &securityv1alpha1.Outcome{
		Type:    securityv1alpha1.OutcomeActionTaken,
		Message: "step recovered post-restart",
	}
	_ = r.Client.Status().Patch(ctx, patch, client.MergeFrom(er))
}

// markPermanent terminates an ER as Phase=Failed +
// error.type=Permanent so the audit trail captures the
// non-recoverable failure mode.
func (r *Recoverer) markPermanent(ctx context.Context, er *securityv1alpha1.EventResponse, reason, detail string) {
	patch := er.DeepCopy()
	now := metav1.NewTime(r.Now())
	patch.Status.Phase = securityv1alpha1.EventResponsePhaseFailed
	patch.Status.CompletedAt = &now
	patch.Status.Outcome = &securityv1alpha1.Outcome{
		Type:    securityv1alpha1.OutcomeErrored,
		Message: detail,
	}
	patch.Status.Error = &securityv1alpha1.ResponseError{
		Type:   securityv1alpha1.ErrorPermanent,
		Reason: reason,
		Detail: detail,
	}
	_ = r.Client.Status().Patch(ctx, patch, client.MergeFrom(er))
}

// bumpAttempt increments the retry-attempts annotation. Used to
// drive the MaxRetryAttempts cap.
func (r *Recoverer) bumpAttempt(ctx context.Context, er *securityv1alpha1.EventResponse) {
	patch := er.DeepCopy()
	if patch.Annotations == nil {
		patch.Annotations = map[string]string{}
	}
	patch.Annotations[RetryAttemptsAnnotation] = strconv.Itoa(readAttempts(er) + 1)
	_ = r.Client.Patch(ctx, patch, client.MergeFrom(er))
}

// needsRecovery returns true for ERs the recoverer should sweep.
func needsRecovery(er *securityv1alpha1.EventResponse) bool {
	switch er.Status.Phase {
	case securityv1alpha1.EventResponsePhasePending,
		securityv1alpha1.EventResponsePhaseRunning,
		"":
		return true
	default:
		return false
	}
}

// readAttempts returns the current retry-attempts counter (0 if
// unset).
func readAttempts(er *securityv1alpha1.EventResponse) int {
	if er.Annotations == nil {
		return 0
	}
	v, _ := strconv.Atoi(er.Annotations[RetryAttemptsAnnotation])
	return v
}

// stepFromMediaType maps an EvidenceRef's MediaType back to the
// step name, mirroring step_evidence.go's logic so the recovery
// path produces the same canonical manifest as the live path.
func stepFromMediaType(ev securityv1alpha1.EvidenceRef) string {
	switch ev.MediaType {
	case "application/x-tar+gzip":
		return "filesystem-snapshot"
	case ManifestMediaType:
		return "evidence-upload"
	default:
		return "unknown"
	}
}
