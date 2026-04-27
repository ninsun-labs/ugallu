// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package controller hosts the EventResponse reconciler used by the
// GitOps responder. The reconciler claims EventResponse CRs whose
// action.type is GitOpsChange and dispatches them through a
// git.Provider (selected via the configured Router).
package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/gitops-responder/pkg/git"
	"github.com/ninsun-labs/ugallu/operators/gitops-responder/pkg/router"
)

// ResponderName is the value EventResponses must carry in
// spec.responder.name to be claimed by this operator.
const ResponderName = "ugallu-gitops-responder"

// FieldManagerName is used as the Server-Side-Apply manager so an
// operator can tell which controller wrote the status fields.
const FieldManagerName = ResponderName

// EventResponseReconciler watches GitOpsChange EventResponse CRs and
// delegates to the configured Provider via the Router.
type EventResponseReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Routes    *router.Snapshot
	Providers map[string]git.Provider

	// MaxAttempts caps the number of Apply attempts for a given ER
	// before the reconciler gives up and surfaces a Failed phase.
	// Zero falls back to spec.retryPolicy.maxAttempts (or 3).
	MaxAttempts int
}

// Reconcile implements the controller-runtime contract.
func (r *EventResponseReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rlog := log.FromContext(ctx).WithName("er-gitops").WithValues("name", req.Name)

	er := &securityv1alpha1.EventResponse{}
	if err := r.Get(ctx, req.NamespacedName, er); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !shouldClaim(er) {
		return ctrl.Result{}, nil
	}

	switch er.Status.Phase {
	case securityv1alpha1.EventResponsePhaseSucceeded,
		securityv1alpha1.EventResponsePhaseFailed,
		securityv1alpha1.EventResponsePhaseCancelled:
		return ctrl.Result{}, nil
	}

	rt := r.Routes.Current()
	if rt == nil {
		rlog.Info("router not yet ready; requeueing")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	repo := rt.Route(er.Namespace, er.Labels)
	providerName := repo.Provider
	if providerName == "" {
		providerName = rt.DefaultProvider()
	}
	provider, ok := r.Providers[providerName]
	if !ok {
		return r.markFailed(ctx, er, fmt.Sprintf("unknown provider %q", providerName))
	}

	attempts := er.Status.Attempts + 1
	maxAttempts := r.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = er.Spec.RetryPolicy.MaxAttempts
	}
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	now := metav1.Now()
	er.Status.Phase = securityv1alpha1.EventResponsePhaseRunning
	if er.Status.StartedAt == nil {
		er.Status.StartedAt = &now
	}
	er.Status.LastAttemptAt = &now
	er.Status.Attempts = attempts
	if err := r.Status().Update(ctx, er); err != nil {
		return ctrl.Result{}, err
	}

	change := buildChangeRequest(er, repo)
	pr, err := provider.Apply(ctx, change)
	if err != nil {
		if attempts >= maxAttempts {
			return r.markFailed(ctx, er, fmt.Sprintf("attempt %d/%d: %s", attempts, maxAttempts, err))
		}
		return r.markRetrying(ctx, er, err)
	}

	completion := metav1.Now()
	er.Status.Phase = securityv1alpha1.EventResponsePhaseSucceeded
	er.Status.CompletedAt = &completion
	er.Status.Outcome = &securityv1alpha1.Outcome{
		Type:    securityv1alpha1.OutcomeActionTaken,
		Message: fmt.Sprintf("PR %s opened on branch %s", pr.URL, pr.Branch),
	}
	er.Status.Evidence = append(er.Status.Evidence, securityv1alpha1.EvidenceRef{
		MediaType: "application/vnd.ugallu.gitops-change+json",
		URL:       pr.URL,
		SHA256:    pr.CommitSHA,
	})
	er.Status.Error = nil
	if err := r.Status().Update(ctx, er); err != nil {
		return ctrl.Result{}, err
	}
	rlog.Info("git change applied", "url", pr.URL, "branch", pr.Branch, "sha", pr.CommitSHA)
	return ctrl.Result{}, nil
}

// SetupWithManager wires the reconciler.
func (r *EventResponseReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("eventresponse-gitops").
		For(&securityv1alpha1.EventResponse{}).
		Complete(r)
}

// --- helpers -----------------------------------------------------------------

// shouldClaim filters the ER to GitOpsChange actions claimed by this
// reconciler. The check is tolerant to both an explicit
// responder.name match and the missing-responder case: when
// responder.name is empty, action.type alone gates the claim.
func shouldClaim(er *securityv1alpha1.EventResponse) bool {
	if er.Spec.Action.Type != securityv1alpha1.ActionGitOpsChange {
		return false
	}
	rname := strings.TrimSpace(er.Spec.Responder.Name)
	if rname != "" && rname != ResponderName {
		return false
	}
	return true
}

// buildChangeRequest extracts the typed parameters from the ER.
// Recognised parameters (all optional except path / contents):
//   - "path"            target file path inside the repo
//   - "contents"        UTF-8 file body
//   - "delete"          "true" to mark as deletion (ignores contents)
//   - "branch"          override branch name
//   - "commitTitle"     first line of the commit message
//   - "commitBody"      remainder of the commit message
//   - "prTitle"         PR title (defaults to commitTitle)
//   - "prBody"          PR body (defaults to commitBody)
//
// Multi-file PRs are encoded by repeating "path" / "contents" entries
// with a numeric suffix (path1, contents1, path2, ...). Missing path
// yields an error in Reconcile via Provider.Apply.
func buildChangeRequest(er *securityv1alpha1.EventResponse, repo securityv1alpha1.GitRepo) *git.ChangeRequest {
	p := er.Spec.Action.Parameters
	if p == nil {
		p = map[string]string{}
	}
	branch := p["branch"]
	if branch == "" {
		branch = fmt.Sprintf("ugallu/%s/%s", er.Spec.SecurityEventRef.Name, shortUID(er.UID))
	}
	commitTitle := p["commitTitle"]
	if commitTitle == "" {
		commitTitle = fmt.Sprintf("ugallu: respond to %s", er.Spec.SecurityEventRef.Name)
	}
	commitBody := p["commitBody"]
	prTitle := p["prTitle"]
	if prTitle == "" {
		prTitle = commitTitle
	}
	prBody := p["prBody"]
	if prBody == "" {
		prBody = commitBody
	}
	files := collectFiles(p)
	return &git.ChangeRequest{
		Repo:        repo,
		BranchName:  branch,
		BaseBranch:  repo.Branch,
		CommitTitle: commitTitle,
		CommitBody:  commitBody,
		PRTitle:     prTitle,
		PRBody:      prBody,
		Files:       files,
	}
}

// collectFiles walks the parameters map for path/contents tuples.
// Single-file shortcut: "path" + "contents" + optional "delete".
// Numbered: "path1" / "contents1" / "delete1", etc.
func collectFiles(p map[string]string) []git.FileChange {
	out := []git.FileChange{}
	if path := p["path"]; path != "" {
		out = append(out, git.FileChange{
			Path:     path,
			Contents: []byte(p["contents"]),
			Delete:   strings.EqualFold(p["delete"], "true"),
		})
	}
	for i := 1; ; i++ {
		key := fmt.Sprintf("path%d", i)
		path, ok := p[key]
		if !ok {
			break
		}
		out = append(out, git.FileChange{
			Path:     path,
			Contents: []byte(p[fmt.Sprintf("contents%d", i)]),
			Delete:   strings.EqualFold(p[fmt.Sprintf("delete%d", i)], "true"),
		})
	}
	return out
}

func shortUID(u types.UID) string {
	s := string(u)
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// markFailed transitions the ER to Failed with the given reason.
func (r *EventResponseReconciler) markFailed(ctx context.Context, er *securityv1alpha1.EventResponse, reason string) (ctrl.Result, error) {
	now := metav1.Now()
	er.Status.Phase = securityv1alpha1.EventResponsePhaseFailed
	er.Status.CompletedAt = &now
	er.Status.Error = &securityv1alpha1.ResponseError{
		Type:   securityv1alpha1.ErrorPermanent,
		Reason: reason,
	}
	er.Status.Outcome = &securityv1alpha1.Outcome{
		Type:    securityv1alpha1.OutcomeErrored,
		Message: reason,
	}
	if err := r.Status().Update(ctx, er); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// markRetrying schedules another attempt and records the transient
// error for observability.
func (r *EventResponseReconciler) markRetrying(ctx context.Context, er *securityv1alpha1.EventResponse, err error) (ctrl.Result, error) {
	delay := 30 * time.Second
	if er.Spec.RetryPolicy.InitialDelay.Duration > 0 {
		delay = er.Spec.RetryPolicy.InitialDelay.Duration
	}
	next := metav1.NewTime(time.Now().Add(delay))
	er.Status.Phase = securityv1alpha1.EventResponsePhasePending
	er.Status.NextAttemptAt = &next
	er.Status.Error = &securityv1alpha1.ResponseError{
		Type:   securityv1alpha1.ErrorTransient,
		Reason: err.Error(),
	}
	if upErr := r.Status().Update(ctx, er); upErr != nil {
		return ctrl.Result{}, upErr
	}
	return ctrl.Result{RequeueAfter: delay}, nil
}
