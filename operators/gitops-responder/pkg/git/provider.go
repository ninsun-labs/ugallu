// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package git abstracts the GitOps responder's interaction with a
// remote SCM. Concrete provider implementations (GitHub, GitLab,
// Gitea, ...) live in sibling packages; this file defines the
// minimal surface the EventResponse reconciler depends on.
package git

import (
	"context"
	"errors"
	"time"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// PullRequest captures the result of a successful change submission.
// PRNumber and URL are the operator-facing handles recorded in the
// EventResponse status; CommitSHA optionally pins the underlying
// content hash for forensic chaining.
type PullRequest struct {
	URL       string
	PRNumber  int
	Branch    string
	CommitSHA string
	CreatedAt time.Time
}

// ChangeRequest is the data shape passed to a Provider. It encodes
// what the responder learned from the EventResponse: the target
// repository, the branch convention, the commit content (a list of
// {path, contents} pairs), and the surrounding PR metadata.
type ChangeRequest struct {
	Repo        securityv1alpha1.GitRepo
	BranchName  string
	BaseBranch  string
	CommitTitle string
	CommitBody  string
	PRTitle     string
	PRBody      string
	Draft       bool
	Labels      []string
	Reviewers   []string
	Files       []FileChange
}

// FileChange is one path-level mutation. Add the path or replace its
// contents (the responder always operates in a "set the file to this"
// mode - incremental diffs are the caller's responsibility).
type FileChange struct {
	Path     string
	Contents []byte
	Delete   bool
}

// Provider is the SCM abstraction. Apply submits the change against
// a remote and returns the PR/MR handle.
type Provider interface {
	Apply(ctx context.Context, req *ChangeRequest) (*PullRequest, error)
	Name() string
}

// ErrConflict is returned when a Provider can't proceed because a
// branch / PR with the same name already exists. The reconciler maps
// this to the configured ConflictBehavior.
var ErrConflict = errors.New("git provider: conflict on existing branch or PR")
