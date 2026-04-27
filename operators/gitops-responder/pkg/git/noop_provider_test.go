// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package git_test

import (
	"context"
	"errors"
	"testing"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/gitops-responder/pkg/git"
)

func sampleRequest(branch string) *git.ChangeRequest {
	return &git.ChangeRequest{
		Repo: securityv1alpha1.GitRepo{
			Provider: "noop", Owner: "ninsun", Repo: "argocd", Branch: "main",
		},
		BranchName:  branch,
		BaseBranch:  "main",
		CommitTitle: "test commit",
		PRTitle:     "test PR",
		Files: []git.FileChange{
			{Path: "policies/test.yaml", Contents: []byte("hello")},
		},
	}
}

func TestNoopProvider_AppliesAndAssignsURL(t *testing.T) {
	p := git.NewNoopProvider()
	pr, err := p.Apply(context.Background(), sampleRequest("ugallu/test/aaa"))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if pr.URL == "" || pr.PRNumber == 0 || pr.CommitSHA == "" {
		t.Fatalf("PR fields missing: %+v", pr)
	}
	if !p.HasBranch("ugallu/test/aaa") {
		t.Error("HasBranch should report true after Apply")
	}
}

func TestNoopProvider_DuplicateBranchReturnsConflict(t *testing.T) {
	p := git.NewNoopProvider()
	_, err := p.Apply(context.Background(), sampleRequest("ugallu/test/dup"))
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	_, err = p.Apply(context.Background(), sampleRequest("ugallu/test/dup"))
	if !errors.Is(err, git.ErrConflict) {
		t.Errorf("expected ErrConflict on duplicate branch, got %v", err)
	}
}

func TestNoopProvider_DeterministicSHA(t *testing.T) {
	a := git.NewNoopProvider()
	b := git.NewNoopProvider()
	pa, _ := a.Apply(context.Background(), sampleRequest("ugallu/branch-a"))
	pb, _ := b.Apply(context.Background(), sampleRequest("ugallu/branch-b"))
	// Same files in both providers => same SHA regardless of branch.
	if pa.CommitSHA != pb.CommitSHA {
		t.Errorf("expected stable SHA for identical file payload, got %q vs %q", pa.CommitSHA, pb.CommitSHA)
	}
}
