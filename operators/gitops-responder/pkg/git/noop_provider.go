// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// NoopProvider records ChangeRequests in memory and synthesises a fake
// PR handle. Used in dev clusters where the operator is wired up but
// real git plumbing isn't yet available, and as a deterministic test
// double for the reconciler.
//
// The provider deliberately panics on a duplicate branch name so the
// reconciler exercises the same conflict path it would hit against a
// real SCM.
type NoopProvider struct {
	mu       sync.Mutex
	prCount  int
	branches map[string]struct{}
	History  []*PullRequest
}

// NewNoopProvider returns a fresh provider.
func NewNoopProvider() *NoopProvider {
	return &NoopProvider{branches: map[string]struct{}{}}
}

// Name reports the provider identifier baked into Apply outputs.
func (p *NoopProvider) Name() string { return "noop" }

// Apply pretends to push the requested change and create a PR. The
// returned URL is a stable placeholder so test assertions can pin it.
func (p *NoopProvider) Apply(_ context.Context, req *ChangeRequest) (*PullRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("noop provider: nil request")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, dup := p.branches[req.BranchName]; dup {
		return nil, fmt.Errorf("%w: branch %q", ErrConflict, req.BranchName)
	}
	p.branches[req.BranchName] = struct{}{}
	p.prCount++

	// Synthesize a deterministic commit SHA over the file payload so
	// downstream consumers (tests, dev dashboards) see a stable hash
	// for a given (path, content) tuple.
	h := sha256.New()
	for _, f := range req.Files {
		h.Write([]byte(f.Path))
		h.Write([]byte{0})
		if !f.Delete {
			h.Write(f.Contents)
		}
	}
	pr := &PullRequest{
		URL:       fmt.Sprintf("noop://%s/%s/%s/pull/%d", req.Repo.Provider, req.Repo.Owner, req.Repo.Repo, p.prCount),
		PRNumber:  p.prCount,
		Branch:    req.BranchName,
		CommitSHA: hex.EncodeToString(h.Sum(nil)),
		CreatedAt: time.Now().UTC(),
	}
	p.History = append(p.History, pr)
	return pr, nil
}

// HasBranch reports whether a previous Apply registered branchName.
// Used by tests to assert reconciler behaviour without inspecting
// History directly.
func (p *NoopProvider) HasBranch(branchName string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.branches[branchName]
	return ok
}
