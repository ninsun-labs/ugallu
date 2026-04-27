// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package git_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/gitops-responder/pkg/git"
)

// fakeGitHub is a minimal REST mock that exercises the same endpoints
// the provider hits in order. It records every call so tests can
// assert wire-level behaviour.
type fakeGitHub struct {
	srv *httptest.Server

	mu sync.Mutex

	// Recorded interactions, in invocation order.
	calls []fakeCall

	// branchExists toggles whether create-ref returns 422 (conflict).
	branchExists atomic.Bool

	// existingFile populates the contents API on GET (for update-mode
	// PUTs). nil keeps a creation flow.
	existingFile map[string]string // path → sha
}

type fakeCall struct {
	Method string
	Path   string
	Auth   string
	Body   string
}

// init helper.
func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{existingFile: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) record(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeCall{
		Method: r.Method,
		Path:   r.URL.Path,
		Auth:   r.Header.Get("Authorization"),
		Body:   string(body),
	})
	return string(body)
}

func (f *fakeGitHub) handle(w http.ResponseWriter, r *http.Request) {
	body := f.record(r)
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": map[string]string{"sha": "base-sha-aaa"},
		})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
		if f.branchExists.Load() {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message":"Reference already exists"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"ref": "refs/heads/x"})
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
		path := strings.SplitN(r.URL.Path, "/contents/", 2)[1]
		f.mu.Lock()
		sha, ok := f.existingFile[path]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": sha})
	case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
		hadSha := strings.Contains(body, `"sha":`)
		status := http.StatusCreated
		if hadSha {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"commit": map[string]string{"sha": "commit-sha-zzz"},
		})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"number":   42,
			"html_url": "https://github.com/o/r/pull/42",
		})
	default:
		http.NotFound(w, r)
	}
}

func sampleReq(branch string) *git.ChangeRequest {
	return &git.ChangeRequest{
		Repo: securityv1alpha1.GitRepo{
			Provider: "github", Owner: "o", Repo: "r", Branch: "main",
		},
		BranchName:  branch,
		BaseBranch:  "main",
		CommitTitle: "ugallu: test commit",
		PRTitle:     "test PR",
		PRBody:      "Triggered by SE smoke",
		Files: []git.FileChange{
			{Path: "policies/test.yaml", Contents: []byte("kind: Test\n")},
		},
	}
}

func TestGitHubProvider_HappyPath(t *testing.T) {
	f := newFakeGitHub(t)
	p, err := git.NewGitHubProvider(git.GitHubProviderOptions{
		APIBase: f.srv.URL,
		Token:   "ghp_test",
	})
	if err != nil {
		t.Fatalf("NewGitHubProvider: %v", err)
	}
	pr, err := p.Apply(context.Background(), sampleReq("ugallu/test/aaa"))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if pr.PRNumber != 42 || pr.URL != "https://github.com/o/r/pull/42" {
		t.Errorf("PR mismatch: %+v", pr)
	}
	if pr.CommitSHA != "commit-sha-zzz" {
		t.Errorf("CommitSHA = %q, want commit-sha-zzz", pr.CommitSHA)
	}
	// Wire ordering: ref-resolve, ref-create, contents-GET (probe),
	// contents-PUT, pull-create.
	gotMethods := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		gotMethods = append(gotMethods, c.Method+" "+c.Path)
	}
	want := []string{
		"GET /repos/o/r/git/ref/heads/main",
		"POST /repos/o/r/git/refs",
		"GET /repos/o/r/contents/policies/test.yaml",
		"PUT /repos/o/r/contents/policies/test.yaml",
		"POST /repos/o/r/pulls",
	}
	if len(gotMethods) != len(want) {
		t.Fatalf("call sequence length = %d, want %d (%v)", len(gotMethods), len(want), gotMethods)
	}
	for i, w := range want {
		if gotMethods[i] != w {
			t.Errorf("call[%d] = %q, want %q", i, gotMethods[i], w)
		}
	}
	for _, c := range f.calls {
		if c.Auth != "Bearer ghp_test" {
			t.Errorf("auth header missing/incorrect on %s %s: %q", c.Method, c.Path, c.Auth)
		}
	}
}

func TestGitHubProvider_BranchExistsReturnsConflict(t *testing.T) {
	f := newFakeGitHub(t)
	f.branchExists.Store(true)
	p, _ := git.NewGitHubProvider(git.GitHubProviderOptions{APIBase: f.srv.URL, Token: "ghp_x"})
	if _, err := p.Apply(context.Background(), sampleReq("dup-branch")); !errors.Is(err, git.ErrConflict) {
		t.Errorf("expected ErrConflict, got %v", err)
	}
}

func TestGitHubProvider_UpdateExistingFile(t *testing.T) {
	f := newFakeGitHub(t)
	f.existingFile["policies/test.yaml"] = "existing-blob-sha"
	p, _ := git.NewGitHubProvider(git.GitHubProviderOptions{APIBase: f.srv.URL, Token: "ghp_x"})
	if _, err := p.Apply(context.Background(), sampleReq("update-branch")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Find the PUT and confirm it carried the existing SHA.
	var put *fakeCall
	for i := range f.calls {
		if f.calls[i].Method == http.MethodPut {
			put = &f.calls[i]
			break
		}
	}
	if put == nil {
		t.Fatal("no PUT recorded")
	}
	if !strings.Contains(put.Body, `"sha":"existing-blob-sha"`) {
		t.Errorf("PUT did not include existing sha: %s", put.Body)
	}
}

func TestGitHubProvider_RejectsBadOptions(t *testing.T) {
	if _, err := git.NewGitHubProvider(git.GitHubProviderOptions{}); err == nil {
		t.Error("expected error when token is empty")
	}
}

func TestGitHubProvider_RequiresFileChanges(t *testing.T) {
	p, _ := git.NewGitHubProvider(git.GitHubProviderOptions{APIBase: "http://x", Token: "y"})
	req := sampleReq("b")
	req.Files = nil
	if _, err := p.Apply(context.Background(), req); err == nil {
		t.Error("expected error when Files is empty")
	}
}
