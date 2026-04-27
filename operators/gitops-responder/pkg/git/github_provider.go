// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultGitHubAPI is the public github.com REST endpoint. Override
// for GHES via GitHubProviderOptions.APIBase.
const DefaultGitHubAPI = "https://api.github.com"

// GitHubProviderOptions configures a GitHubProvider. The "GitHub" prefix
// matches the upstream API naming and the other Provider types in this
// package; the revive stutter check is disabled here intentionally.
//
//nolint:revive // GitHub*-prefixed names mirror the upstream API.
type GitHubProviderOptions struct {
	// APIBase is the REST API root. Empty defaults to DefaultGitHubAPI.
	APIBase string

	// Token is a static Bearer credential — typically a fine-grained
	// or classic PAT. Mutually exclusive with AppCreds: at least one
	// of the two must be set.
	Token string

	// AppCreds carries GitHub App credentials (AppID +
	// InstallationID + PrivateKeyPEM). When set, the provider mints a
	// short-lived JWT, exchanges it for an installation access token,
	// and refreshes the token before expiry on every Apply.
	AppCreds *GitHubAppCreds

	// HTTPClient is reused across requests; nil triggers a default
	// 30s-timeout client.
	HTTPClient *http.Client
}

// GitHubProvider opens pull requests on github.com (or a GHES
// install) using the REST API directly. The flow per Apply is:
//
//  1. GET base ref -> base commit SHA
//  2. POST /git/refs to create the feature branch from the base SHA
//  3. PUT  /contents/<path> for every FileChange (commit per file)
//  4. POST /pulls to open the PR
//  5. Optionally label / mark draft / request reviewers (best-effort)
//
// All errors are wrapped so the reconciler can surface them on the
// EventResponse status.
//
//nolint:revive // GitHub*-prefixed names match the upstream API.
type GitHubProvider struct {
	opts   GitHubProviderOptions
	tokens tokenSource
}

// NewGitHubProvider constructs a provider. Exactly one of opts.Token
// or opts.AppCreds must be set. APIBase falls back to DefaultGitHubAPI
// when empty.
func NewGitHubProvider(opts GitHubProviderOptions) (*GitHubProvider, error) {
	hasToken := strings.TrimSpace(opts.Token) != ""
	hasApp := opts.AppCreds != nil
	switch {
	case !hasToken && !hasApp:
		return nil, errors.New("github provider: either Token or AppCreds must be set")
	case hasToken && hasApp:
		return nil, errors.New("github provider: Token and AppCreds are mutually exclusive")
	}
	if opts.APIBase == "" {
		opts.APIBase = DefaultGitHubAPI
	}
	opts.APIBase = strings.TrimRight(opts.APIBase, "/")
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	var tokens tokenSource
	if hasApp {
		ats, err := newAppTokenSource(*opts.AppCreds, opts.APIBase, opts.HTTPClient)
		if err != nil {
			return nil, fmt.Errorf("github app credentials: %w", err)
		}
		tokens = ats
	} else {
		tokens = staticTokenSource{value: opts.Token}
	}
	return &GitHubProvider{opts: opts, tokens: tokens}, nil
}

// Name reports the provider identifier.
func (p *GitHubProvider) Name() string { return "github" }

// Apply runs the full PR-creation flow.
func (p *GitHubProvider) Apply(ctx context.Context, req *ChangeRequest) (*PullRequest, error) {
	if req == nil {
		return nil, errors.New("github provider: nil request")
	}
	if req.Repo.Owner == "" || req.Repo.Repo == "" {
		return nil, errors.New("github provider: repo.owner and repo.repo are required")
	}
	if req.BranchName == "" {
		return nil, errors.New("github provider: branchName is required")
	}
	if len(req.Files) == 0 {
		return nil, errors.New("github provider: at least one file change is required")
	}
	base := req.BaseBranch
	if base == "" {
		base = "main"
	}

	repoPath := fmt.Sprintf("/repos/%s/%s", req.Repo.Owner, req.Repo.Repo)

	// Step 1 — resolve base ref.
	baseSHA, err := p.resolveRef(ctx, repoPath, base)
	if err != nil {
		return nil, fmt.Errorf("resolve base %q: %w", base, err)
	}

	// Step 2 — create the feature branch.
	if cErr := p.createRef(ctx, repoPath, req.BranchName, baseSHA); cErr != nil {
		return nil, fmt.Errorf("create branch %q: %w", req.BranchName, cErr)
	}

	// Step 3 — apply each file via the contents API. We fetch the
	// existing SHA so updates round-trip correctly; missing means a
	// fresh create.
	var lastCommitSHA string
	for i := range req.Files {
		f := req.Files[i]
		sha, putErr := p.putContents(ctx, repoPath, req.BranchName, &f, req.CommitTitle, req.CommitBody)
		if putErr != nil {
			return nil, fmt.Errorf("write %q: %w", f.Path, putErr)
		}
		lastCommitSHA = sha
	}

	// Step 4 — open the PR.
	pr, err := p.openPullRequest(ctx, repoPath, req, base)
	if err != nil {
		return nil, fmt.Errorf("open PR: %w", err)
	}
	pr.CommitSHA = lastCommitSHA

	// Step 5 — best-effort labels / reviewers. Label failures don't
	// invalidate a successful PR.
	if len(req.Labels) > 0 {
		if err := p.addLabels(ctx, repoPath, pr.PRNumber, req.Labels); err != nil {
			pr.URL = pr.URL + " (label-apply failed: " + err.Error() + ")"
		}
	}
	return pr, nil
}

// --- helpers -----------------------------------------------------------------

// resolveRef returns the commit SHA at the tip of refName.
func (p *GitHubProvider) resolveRef(ctx context.Context, repoPath, refName string) (string, error) {
	url := p.opts.APIBase + repoPath + "/git/ref/heads/" + refName
	body, status, err := p.do(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("status %d: %s", status, snippet(body))
	}
	var out struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode ref: %w", err)
	}
	if out.Object.SHA == "" {
		return "", errors.New("empty SHA in ref response")
	}
	return out.Object.SHA, nil
}

// createRef creates a new heads/<branchName> ref pointing at baseSHA.
// A 422 with "Reference already exists" is mapped to ErrConflict.
func (p *GitHubProvider) createRef(ctx context.Context, repoPath, branchName, baseSHA string) error {
	url := p.opts.APIBase + repoPath + "/git/refs"
	payload := map[string]string{
		"ref": "refs/heads/" + branchName,
		"sha": baseSHA,
	}
	body, status, err := p.do(ctx, http.MethodPost, url, payload)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusCreated:
		return nil
	case http.StatusUnprocessableEntity:
		if strings.Contains(string(body), "already exists") {
			return fmt.Errorf("%w: %s", ErrConflict, snippet(body))
		}
	}
	return fmt.Errorf("status %d: %s", status, snippet(body))
}

// putContents creates or updates a single file via the Contents API.
// Returns the resulting commit SHA.
func (p *GitHubProvider) putContents(ctx context.Context, repoPath, branchName string, f *FileChange, commitTitle, commitBody string) (string, error) {
	if f.Delete {
		return p.deleteFile(ctx, repoPath, branchName, f.Path, commitTitle, commitBody)
	}
	// Probe for an existing file SHA on the branch (PUT requires it
	// for updates; for creates GitHub accepts no SHA at all).
	existingSHA := p.tryGetContentSHA(ctx, repoPath, f.Path, branchName)

	url := p.opts.APIBase + repoPath + "/contents/" + f.Path
	commitMessage := commitTitle
	if commitBody != "" {
		commitMessage = commitMessage + "\n\n" + commitBody
	}
	payload := map[string]any{
		"message": commitMessage,
		"content": base64.StdEncoding.EncodeToString(f.Contents),
		"branch":  branchName,
	}
	if existingSHA != "" {
		payload["sha"] = existingSHA
	}
	body, status, err := p.do(ctx, http.MethodPut, url, payload)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return "", fmt.Errorf("status %d: %s", status, snippet(body))
	}
	var out struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode contents response: %w", err)
	}
	return out.Commit.SHA, nil
}

// deleteFile removes a path on the branch via the Contents DELETE API.
func (p *GitHubProvider) deleteFile(ctx context.Context, repoPath, branchName, path, commitTitle, commitBody string) (string, error) {
	existingSHA := p.tryGetContentSHA(ctx, repoPath, path, branchName)
	if existingSHA == "" {
		return "", fmt.Errorf("file %q not found on branch %q (cannot delete)", path, branchName)
	}
	url := p.opts.APIBase + repoPath + "/contents/" + path
	commitMessage := commitTitle
	if commitBody != "" {
		commitMessage = commitMessage + "\n\n" + commitBody
	}
	payload := map[string]any{
		"message": commitMessage,
		"branch":  branchName,
		"sha":     existingSHA,
	}
	body, status, err := p.do(ctx, http.MethodDelete, url, payload)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("status %d: %s", status, snippet(body))
	}
	var out struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode delete response: %w", err)
	}
	return out.Commit.SHA, nil
}

// tryGetContentSHA returns the file SHA on the branch, or "" when
// missing. Errors collapse to "" because PUT will then create the
// file fresh.
func (p *GitHubProvider) tryGetContentSHA(ctx context.Context, repoPath, path, branchName string) string {
	url := p.opts.APIBase + repoPath + "/contents/" + path + "?ref=" + branchName
	body, status, err := p.do(ctx, http.MethodGet, url, nil)
	if err != nil || status != http.StatusOK {
		return ""
	}
	var out struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return ""
	}
	return out.SHA
}

// openPullRequest opens the PR and returns its handle. Drafts are
// honoured when the request opts in.
func (p *GitHubProvider) openPullRequest(ctx context.Context, repoPath string, req *ChangeRequest, base string) (*PullRequest, error) {
	url := p.opts.APIBase + repoPath + "/pulls"
	payload := map[string]any{
		"title": req.PRTitle,
		"head":  req.BranchName,
		"base":  base,
		"body":  req.PRBody,
	}
	if req.Draft {
		payload["draft"] = true
	}
	body, status, err := p.do(ctx, http.MethodPost, url, payload)
	if err != nil {
		return nil, err
	}
	if status != http.StatusCreated {
		return nil, fmt.Errorf("status %d: %s", status, snippet(body))
	}
	var out struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode PR response: %w", err)
	}
	return &PullRequest{
		URL:       out.HTMLURL,
		PRNumber:  out.Number,
		Branch:    req.BranchName,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// addLabels applies labels via the Issues API (PRs are issues on
// GitHub). Best-effort: a 422 is non-fatal.
func (p *GitHubProvider) addLabels(ctx context.Context, repoPath string, prNumber int, labels []string) error {
	url := fmt.Sprintf("%s%s/issues/%d/labels", p.opts.APIBase, repoPath, prNumber)
	payload := map[string]any{"labels": labels}
	body, status, err := p.do(ctx, http.MethodPost, url, payload)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("status %d: %s", status, snippet(body))
	}
	return nil
}

// do is the shared HTTP entry point. It returns the response body and
// HTTP status; transport errors are returned as the third value.
func (p *GitHubProvider) do(ctx context.Context, method, url string, payload any) (body []byte, status int, err error) {
	var reader io.Reader
	if payload != nil {
		buf, mErr := json.Marshal(payload)
		if mErr != nil {
			return nil, 0, fmt.Errorf("marshal payload: %w", mErr)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	bearer, tokErr := p.tokens.Token(ctx)
	if tokErr != nil {
		return nil, 0, fmt.Errorf("acquire bearer token: %w", tokErr)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, doErr := p.opts.HTTPClient.Do(req)
	if doErr != nil {
		return nil, 0, fmt.Errorf("HTTP %s %s: %w", method, url, doErr)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", readErr)
	}
	return respBody, resp.StatusCode, nil
}

// snippet truncates noisy GitHub error bodies for log/error messages.
func snippet(b []byte) string {
	const maxLen = 240
	s := strings.TrimSpace(string(b))
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
