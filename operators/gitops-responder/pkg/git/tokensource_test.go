// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package git_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ninsun-labs/ugallu/operators/gitops-responder/pkg/git"
)

// genTestKey returns a fresh RSA-2048 keypair encoded as PKCS#1 PEM.
func genTestKey(t *testing.T) (key *rsa.PrivateKey, pemBytes []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	return k, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

// fakeAppAPI is an httptest server that mimics the
// /app/installations/<id>/access_tokens endpoint. It records the JWT
// it receives so tests can assert claims/signature.
type fakeAppAPI struct {
	srv          *httptest.Server
	publicKey    *rsa.PublicKey
	expectedApp  string
	expectedInst string
	calls        atomic.Int32
	tokenValue   string
	tokenTTL     time.Duration
}

func newFakeAppAPI(t *testing.T, pub *rsa.PublicKey, appID, instID, tokenValue string, ttl time.Duration) *fakeAppAPI {
	t.Helper()
	f := &fakeAppAPI{
		publicKey:    pub,
		expectedApp:  appID,
		expectedInst: instID,
		tokenValue:   tokenValue,
		tokenTTL:     ttl,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAppAPI) handle(w http.ResponseWriter, r *http.Request) {
	expectedPath := "/app/installations/" + f.expectedInst + "/access_tokens"
	if r.URL.Path != expectedPath || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	f.calls.Add(1)

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "missing Bearer", http.StatusUnauthorized)
		return
	}
	jwtRaw := strings.TrimPrefix(auth, "Bearer ")
	tok, err := jwt.Parse(jwtRaw, func(_ *jwt.Token) (any, error) { return f.publicKey, nil })
	if err != nil || !tok.Valid {
		http.Error(w, "invalid JWT: "+err.Error(), http.StatusUnauthorized)
		return
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "unexpected claims", http.StatusBadRequest)
		return
	}
	if iss, _ := claims["iss"].(string); iss != f.expectedApp {
		http.Error(w, "wrong iss", http.StatusBadRequest)
		return
	}
	exp := time.Now().Add(f.tokenTTL).UTC()
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":      f.tokenValue,
		"expires_at": exp.Format(time.RFC3339),
	})
}

// TestGitHubProvider_AppAuthFlow exercises the App-mode token
// exchange end to end. It also verifies that subsequent calls reuse
// the cached token (no second exchange).
func TestGitHubProvider_AppAuthFlow(t *testing.T) {
	key, pemBytes := genTestKey(t)
	appAPI := newFakeAppAPI(t, &key.PublicKey, "12345", "67890", "ghs_test_install_token", time.Hour)

	// The data-plane fake REST endpoints are needed too. Both are
	// tied into the same httptest server by routing on path:
	// app-token endpoints stay on appAPI.srv, the data-plane
	// endpoints use a sibling fakeGitHub-like minimal handler so an
	// Apply can complete end to end.
	dataAPI := newDataPlaneFake(t, "ghs_test_install_token")

	// Compose: appAPI on /app/...; dataAPI on /repos/...
	mux := http.NewServeMux()
	mux.Handle("/app/", appAPI.srv.Config.Handler)
	mux.Handle("/repos/", dataAPI)
	merged := httptest.NewServer(mux)
	t.Cleanup(merged.Close)

	p, err := git.NewGitHubProvider(git.GitHubProviderOptions{
		APIBase: merged.URL,
		AppCreds: &git.GitHubAppCreds{
			AppID:          "12345",
			InstallationID: "67890",
			PrivateKeyPEM:  pemBytes,
		},
	})
	if err != nil {
		t.Fatalf("NewGitHubProvider: %v", err)
	}

	pr, err := p.Apply(context.Background(), &git.ChangeRequest{
		Repo:        securityv1alpha1.GitRepo{Provider: "github", Owner: "o", Repo: "r", Branch: "main"},
		BranchName:  "ugallu/app-test",
		BaseBranch:  "main",
		CommitTitle: "test",
		PRTitle:     "test PR",
		Files:       []git.FileChange{{Path: "f.yaml", Contents: []byte("k: v\n")}},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if pr.PRNumber != 1 {
		t.Errorf("PR number = %d, want 1", pr.PRNumber)
	}
	if got := appAPI.calls.Load(); got != 1 {
		t.Errorf("app-token exchange calls = %d, want 1 (token must be cached after first Apply)", got)
	}
	// Second Apply: token cache must hold; no extra exchange.
	_, err = p.Apply(context.Background(), &git.ChangeRequest{
		Repo:        securityv1alpha1.GitRepo{Provider: "github", Owner: "o", Repo: "r", Branch: "main"},
		BranchName:  "ugallu/app-test-2",
		BaseBranch:  "main",
		CommitTitle: "test",
		PRTitle:     "test PR 2",
		Files:       []git.FileChange{{Path: "g.yaml", Contents: []byte("k: v\n")}},
	})
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if got := appAPI.calls.Load(); got != 1 {
		t.Errorf("app-token exchange calls after second Apply = %d, want still 1", got)
	}
}

// TestGitHubProvider_AppAuth_RefreshesNearExpiry exercises the
// refresh path: a token whose expiry is inside the leadTime window
// triggers a fresh exchange on the next Token() call.
func TestGitHubProvider_AppAuth_RefreshesNearExpiry(t *testing.T) {
	key, pemBytes := genTestKey(t)
	// Tiny TTL: well below the 5-min leadTime so the source refreshes
	// every call.
	appAPI := newFakeAppAPI(t, &key.PublicKey, "12345", "67890", "ghs_short", 1*time.Second)
	dataAPI := newDataPlaneFake(t, "ghs_short")

	mux := http.NewServeMux()
	mux.Handle("/app/", appAPI.srv.Config.Handler)
	mux.Handle("/repos/", dataAPI)
	merged := httptest.NewServer(mux)
	t.Cleanup(merged.Close)

	p, err := git.NewGitHubProvider(git.GitHubProviderOptions{
		APIBase: merged.URL,
		AppCreds: &git.GitHubAppCreds{
			AppID:          "12345",
			InstallationID: "67890",
			PrivateKeyPEM:  pemBytes,
		},
	})
	if err != nil {
		t.Fatalf("NewGitHubProvider: %v", err)
	}
	for i := 0; i < 3; i++ {
		_, err := p.Apply(context.Background(), &git.ChangeRequest{
			Repo:        securityv1alpha1.GitRepo{Provider: "github", Owner: "o", Repo: "r", Branch: "main"},
			BranchName:  "ugallu/refresh-" + string(rune('a'+i)),
			BaseBranch:  "main",
			CommitTitle: "test",
			PRTitle:     "t",
			Files:       []git.FileChange{{Path: "f.yaml", Contents: []byte("k: v\n")}},
		})
		if err != nil {
			t.Fatalf("Apply #%d: %v", i, err)
		}
	}
	// 3 applies, each within the leadTime window → 3 exchanges.
	if got := appAPI.calls.Load(); got < 3 {
		t.Errorf("app-token exchange calls = %d, want >= 3", got)
	}
}

func TestGitHubProvider_RejectsBothTokenAndApp(t *testing.T) {
	_, pemBytes := genTestKey(t)
	if _, err := git.NewGitHubProvider(git.GitHubProviderOptions{
		Token: "ghp_x",
		AppCreds: &git.GitHubAppCreds{
			AppID:          "1",
			InstallationID: "2",
			PrivateKeyPEM:  pemBytes,
		},
	}); err == nil {
		t.Error("expected error when both Token and AppCreds are set")
	}
}

func TestGitHubProvider_RejectsNeitherTokenNorApp(t *testing.T) {
	if _, err := git.NewGitHubProvider(git.GitHubProviderOptions{}); err == nil {
		t.Error("expected error when neither Token nor AppCreds are set")
	}
}

// newDataPlaneFake is a stripped-down GitHub data-plane mock: just
// enough to satisfy a single Apply (resolve base, create branch, put
// contents, open PR). It refuses requests whose Bearer mismatches.
func newDataPlaneFake(_ *testing.T, expectedToken string) http.Handler {
	branches := map[string]bool{}
	prCount := 0
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+expectedToken {
			http.Error(w, "wrong token "+auth, http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object": map[string]string{"sha": "base"},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"ref": "x"})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"commit": map[string]string{"sha": "c"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			prCount++
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"number":   prCount,
				"html_url": "https://github.com/o/r/pull/1",
			})
		default:
			http.NotFound(w, r)
		}
		_ = branches
	})
}
