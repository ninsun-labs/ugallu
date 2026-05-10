// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package server wires the ugallu BFF HTTP surface: OIDC + PKCE
// auth, cookie-based sessions, and a small read-only REST API
// against the security.ugallu.io group.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Options carries the dependencies needed to build a Server.
type Options struct {
	Logger        *slog.Logger
	K8sClient     client.Client
	K8sRESTConfig *rest.Config
	// OIDCConfig / OIDCVerifier / CookieSecret are unused when
	// AuthDisabled is true.
	OIDCConfig   *oauth2.Config
	OIDCVerifier *oidc.IDTokenVerifier
	CookieSecret []byte
	CookieDomain string
	Impersonate  bool
	Version      string
	// AuthDisabled bypasses OIDC entirely. Every /api/v1 request is
	// served as a synthetic "lab-user". Lab/dev only.
	AuthDisabled bool
}

// Server holds the wired-up handler tree.
type Server struct {
	opts Options
	auth *Auth
}

// New constructs a Server from validated Options. The Options
// value is large (multiple slog/oauth/oidc handles); take a
// pointer to keep the call site cheap and to satisfy
// gocritic's hugeParam check.
func New(opts *Options) (*Server, error) {
	var auth *Auth
	if opts.AuthDisabled {
		auth = &Auth{disabled: true, log: opts.Logger}
	} else {
		a, err := newAuth(opts.OIDCConfig, opts.OIDCVerifier, opts.CookieSecret, opts.CookieDomain, opts.Logger)
		if err != nil {
			return nil, err
		}
		auth = a
	}
	return &Server{opts: *opts, auth: auth}, nil
}

// Handler returns the public http.Handler with all routes mounted.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.Handle("GET /auth/login", http.HandlerFunc(s.auth.Login))
	mux.Handle("GET /auth/callback", http.HandlerFunc(s.auth.Callback))
	mux.Handle("POST /auth/logout", http.HandlerFunc(s.auth.Logout))

	api := http.NewServeMux()
	api.HandleFunc("GET /me", s.handleMe)
	api.HandleFunc("GET /events", s.handleEventsList)
	api.HandleFunc("GET /events/{name}", s.handleEventGet)
	api.HandleFunc("GET /runs", s.handleRunsList)
	api.HandleFunc("GET /runs/{kind}/{namespace}/{name}", s.handleRunGet)
	api.HandleFunc("GET /configurations", s.handleConfigurationsList)
	api.HandleFunc("GET /configurations/{kind}/{namespace}/{name}", s.handleConfigurationGet)
	api.HandleFunc("GET /configurations/{kind}/{name}", s.handleConfigurationGet)

	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", s.auth.Middleware(api)))

	return loggingMiddleware(s.opts.Logger, securityHeadersMiddleware(mux))
}

// writeJSON encodes body to w with the given status. JSON errors at
// this point indicate a programmer mistake; logged and ignored.
func (s *Server) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.opts.Logger.Warn("write json", "err", err)
	}
}

// writeError writes a structured error envelope.
func (s *Server) writeError(w http.ResponseWriter, status int, code, msg string) {
	s.writeJSON(w, status, map[string]any{
		"code":    code,
		"message": msg,
		"ts":      time.Now().UTC().Format(time.RFC3339),
	})
}
