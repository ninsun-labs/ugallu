// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	cookieSession = "ugallu_session"
	cookieState   = "ugallu_oidc_state"
	sessionTTL    = 8 * time.Hour
	stateTTL      = 5 * time.Minute
)

type ctxKey int

const userCtxKey ctxKey = 0

// Session is the authenticated user record carried by the cookie.
// All fields come from the OIDC id_token claims; nothing here is
// trusted enough to be a security boundary on its own - apiserver
// RBAC is the real authorisation gate.
type Session struct {
	Sub    string   `json:"sub"`
	Email  string   `json:"email,omitempty"`
	Name   string   `json:"name,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Exp    int64    `json:"exp"`
}

// Auth wraps the OIDC + PKCE flow and the cookie-based session.
// When `disabled` is true every middleware call short-circuits to
// a synthetic lab-user; the OIDC + cookie fields are unused.
type Auth struct {
	disabled     bool
	oauth2       *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	cookieSecret []byte
	cookieDomain string
	log          *slog.Logger
}

// labSession is the synthetic Session injected when --auth-disabled
// is set. The display fields make it obvious in /me payloads that
// the BFF is running un-authenticated.
var labSession = Session{
	Sub:    "lab-user",
	Email:  "lab@ugallu.local",
	Name:   "lab user (auth disabled)",
	Groups: []string{"ugallu:lab"},
}

func newAuth(cfg *oauth2.Config, verifier *oidc.IDTokenVerifier, secret []byte, domain string, log *slog.Logger) (*Auth, error) {
	if cfg == nil || verifier == nil {
		return nil, errors.New("auth: oauth2 config and verifier required")
	}
	if len(secret) < 32 {
		return nil, errors.New("auth: cookie secret must be >=32 bytes")
	}
	return &Auth{oauth2: cfg, verifier: verifier, cookieSecret: secret, cookieDomain: domain, log: log}, nil
}

type statePayload struct {
	State        string `json:"state"`
	CodeVerifier string `json:"cv"`
	ReturnTo     string `json:"return_to"`
	Exp          int64  `json:"exp"`
}

// Login starts the auth-code + PKCE flow and redirects to the IdP.
// In auth-disabled mode it just bounces back to the SPA root.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	if a.disabled {
		returnTo := r.URL.Query().Get("return_to")
		if !isSafeReturnTo(returnTo) {
			returnTo = "/"
		}
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}
	state := randString(24)
	verifier := randString(64) // PKCE code_verifier (43..128 chars)
	challenge := pkceChallenge(verifier)

	returnTo := r.URL.Query().Get("return_to")
	if !isSafeReturnTo(returnTo) {
		returnTo = "/"
	}

	a.setSignedCookie(w, cookieState, statePayload{
		State:        state,
		CodeVerifier: verifier,
		ReturnTo:     returnTo,
		Exp:          time.Now().Add(stateTTL).Unix(),
	}, stateTTL)

	url := a.oauth2.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

// Callback exchanges the auth code for an id_token and sets the
// session cookie. No-op in auth-disabled mode.
func (a *Auth) Callback(w http.ResponseWriter, r *http.Request) {
	if a.disabled {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	var sp statePayload
	if err := a.readSignedCookie(r, cookieState, &sp); err != nil {
		http.Error(w, "invalid state cookie", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != sp.State {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	tok, err := a.oauth2.Exchange(r.Context(), code,
		oauth2.SetAuthURLParam("code_verifier", sp.CodeVerifier),
	)
	if err != nil {
		a.log.Warn("token exchange failed", "err", err)
		http.Error(w, "token exchange failed", http.StatusUnauthorized)
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		http.Error(w, "missing id_token", http.StatusUnauthorized)
		return
	}
	idTok, err := a.verifier.Verify(r.Context(), rawID)
	if err != nil {
		a.log.Warn("id_token verify failed", "err", err)
		http.Error(w, "invalid id_token", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Sub               string   `json:"sub"`
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := idTok.Claims(&claims); err != nil {
		http.Error(w, "claims unmarshal", http.StatusInternalServerError)
		return
	}
	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}

	a.setSignedCookie(w, cookieSession, Session{
		Sub:    claims.Sub,
		Email:  claims.Email,
		Name:   name,
		Groups: claims.Groups,
		Exp:    time.Now().Add(sessionTTL).Unix(),
	}, sessionTTL)
	a.clearCookie(w, cookieState)

	http.Redirect(w, r, sp.ReturnTo, http.StatusFound)
}

// Logout clears the session cookie.
func (a *Auth) Logout(w http.ResponseWriter, _ *http.Request) {
	a.clearCookie(w, cookieSession)
	w.WriteHeader(http.StatusNoContent)
}

// Middleware verifies the session cookie and injects the Session
// into the request context. Endpoints under /api/v1/ are mounted
// behind it. When the Auth was constructed with disabled=true
// every request is accepted with a synthetic lab Session.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.disabled {
			sess := labSession
			sess.Exp = time.Now().Add(sessionTTL).Unix()
			ctx := context.WithValue(r.Context(), userCtxKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		var sess Session
		if err := a.readSignedCookie(r, cookieSession, &sess); err != nil {
			a.unauthenticated(w, r)
			return
		}
		if time.Now().Unix() > sess.Exp {
			a.clearCookie(w, cookieSession)
			a.unauthenticated(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Auth) unauthenticated(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":     "unauthenticated",
		"loginURL": "/auth/login?return_to=" + r.URL.Path,
	})
}

// SessionFromContext returns the user from the request context.
// Callers MUST be inside a handler mounted behind Middleware.
func SessionFromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(userCtxKey).(Session)
	return s, ok
}

func (a *Auth) setSignedCookie(w http.ResponseWriter, name string, payload any, ttl time.Duration) {
	raw, _ := json.Marshal(payload)
	sig := hmacSign(a.cookieSecret, raw)
	val := base64.URLEncoding.EncodeToString(raw) + "." + sig
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    val,
		Path:     "/",
		Domain:   a.cookieDomain,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) readSignedCookie(r *http.Request, name string, out any) error {
	c, err := r.Cookie(name)
	if err != nil {
		return err
	}
	dot := strings.LastIndexByte(c.Value, '.')
	if dot < 0 {
		return errors.New("malformed cookie")
	}
	raw, err := base64.URLEncoding.DecodeString(c.Value[:dot])
	if err != nil {
		return fmt.Errorf("cookie body decode: %w", err)
	}
	expected := hmacSign(a.cookieSecret, raw)
	if !hmac.Equal([]byte(c.Value[dot+1:]), []byte(expected)) {
		return errors.New("cookie signature mismatch")
	}
	return json.Unmarshal(raw, out)
}

func (a *Auth) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   a.cookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func hmacSign(secret, msg []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write(msg)
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

func pkceChallenge(verifier string) string {
	s := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func randString(n int) string {
	// generate enough bytes that the base64 encoding is at least n
	// chars, then trim - safer than computing exact byte counts.
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	enc := base64.RawURLEncoding.EncodeToString(b)
	if len(enc) > n {
		return enc[:n]
	}
	return enc
}

// isSafeReturnTo blocks open-redirect tricks: only same-origin paths
// (starting with "/") are accepted.
func isSafeReturnTo(p string) bool {
	if p == "" {
		return false
	}
	if !strings.HasPrefix(p, "/") {
		return false
	}
	if strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return false
	}
	return true
}
