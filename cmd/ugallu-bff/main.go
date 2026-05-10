// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-bff is the Backend-for-Frontend that powers the
// ugallu UI. It terminates the OIDC + PKCE flow against an external
// IdP (Keycloak in the reference deployment), holds a signed
// session cookie, and proxies a small read-only REST surface against
// the cluster's `security.ugallu.io` CRDs.
//
// The browser SPA never holds a Kubernetes token; every apiserver
// call is made by the BFF's ServiceAccount, with the human's OIDC
// subject carried in an `Impersonate-User` header so audit retains
// the actor identity. RBAC denies every verb other than
// get/list/watch on the security.ugallu.io group, so the BFF
// cannot proxy mutations.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/cmd/ugallu-bff/pkg/server"
)

const version = "v0.0.1-alpha.1"

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listenAddr      string
		oidcIssuer      string
		oidcClientID    string
		clientSecretEnv string
		cookieSecretEnv string
		cookieDomain    string
		externalURL     string
		impersonate     bool
		authDisabled    bool
	)
	flag.StringVar(&listenAddr, "listen", ":8080", "HTTP listen address")
	flag.StringVar(&oidcIssuer, "oidc-issuer", "", "OIDC issuer URL (required unless --auth-disabled)")
	flag.StringVar(&oidcClientID, "oidc-client-id", "ugallu-ui", "OIDC client_id")
	flag.StringVar(&clientSecretEnv, "oidc-client-secret-env", "OIDC_CLIENT_SECRET",
		"Env var holding the OIDC client secret")
	flag.StringVar(&cookieSecretEnv, "cookie-secret-env", "COOKIE_SECRET",
		"Env var holding the >=32-byte cookie HMAC secret")
	flag.StringVar(&cookieDomain, "cookie-domain", "",
		"Cookie Domain attribute (empty = host-only)")
	flag.StringVar(&externalURL, "external-url", "",
		"Public URL where the SPA is reachable, used for the OIDC redirect (required unless --auth-disabled)")
	flag.BoolVar(&impersonate, "impersonate", true,
		"Set Impersonate-User on apiserver calls so audit retains the human actor")
	flag.BoolVar(&authDisabled, "auth-disabled", false,
		"DEV/LAB ONLY: skip OIDC entirely. Every API call is accepted as a synthetic 'lab-user'. "+
			"Apiserver impersonation is also disabled. NEVER set in production.")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("get k8s config: %w", err)
	}
	cli, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("k8s client: %w", err)
	}

	opts := server.Options{
		Logger:        log,
		K8sClient:     cli,
		K8sRESTConfig: cfg,
		Impersonate:   impersonate,
		Version:       version,
		AuthDisabled:  authDisabled,
	}

	if authDisabled {
		log.Warn("AUTH DISABLED",
			"hint", "every API call is accepted as a synthetic lab-user; apiserver impersonation is also disabled.",
			"do_not_use_in", "production")
		// Apiserver impersonation requires a stable subject; we don't
		// have one when auth is bypassed.
		opts.Impersonate = false
	} else {
		if oidcIssuer == "" {
			return errors.New("--oidc-issuer is required (or pass --auth-disabled for lab/dev)")
		}
		if externalURL == "" {
			return errors.New("--external-url is required (or pass --auth-disabled for lab/dev)")
		}

		clientSecret := os.Getenv(clientSecretEnv)
		if clientSecret == "" {
			return fmt.Errorf("env %s is empty", clientSecretEnv)
		}
		cookieSecret := os.Getenv(cookieSecretEnv)
		if len(cookieSecret) < 32 {
			return fmt.Errorf("env %s must be at least 32 bytes (got %d)", cookieSecretEnv, len(cookieSecret))
		}

		provider, err := oidc.NewProvider(ctx, oidcIssuer)
		if err != nil {
			return fmt.Errorf("oidc provider %q: %w", oidcIssuer, err)
		}
		verifier := provider.Verifier(&oidc.Config{ClientID: oidcClientID})
		opts.OIDCConfig = &oauth2.Config{
			ClientID:     oidcClientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  externalURL + "/auth/callback",
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		}
		opts.OIDCVerifier = verifier
		opts.CookieSecret = []byte(cookieSecret)
		opts.CookieDomain = cookieDomain
	}

	srv, err := server.New(opts)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}

	httpSrv := &http.Server{
		Addr:              listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Info("ugallu-bff up", "version", version, "listen", listenAddr,
		"issuer", oidcIssuer, "impersonate", impersonate)

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}
