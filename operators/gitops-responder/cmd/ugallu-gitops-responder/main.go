// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-gitops-responder is the leader-elected operator that
// turns GitOpsChange EventResponses into pull / merge requests on a
// remote SCM. Real GitHub / GitLab integration lands in a follow-up
// commit; this build ships with the noop provider so e2e wiring (CRD
// + RBAC + sync-wave + reconcile loop) is exercised end to end.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/gitops-responder/pkg/controller"
	"github.com/ninsun-labs/ugallu/operators/gitops-responder/pkg/git"
	"github.com/ninsun-labs/ugallu/operators/gitops-responder/pkg/router"
)

const version = "v0.0.1-alpha.1"

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
}

func main() {
	if err := runMain(); err != nil {
		ctrl.Log.Error(err, "fatal")
		os.Exit(1)
	}
}

func runMain() error {
	var (
		metricsAddr      string
		probeAddr        string
		leaderElectionNS string
		configNamespace  string
		maxAttempts      int
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "ugallu-system", "Leader election Lease namespace")
	flag.StringVar(&configNamespace, "config-namespace", "ugallu-system", "Namespace of the GitOpsResponderConfig singleton")
	flag.IntVar(&maxAttempts, "max-attempts", 0, "Override spec.retryPolicy.maxAttempts (0 = honour CR)")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log := ctrl.Log.WithName("ugallu-gitops-responder")
	log.Info("starting", "version", version)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          true,
		LeaderElectionID:        "ugallu-gitops-responder-leader",
		LeaderElectionNamespace: leaderElectionNS,
	})
	if err != nil {
		return fmt.Errorf("manager creation: %w", err)
	}
	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("healthz: %w", err)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("readyz: %w", err)
	}

	// Boot-time GitOpsResponderConfig load. A future iteration will
	// add a Watch reconciler so config edits propagate without a
	// restart; for now we read once at startup.
	bootClient, err := client.New(mgr.GetConfig(), client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("bootstrap client: %w", err)
	}
	cfg, err := loadConfig(context.Background(), bootClient, configNamespace)
	if err != nil {
		return fmt.Errorf("load GitOpsResponderConfig: %w", err)
	}

	routes := router.NewSnapshot()
	if cfg != nil {
		r, rerr := router.New(cfg)
		if rerr != nil {
			return fmt.Errorf("compile router: %w", rerr)
		}
		routes.Set(r)
		log.Info("router ready", "rules", len(cfg.Routing), "defaultProvider", cfg.DefaultProvider)
	} else {
		log.Info("GitOpsResponderConfig not found; reconciler will requeue until configured")
	}

	providers := map[string]git.Provider{
		"noop": git.NewNoopProvider(),
	}
	if cfg != nil {
		for i := range cfg.Providers {
			gp := cfg.Providers[i]
			if gp.Type == "github" {
				token, terr := loadProviderToken(context.Background(), bootClient, configNamespace, gp.Auth.SecretRef.Name)
				if terr != nil {
					log.Info("github provider: token load failed; provider not registered", "name", gp.Name, "error", terr.Error())
					continue
				}
				apiBase := ""
				if gp.Host != "" && gp.Host != "github.com" {
					apiBase = "https://" + gp.Host + "/api/v3"
				}
				ghp, gerr := git.NewGitHubProvider(git.GitHubProviderOptions{
					APIBase: apiBase,
					Token:   token,
				})
				if gerr != nil {
					log.Info("github provider: construction failed", "name", gp.Name, "error", gerr.Error())
					continue
				}
				providers[gp.Name] = ghp
				log.Info("github provider registered", "name", gp.Name, "host", gp.Host)
			}
		}
	}

	if err = (&controller.EventResponseReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		Routes:      routes,
		Providers:   providers,
		MaxAttempts: maxAttempts,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup EventResponseReconciler: %w", err)
	}

	log.Info("running manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}

// loadProviderToken pulls the bearer token out of the Secret named in
// GitProviderConfig.auth.secretRef. The expected key is "token"
// (a fine-grained PAT, classic PAT, or GitHub App installation token);
// fallbacks to "github-token" for compatibility with the secrets
// shipped by some bootstrap charts.
func loadProviderToken(ctx context.Context, c client.Client, namespace, secretName string) (string, error) {
	if secretName == "" {
		return "", fmt.Errorf("auth.secretRef.name is empty")
	}
	sec := &corev1.Secret{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, sec); err != nil {
		return "", fmt.Errorf("get secret %s/%s: %w", namespace, secretName, err)
	}
	for _, key := range []string{"token", "github-token", "GITHUB_TOKEN"} {
		if v, ok := sec.Data[key]; ok && len(v) > 0 {
			return strings.TrimSpace(string(v)), nil
		}
	}
	return "", fmt.Errorf("secret %s/%s has no token / github-token / GITHUB_TOKEN key", namespace, secretName)
}

// loadConfig fetches the GitOpsResponderConfig singleton, preferring
// name="default" when multiple exist. Missing CR returns (nil, nil)
// so the operator can come up and wait for one to be created.
func loadConfig(ctx context.Context, c client.Client, namespace string) (*securityv1alpha1.GitOpsResponderConfigSpec, error) {
	list := &securityv1alpha1.GitOpsResponderConfigList{}
	if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, nil
	}
	for i := range list.Items {
		if list.Items[i].Name == "default" {
			return &list.Items[i].Spec, nil
		}
	}
	return &list.Items[0].Spec, nil
}
