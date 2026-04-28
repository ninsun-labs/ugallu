// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-audit-detection is the audit-detection operator. It
// boots a controller-runtime manager that watches SigmaRule CRDs and
// runs an Engine that consumes one of two audit-event sources:
//
//   - file backend: tails the kubelet/apiserver audit-log file
//     (DaemonSet, design 20 §A2 Phase 1)
//   - webhook backend: HTTPS endpoint that the apiserver POSTs batched
//     audit events to (Deployment, design 20 §A2 Phase 2)
//
// The source choice is a single --source flag.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"

	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection"
	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection/bus"
	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection/engine"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
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
		metricsAddr         string
		probeAddr           string
		leaderElectionNS    string
		clusterID           string
		sourceKind          string
		auditLogPath        string
		webhookListenAddr   string
		webhookPath         string
		webhookCertFile     string
		webhookKeyFile      string
		webhookClientCAFile string
		webhookSecretEnv    string
		configName          string
		busTokenEnv         string
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "ugallu-system", "Leader election Lease namespace")
	flag.StringVar(&clusterID, "cluster-id", "", "ClusterIdentity.ClusterID stamped on emitted SecurityEvents")
	flag.StringVar(&sourceKind, "source", "file", `Audit-event source: "file" (DaemonSet, kubelet/apiserver log) or "webhook" (Deployment, apiserver audit-webhook backend)`)
	flag.StringVar(&auditLogPath, "audit-log-path", auditdetection.DefaultAuditLogPath, "Audit-log file path (file source)")
	flag.StringVar(&webhookListenAddr, "webhook-listen", auditdetection.DefaultWebhookListenAddr, "Webhook listen address")
	flag.StringVar(&webhookPath, "webhook-path", auditdetection.DefaultWebhookPath, "Webhook URL path")
	flag.StringVar(&webhookCertFile, "webhook-cert", "", "TLS cert file (webhook source)")
	flag.StringVar(&webhookKeyFile, "webhook-key", "", "TLS key file (webhook source)")
	flag.StringVar(&webhookClientCAFile, "webhook-client-ca", "", "Client CA bundle for mTLS (webhook source)")
	flag.StringVar(&webhookSecretEnv, "webhook-secret-env", "AUDIT_WEBHOOK_TOKEN", "Env var name carrying the bearer-token shared secret (webhook source)")
	flag.StringVar(&configName, "config-name", "default", "AuditDetectionConfig CR name (cluster-scoped). Wave 3 §S2 event-bus settings live here; missing CR or EventBus.Enabled=false runs in Wave-2 mode (no bus).")
	flag.StringVar(&busTokenEnv, "bus-token-env", "AUDIT_BUS_TOKEN", "Env var name carrying the bearer-token shared secret for the event bus (Wave 3)")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log := ctrl.Log.WithName("ugallu-audit-detection")
	log.Info("starting", "version", version, "source", sourceKind)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          true,
		LeaderElectionID:        "ugallu-audit-detection-leader",
		LeaderElectionNamespace: leaderElectionNS,
	})
	if err != nil {
		return fmt.Errorf("manager: %w", err)
	}
	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("healthz: %w", err)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("readyz: %w", err)
	}

	em, err := emitterv1alpha1.NewEmitter(&emitterv1alpha1.EmitterOpts{
		Client:       mgr.GetClient(),
		AttestorMeta: sign.AttestorMeta{Name: "ugallu-audit-detection", Version: version},
	})
	if err != nil {
		return fmt.Errorf("emitter: %w", err)
	}

	busServer, err := buildBusServer(mgr, configName, busTokenEnv)
	if err != nil {
		return fmt.Errorf("audit bus: %w", err)
	}

	engOpts := &engine.Options{
		Emitter:         em,
		ClusterIdentity: securityv1alpha1.ClusterIdentity{ClusterID: clusterID},
		Log:             slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
	if busServer != nil {
		engOpts.Publisher = busServer
		log.Info("audit event-bus enabled", "listen", busServer.ListenAddr())
		if addErr := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
			return busServer.Start(ctx)
		})); addErr != nil {
			return fmt.Errorf("add bus runnable: %w", addErr)
		}
	}
	eng, err := engine.New(engOpts)
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}

	if err = (&engine.SigmaRuleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Rules:  eng.Rules(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup SigmaRuleReconciler: %w", err)
	}

	src, err := buildSource(sourceKind, auditLogPath, webhookListenAddr, webhookPath, webhookCertFile, webhookKeyFile, webhookClientCAFile, webhookSecretEnv)
	if err != nil {
		return err
	}

	// Engine + Emitter share the manager's lifecycle. Adding them as
	// Runnables means leader election gates them and ctx is wired
	// through controller-runtime's signal handler.
	if addErr := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		em.Start(ctx)
		defer em.Close()
		return eng.Run(ctx, src)
	})); addErr != nil {
		return fmt.Errorf("add engine runnable: %w", addErr)
	}

	log.Info("running manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}

// buildBusServer reads the AuditDetectionConfig CR (when present)
// and instantiates a bus.Server iff EventBus.Enabled=true. Returns
// (nil, nil) when the bus is disabled or the CR is missing — that's
// the Wave-2 retrocompat path. Bearer-token comes from env so it
// never lands in process listings.
func buildBusServer(mgr ctrl.Manager, configName, tokenEnv string) (*bus.Server, error) {
	cfg := &securityv1alpha1.AuditDetectionConfig{}
	if err := mgr.GetAPIReader().Get(context.Background(), types.NamespacedName{Name: configName}, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get AuditDetectionConfig %q: %w", configName, err)
	}
	if !cfg.Spec.EventBus.Enabled {
		return nil, nil
	}
	listen := cfg.Spec.EventBus.ListenAddr
	if listen == "" {
		listen = ":8444"
	}
	return bus.New(bus.Config{
		ListenAddr:  listen,
		BearerToken: os.Getenv(tokenEnv),
		Consumers:   cfg.Spec.Consumers,
	})
}

// buildSource picks between the file and webhook backends based on
// the --source flag. Bearer-token shared secret comes from env so it
// never lands in flags or process listings.
func buildSource(kind, auditLogPath, listen, path, certFile, keyFile, clientCAFile, secretEnv string) (auditdetection.Source, error) {
	switch kind {
	case "file":
		return auditdetection.NewFileSource(&auditdetection.FileSourceOpts{Path: auditLogPath})
	case "webhook":
		return auditdetection.NewWebhookSource(&auditdetection.WebhookSourceOpts{
			ListenAddr:   listen,
			Path:         path,
			CertFile:     certFile,
			KeyFile:      keyFile,
			ClientCAFile: clientCAFile,
			SharedSecret: auditdetection.FromEnv(secretEnv),
		})
	default:
		return nil, errors.New(`--source must be "file" or "webhook"`)
	}
}
