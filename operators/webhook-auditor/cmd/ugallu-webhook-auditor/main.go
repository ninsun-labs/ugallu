// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-webhook-auditor scores admission webhook
// configurations (MutatingWebhookConfiguration / ValidatingWebhookConfiguration)
// and emits SecurityEvent CRs when a webhook crosses the configured
// risk threshold.
//
// Scaffold commit: the manager boots, registers /healthz + /readyz,
// validates Options, and exits cleanly. Real reconcilers ship in
// the next commit.
package main

import (
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"

	"github.com/ninsun-labs/ugallu/operators/webhook-auditor/pkg/webhookauditor"
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
		clusterID        string
		clusterName      string
		configName       string
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "ugallu-system", "Leader election Lease namespace")
	flag.StringVar(&clusterID, "cluster-id", "", "ClusterIdentity.ClusterID stamped on emitted SecurityEvents")
	flag.StringVar(&clusterName, "cluster-name", "", "ClusterIdentity.ClusterName stamped on emitted SecurityEvents")
	flag.StringVar(&configName, "config-name", "default", "WebhookAuditorConfig singleton name")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log := ctrl.Log.WithName("ugallu-webhook-auditor")
	log.Info("starting", "version", version)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          true,
		LeaderElectionID:        "ugallu-webhook-auditor-leader",
		LeaderElectionNamespace: leaderElectionNS,
	})
	if err != nil {
		return fmt.Errorf("manager creation: %w", err)
	}

	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("healthz check setup: %w", err)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("readyz check setup: %w", err)
	}

	emitter, err := emitterv1alpha1.NewEmitter(&emitterv1alpha1.EmitterOpts{
		Client:       mgr.GetClient(),
		AttestorMeta: sign.AttestorMeta{Name: "ugallu-webhook-auditor", Version: version},
	})
	if err != nil {
		return fmt.Errorf("emitter setup: %w", err)
	}

	if err = webhookauditor.SetupWithManager(mgr, &webhookauditor.Options{
		ConfigName: configName,
		ClusterIdentity: securityv1alpha1.ClusterIdentity{
			ClusterID:   clusterID,
			ClusterName: clusterName,
		},
		Emitter: emitter,
	}); err != nil {
		return fmt.Errorf("webhookauditor reconcilers setup: %w", err)
	}

	log.Info("running manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}
