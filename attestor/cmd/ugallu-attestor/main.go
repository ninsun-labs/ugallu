// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-attestor is the leader-elected Deployment that signs
// SecurityEvent and EventResponse facts as in-toto attestations and
// stores them on Rekor + WORM.
//
// Pre-alpha (iter 2): three reconcilers from sdk/pkg/evidence/attestor are
// wired (SecurityEvent watcher, EventResponse watcher, AttestationBundle
// pipeline). Bundles are signed via the in-process Ed25519 Signer (the
// default in this build). Real Fulcio keyless / OpenBao transit signing
// + Rekor logging + WORM archival arrive in subsequent commits.
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
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/attestor"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

const version = "v0.0.1-alpha.1"

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
}

func main() {
	if err := runMain(); err != nil {
		// Logger already set up by runMain; fall back to stderr if not.
		ctrl.Log.Error(err, "fatal")
		os.Exit(1)
	}
}

func runMain() error {
	var (
		metricsAddr      string
		probeAddr        string
		leaderElectionNS string
		signingMode      string
		instanceName     string
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "ugallu-system", "Leader election Lease namespace")
	flag.StringVar(&signingMode, "signing-mode", "ed25519-dev", "Signing mode (ed25519-dev | fulcio-keyless | openbao-transit | dual)")
	flag.StringVar(&instanceName, "instance", os.Getenv("HOSTNAME"), "Attestor instance identifier (recorded in the in-toto Statement; defaults to $HOSTNAME)")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log := ctrl.Log.WithName("ugallu-attestor")
	log.Info("starting", "version", version)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          true,
		LeaderElectionID:        "ugallu-attestor-leader",
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

	signer, err := sign.NewSigner(securityv1alpha1.SigningMode(signingMode))
	if err != nil {
		return fmt.Errorf("signer setup (mode=%s): %w", signingMode, err)
	}
	log.Info("signer ready", "mode", signer.Mode(), "keyID", signer.KeyID())

	if err = attestor.SetupReconcilers(mgr, attestor.Options{
		Signer: signer,
		Attestor: sign.AttestorMeta{
			Name:     "ugallu-attestor",
			Version:  version,
			Instance: instanceName,
		},
	}); err != nil {
		return fmt.Errorf("attestor reconcilers setup: %w", err)
	}

	log.Info("running manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}
