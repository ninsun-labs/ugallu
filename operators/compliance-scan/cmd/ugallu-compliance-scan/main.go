// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-compliance-scan reconciles ComplianceScanRun CRs:
// for each Run it dispatches to one of the backend scanners
// (kube-bench, Falco, CEL-custom), writes a ComplianceScanResult
// with the per-check report, and emits the matching SE
// (design 21 §C — Wave 4 §S5).
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

	"github.com/ninsun-labs/ugallu/operators/compliance-scan/pkg/compliancescan"
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
		jobNamespace     string
		kubeBenchImage   string
		falcoHost        string
		falcoPort        uint
		falcoCertFile    string
		falcoKeyFile     string
		falcoCARootFile  string
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "ugallu-system", "Leader election Lease namespace")
	flag.StringVar(&clusterID, "cluster-id", "", "ClusterIdentity.ClusterID stamped on emitted SecurityEvents")
	flag.StringVar(&clusterName, "cluster-name", "", "ClusterIdentity.ClusterName stamped on emitted SecurityEvents")
	flag.StringVar(&jobNamespace, "job-namespace", "ugallu-system-privileged", "Namespace where the kube-bench backend templates its privileged Job")
	flag.StringVar(&kubeBenchImage, "kube-bench-image", "", "Override the kube-bench image (empty = chart default)")
	flag.StringVar(&falcoHost, "falco-host", "", "Falco gRPC hostname (empty = degrade to stub for the falco backend)")
	flag.UintVar(&falcoPort, "falco-port", 5060, "Falco gRPC port")
	flag.StringVar(&falcoCertFile, "falco-cert-file", "/etc/falco-client-certs/client.crt", "Path to the client certificate for the Falco mTLS handshake")
	flag.StringVar(&falcoKeyFile, "falco-key-file", "/etc/falco-client-certs/client.key", "Path to the client key for the Falco mTLS handshake")
	flag.StringVar(&falcoCARootFile, "falco-ca-root-file", "/etc/falco-client-certs/ca.crt", "Path to the CA root cert chain that issued the Falco server cert")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log := ctrl.Log.WithName("ugallu-compliance-scan")
	log.Info("starting", "version", version)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          true,
		LeaderElectionID:        "ugallu-compliance-scan-leader",
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
		AttestorMeta: sign.AttestorMeta{Name: "ugallu-compliance-scan", Version: version},
	})
	if err != nil {
		return fmt.Errorf("emitter setup: %w", err)
	}

	if err = compliancescan.SetupWithManager(mgr, &compliancescan.Options{
		ClusterIdentity: securityv1alpha1.ClusterIdentity{
			ClusterID:   clusterID,
			ClusterName: clusterName,
		},
		Emitter:         emitter,
		JobNamespace:    jobNamespace,
		KubeBenchImage:  kubeBenchImage,
		FalcoHost:       falcoHost,
		FalcoPort:       uint16(falcoPort), //nolint:gosec // CLI flag is bounded; uint16 cast is safe.
		FalcoCertFile:   falcoCertFile,
		FalcoKeyFile:    falcoKeyFile,
		FalcoCARootFile: falcoCARootFile,
	}); err != nil {
		return fmt.Errorf("compliance-scan reconcilers setup: %w", err)
	}

	log.Info("running manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}
