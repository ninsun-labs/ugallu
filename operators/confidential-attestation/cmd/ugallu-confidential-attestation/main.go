// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-confidential-attestation reconciles
// ConfidentialAttestationRun CRs and produces a per-run
// ConfidentialAttestationResult with the hardware-backed quote +
// verifier verdict (design 21 §A — Wave 4 §S6).
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

	"github.com/ninsun-labs/ugallu/operators/confidential-attestation/pkg/confidentialattestation"
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
		nodeName         string
		tpmDevice        string
		sevSnpDevice     string
		tdxDevice        string
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "ugallu-system", "Leader election Lease namespace")
	flag.StringVar(&clusterID, "cluster-id", "", "ClusterIdentity.ClusterID stamped on emitted SecurityEvents")
	flag.StringVar(&clusterName, "cluster-name", "", "ClusterIdentity.ClusterName stamped on emitted SecurityEvents")
	flag.StringVar(&nodeName, "node-name", os.Getenv("NODE_NAME"),
		"Node this attester pod runs on (defaults to NODE_NAME). The reconciler ignores runs targeting other nodes.")
	flag.StringVar(&tpmDevice, "tpm-device", "/dev/tpm0", "Host-mounted TPM 2.0 character device")
	flag.StringVar(&sevSnpDevice, "sev-snp-device", "/dev/sev-guest", "Host-mounted AMD SEV-SNP guest attestation device")
	flag.StringVar(&tdxDevice, "tdx-device", "/dev/tdx-guest", "Host-mounted Intel TDX guest attestation device")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log := ctrl.Log.WithName("ugallu-confidential-attestation")
	log.Info("starting", "version", version, "node", nodeName)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          true,
		LeaderElectionID:        "ugallu-confidential-attestation-leader",
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
		AttestorMeta: sign.AttestorMeta{Name: "ugallu-confidential-attestation", Version: version},
	})
	if err != nil {
		return fmt.Errorf("emitter setup: %w", err)
	}

	if err = confidentialattestation.SetupWithManager(mgr, &confidentialattestation.Options{
		ClusterIdentity: securityv1alpha1.ClusterIdentity{
			ClusterID:   clusterID,
			ClusterName: clusterName,
		},
		Emitter:      emitter,
		NodeName:     nodeName,
		TPMDevice:    tpmDevice,
		SEVSNPDevice: sevSnpDevice,
		TDXDevice:    tdxDevice,
	}); err != nil {
		return fmt.Errorf("confidential-attestation reconcilers setup: %w", err)
	}

	log.Info("running manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}
