// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-dns-detect consumes DNS events from CoreDNS plugin
// (primary) or Tetragon kprobe (fallback) and emits SecurityEvent CRs
// when one of the 5 detectors fires (design 21 §D).
//
// Scaffold commit: manager boots, /healthz + /readyz registered,
// Options validated. Source + detector wiring lands in subsequent
// commits of Wave 3 Sprint 3.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
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
	resolverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/clientv1"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsdetect"
	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsdetect/source"
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
		resolverUDS      string
		resolverEndpoint string
		resolverInsecure bool
		resolverDialBoot time.Duration
		resolverDisable  bool
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "ugallu-system", "Leader election Lease namespace")
	flag.StringVar(&clusterID, "cluster-id", "", "ClusterIdentity.ClusterID stamped on emitted SecurityEvents")
	flag.StringVar(&clusterName, "cluster-name", "", "ClusterIdentity.ClusterName stamped on emitted SecurityEvents")
	flag.StringVar(&configName, "config-name", "default", "DNSDetectConfig singleton name")
	flag.StringVar(&resolverUDS, "resolver-uds", resolverv1.DefaultUnixSocket, "Resolver UDS path (UDS-fast path)")
	flag.StringVar(&resolverEndpoint, "resolver-endpoint", resolverv1.DefaultClusterEndpoint, "Resolver TCP fallback endpoint")
	flag.BoolVar(&resolverInsecure, "resolver-insecure", false, "Skip TLS on the resolver TCP endpoint (lab/dev only)")
	flag.DurationVar(&resolverDialBoot, "resolver-dial-boot-timeout", 2*time.Second, "Bound on the boot-time resolver dial")
	flag.BoolVar(&resolverDisable, "resolver-disable", false, "Disable resolver enrichment — detectors fall back to SrcIP synthetic key")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log := ctrl.Log.WithName("ugallu-dns-detect")
	log.Info("starting", "version", version)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          true,
		LeaderElectionID:        "ugallu-dns-detect-leader",
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
		AttestorMeta: sign.AttestorMeta{Name: "ugallu-dns-detect", Version: version},
	})
	if err != nil {
		return fmt.Errorf("emitter setup: %w", err)
	}

	var resolver source.Resolver
	if !resolverDisable {
		resolver, err = buildResolver(resolverUDS, resolverEndpoint, resolverInsecure, resolverDialBoot, log)
		if err != nil {
			// A boot-time resolver miss should not crashloop the
			// operator — detectors degrade gracefully to the SrcIP
			// synthetic key. Log loudly and continue.
			log.Error(err, "resolver dial failed, continuing without enrichment")
			resolver = nil
		}
	}

	if err = dnsdetect.SetupWithManager(mgr, &dnsdetect.Options{
		ConfigName: configName,
		ClusterIdentity: securityv1alpha1.ClusterIdentity{
			ClusterID:   clusterID,
			ClusterName: clusterName,
		},
		Emitter:  emitter,
		Resolver: resolver,
	}); err != nil {
		return fmt.Errorf("dnsdetect reconcilers setup: %w", err)
	}

	log.Info("running manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}

// buildResolver dials the resolver (UDS-first, TCP fallback) and wraps
// the stub in the SDK CachedClient so per-event lookups are bounded
// by an LRU + per-method circuit breaker.
func buildResolver(uds, endpoint string, tcpInsecure bool, dialBoot time.Duration, log logr.Logger) (source.Resolver, error) {
	dialer := resolverv1.NewDialer(&resolverv1.DialerOpts{
		UnixSocket:      uds,
		ClusterEndpoint: endpoint,
		Insecure:        tcpInsecure,
	})
	dialCtx, cancel := context.WithTimeout(context.Background(), dialBoot)
	defer cancel()
	stub, err := dialer.Dial(dialCtx)
	if err != nil {
		return nil, fmt.Errorf("resolver dial: %w", err)
	}
	cached, err := resolverv1.NewCachedClient(&resolverv1.CachedClientOpts{Inner: stub})
	if err != nil {
		return nil, fmt.Errorf("resolver cached client: %w", err)
	}
	log.Info("resolver wired", "transport", dialer.Transport())
	return cached, nil
}
