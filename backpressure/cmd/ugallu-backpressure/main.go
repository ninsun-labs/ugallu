// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-backpressure is the leader-elected workload that
// samples kube-apiserver storage usage and reconciles the
// ugallu-backpressure ConfigMap consumed by every SDK emitter
// (design 16 §Layer 4).
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/runtime/backpressure"
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

		cmNamespace string
		cmName      string

		metricsURL      string
		bearerTokenFile string
		caBundlePath    string
		insecureSkipTLS bool

		etcdCapacityBytes uint64
		yellowAt          float64
		redAt             float64
		recoverAt         float64
		pollInterval      time.Duration
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "ugallu-system", "Leader election Lease namespace")

	flag.StringVar(&cmNamespace, "configmap-namespace", backpressure.DefaultNamespace, "Namespace of the output ConfigMap")
	flag.StringVar(&cmName, "configmap-name", backpressure.DefaultConfigMapName, "Name of the output ConfigMap")

	flag.StringVar(&metricsURL, "metrics-url", "https://kubernetes.default.svc/metrics", "kube-apiserver Prometheus metrics endpoint")
	flag.StringVar(&bearerTokenFile, "bearer-token-file", "/var/run/secrets/kubernetes.io/serviceaccount/token", "OIDC/SA token file used for the metrics scrape")
	flag.StringVar(&caBundlePath, "ca-bundle-path", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "PEM CA bundle for the metrics scrape (empty uses system trust)")
	flag.BoolVar(&insecureSkipTLS, "insecure-skip-tls-verify", false, "Disable TLS verification for the metrics scrape (dev/lab only)")

	flag.Uint64Var(&etcdCapacityBytes, "etcd-capacity-bytes", backpressure.DefaultEtcdCapacityBytes, "Etcd capacity used as denominator when the sampler doesn't report one")
	flag.Float64Var(&yellowAt, "yellow-at", backpressure.DefaultYellowAt, "Storage-usage ratio that escalates from Green to Yellow")
	flag.Float64Var(&redAt, "red-at", backpressure.DefaultRedAt, "Storage-usage ratio that escalates to Red")
	flag.Float64Var(&recoverAt, "recover-at", backpressure.DefaultRecoverAt, "Storage-usage ratio that recovers from Yellow to Green")
	flag.DurationVar(&pollInterval, "poll-interval", backpressure.DefaultPollInterval, "Sampler poll cadence")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	log := ctrl.Log.WithName("ugallu-backpressure")
	log.Info("starting", "version", version)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          true,
		LeaderElectionID:        "ugallu-backpressure-leader",
		LeaderElectionNamespace: leaderElectionNS,
		// The backpressure controller writes a single ConfigMap in
		// cmNamespace; restrict the informer cache to that namespace
		// so the SA only needs namespaced list/watch perms.
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				cmNamespace: {},
			},
		},
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

	var caBundle []byte
	if caBundlePath != "" {
		b, rErr := os.ReadFile(caBundlePath) //nolint:gosec // operator-controlled path
		if rErr == nil {
			caBundle = b
		} else if !os.IsNotExist(rErr) {
			return fmt.Errorf("read ca bundle %q: %w", caBundlePath, rErr)
		}
	}

	sampler := &backpressure.PrometheusSampler{
		URL:                metricsURL,
		BearerTokenFile:    bearerTokenFile,
		CABundle:           caBundle,
		InsecureSkipVerify: insecureSkipTLS,
	}

	controller, err := backpressure.NewController(&backpressure.Options{
		Sampler:           sampler,
		Client:            mgr.GetClient(),
		Namespace:         cmNamespace,
		ConfigMapName:     cmName,
		PollInterval:      pollInterval,
		EtcdCapacityBytes: etcdCapacityBytes,
		YellowAt:          yellowAt,
		RedAt:             redAt,
		RecoverAt:         recoverAt,
	})
	if err != nil {
		return fmt.Errorf("backpressure controller: %w", err)
	}
	if err = controller.AddToManager(mgr); err != nil {
		return fmt.Errorf("add controller to manager: %w", err)
	}

	log.Info("running manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}
