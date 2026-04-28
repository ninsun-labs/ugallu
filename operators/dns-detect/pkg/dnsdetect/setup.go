// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package dnsdetect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsdetect/detector"
	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsdetect/source"
)

// Options bundles the runtime parameters cmd/ugallu-dns-detect passes
// to SetupWithManager.
type Options struct {
	ConfigName      string
	ClusterIdentity securityv1alpha1.ClusterIdentity
	Emitter         *emitterv1alpha1.Emitter
}

// SetupWithManager loads the DNSDetectConfig, builds the 5 detectors
// and the chosen source, and starts the dispatcher as a manager
// Runnable.
func SetupWithManager(mgr ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("dnsdetect.SetupWithManager: nil Options")
	}
	if opts.Emitter == nil {
		return errors.New("dnsdetect.SetupWithManager: nil Emitter")
	}
	if opts.ConfigName == "" {
		return errors.New("dnsdetect.SetupWithManager: empty ConfigName")
	}

	cfg, err := loadConfig(context.Background(), mgr.GetAPIReader(), opts.ConfigName)
	if err != nil {
		return fmt.Errorf("load DNSDetectConfig %q: %w", opts.ConfigName, err)
	}

	detectors := buildDetectors(cfg.Spec.Detectors)
	src, srcKind, err := buildSource(cfg.Spec.Source)
	if err != nil {
		return fmt.Errorf("source setup: %w", err)
	}

	disp := NewDispatcher(detectors, opts.Emitter, opts.ClusterIdentity)

	// Track the active source kind for Status reporting (atomic so
	// the cfg-status reconciler can read concurrently).
	activeSource := &atomic.Value{}
	activeSource.Store(srcKind)

	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		ch, runErr := src.Run(ctx)
		if runErr != nil {
			return fmt.Errorf("source %s: %w", src.Name(), runErr)
		}
		disp.Run(ctx, ch)
		return nil
	})); err != nil {
		return fmt.Errorf("dispatcher Runnable: %w", err)
	}

	cs := &ConfigStatusReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		ConfigName: opts.ConfigName,
		ActiveSource: func() securityv1alpha1.DNSDetectSourceMode {
			return activeSource.Load().(securityv1alpha1.DNSDetectSourceMode)
		},
	}
	return cs.SetupWithManager(mgr)
}

// buildDetectors instantiates the 5 detectors from the config block.
// Disabled detectors are silently skipped.
func buildDetectors(cfg securityv1alpha1.DNSDetectorsConfig) []detector.Detector {
	out := make([]detector.Detector, 0, 5)
	if cfg.Exfiltration.Enabled {
		minEntropy, _ := strconv.ParseFloat(cfg.Exfiltration.MinEntropy, 64)
		out = append(out, detector.NewExfiltrationDetector(detector.ExfiltrationConfig{
			MinLabelLen:         int(cfg.Exfiltration.MinLabelLen),
			MinEntropy:          minEntropy,
			WindowSize:          int(cfg.Exfiltration.WindowSize),
			ConsecutiveTriggers: int(cfg.Exfiltration.ConsecutiveTriggers),
		}))
	}
	if cfg.Tunneling.Enabled {
		out = append(out, detector.NewTunnelingDetector(detector.TunnelingConfig{
			RatelimitPerPod: cfg.Tunneling.RatelimitPerPod.Duration,
		}))
	}
	if cfg.Blocklist.Enabled {
		// Entries are pushed at runtime by the ConfigMap watcher;
		// commit-4 wires that. For now, an empty list — the detector
		// no-fires until SetEntries is called.
		out = append(out, detector.NewBlocklistDetector())
	}
	if cfg.YoungDomain.Enabled {
		// AgeLookup wired to RDAP in a follow-up commit; nil disables
		// the detector cleanly.
		out = append(out, detector.NewYoungDomainDetector(detector.YoungDomainConfig{
			ThresholdDays: int(cfg.YoungDomain.ThresholdDays),
		}, nil))
	}
	if cfg.AnomalousPort.Enabled {
		out = append(out, detector.NewAnomalousPortDetector())
	}
	return out
}

// buildSource picks the primary source from Spec.Source.Primary.
// Fallback wiring is a follow-up — for now the operator runs on the
// primary and emits DNSSourceSilent when it goes quiet.
func buildSource(cfg securityv1alpha1.DNSSourceConfig) (source.Source, securityv1alpha1.DNSDetectSourceMode, error) {
	switch cfg.Primary {
	case securityv1alpha1.DNSDetectSourceCoreDNSPlugin:
		endpoint := ""
		if cfg.Plugin != nil {
			endpoint = cfg.Plugin.GRPCEndpoint
		}
		if endpoint == "" {
			return nil, "", errors.New("source.primary=coredns_plugin requires source.plugin.grpcEndpoint")
		}
		s, err := source.NewCoreDNSPluginSource(source.CoreDNSPluginConfig{
			GRPCEndpoint: endpoint,
			NodeName:     os.Getenv("HOSTNAME"),
		})
		if err != nil {
			return nil, "", err
		}
		return s, securityv1alpha1.DNSDetectSourceCoreDNSPlugin, nil
	case securityv1alpha1.DNSDetectSourceTetragonKprobe:
		return source.NewTetragonKprobeSource(), securityv1alpha1.DNSDetectSourceTetragonKprobe, nil
	default:
		return nil, "", fmt.Errorf("unsupported source.primary %q", cfg.Primary)
	}
}

// loadConfig fetches the singleton DNSDetectConfig CR via APIReader.
func loadConfig(ctx context.Context, reader client.Reader, name string) (*securityv1alpha1.DNSDetectConfig, error) {
	cfg := &securityv1alpha1.DNSDetectConfig{}
	if err := reader.Get(ctx, types.NamespacedName{Name: name}, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			// Defaults: coredns_plugin source, all 5 detectors enabled
			// with kubebuilder defaults. Empty plugin endpoint will
			// fail buildSource — admin sees a clear "create the CR"
			// error in the operator log.
			return nil, fmt.Errorf("DNSDetectConfig %q not found; chart-shipped CR is required", name)
		}
		return nil, err
	}
	return cfg, nil
}
