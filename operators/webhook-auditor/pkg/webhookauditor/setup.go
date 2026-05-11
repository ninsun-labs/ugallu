// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package webhookauditor exposes the controller-runtime wiring for the
// ugallu-webhook-auditor operator.
package webhookauditor

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	emitterv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/emitter/v1alpha1"
)

// Options bundles the runtime parameters cmd/ugallu-webhook-auditor
// passes to SetupWithManager.
type Options struct {
	// ConfigName is the singleton WebhookAuditorConfig name (default
	// "default"). Empty disables the operator's read of the CR;
	// chart-shipped CR is required, so empty is treated as error.
	ConfigName string

	// ClusterIdentity stamps every emitted SE so downstream consumers
	// (attestor, forensics) can partition by cluster.
	ClusterIdentity securityv1alpha1.ClusterIdentity

	// Emitter is the SE emitter wired by cmd. Required.
	Emitter *emitterv1alpha1.Emitter
}

// SetupWithManager wires the MWC + VWC reconcilers + emit pipeline.
// Reads WebhookAuditorConfig once at startup to seed the evaluator
// and ignore matcher; subsequent updates are picked up on the
// 30s reconcile cadence (config CR mutations are rare in practice).
func SetupWithManager(mgr ctrl.Manager, opts *Options) error {
	if opts == nil {
		return errors.New("webhookauditor.SetupWithManager: nil Options")
	}
	if opts.Emitter == nil {
		return errors.New("webhookauditor.SetupWithManager: nil Emitter")
	}
	if opts.ConfigName == "" {
		return errors.New("webhookauditor.SetupWithManager: empty ConfigName")
	}

	cfg, err := loadConfig(context.Background(), mgr.GetAPIReader(), opts.ConfigName)
	if err != nil {
		return fmt.Errorf("load WebhookAuditorConfig %q: %w", opts.ConfigName, err)
	}

	threshold := int(cfg.Spec.RiskThreshold)
	if threshold == 0 {
		threshold = 60 // mirror the kubebuilder default for safety
	}

	allowedNamespaces := make([]string, 0, len(cfg.Spec.TrustedCASources))
	for _, src := range cfg.Spec.TrustedCASources {
		allowedNamespaces = append(allowedNamespaces, src.Namespace)
	}

	r := &Reconciler{
		Client:           mgr.GetClient(),
		Scheme:           mgr.GetScheme(),
		Evaluator:        NewEvaluator(EvaluatorOptions{TrustedSubjectDNs: cfg.Spec.TrustedSubjectDNs}),
		Cache:            newDebounceCache(),
		Ignore:           NewIgnoreMatcher(cfg.Spec.Ignore),
		CABundleResolver: NewCABundleResolver(mgr.GetAPIReader(), allowedNamespaces),
		Emit: EmitOptions{
			Emitter:         opts.Emitter,
			ClusterIdentity: opts.ClusterIdentity,
			Threshold:       threshold,
		},
	}
	if err := r.SetupWithManager(mgr); err != nil {
		return err
	}

	cs := &ConfigStatusReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		ConfigName: opts.ConfigName,
	}
	return cs.SetupWithManager(mgr)
}

// loadConfig fetches the singleton WebhookAuditorConfig CR via the
// manager's APIReader (cache may not be ready at startup).
func loadConfig(ctx context.Context, reader client.Reader, name string) (*securityv1alpha1.WebhookAuditorConfig, error) {
	cfg := &securityv1alpha1.WebhookAuditorConfig{}
	if err := reader.Get(ctx, types.NamespacedName{Name: name}, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			// No CR present → defaults. Operator runs with the
			// kubebuilder default threshold and empty trust list
			// (everything will trigger ca_untrusted, by design - let
			// the admin notice and create the CR).
			return &securityv1alpha1.WebhookAuditorConfig{
				Spec: securityv1alpha1.WebhookAuditorConfigSpec{RiskThreshold: 60},
			}, nil
		}
		return nil, err
	}
	return cfg, nil
}

// Manager is a thin re-export so cmd/ugallu-webhook-auditor's main.go
// can keep its imports stable across the scaffold → wired transition.
type Manager = manager.Manager
