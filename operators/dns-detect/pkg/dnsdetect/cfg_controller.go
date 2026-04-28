// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package dnsdetect

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// ConfigStatusReconciler refreshes DNSDetectConfig.Status with the
// active source backend. Cadence 30s — config CR mutations are rare.
type ConfigStatusReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	ConfigName    string
	ActiveSource  func() securityv1alpha1.DNSDetectSourceMode
	InflightLookups func() int32
}

// Reconcile patches Status.source + Status.lastConfigLoadAt every
// 30s. Skipped when the CR is absent (chart pre-install gap).
func (r *ConfigStatusReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	cfg := &securityv1alpha1.DNSDetectConfig{}
	if err := r.Get(ctx, req.NamespacedName, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	now := metav1.Now()
	patch := client.MergeFrom(cfg.DeepCopy())
	if r.ActiveSource != nil {
		cfg.Status.Source = r.ActiveSource()
	}
	if r.InflightLookups != nil {
		cfg.Status.InflightLookups = r.InflightLookups()
	}
	cfg.Status.LastConfigLoadAt = &now

	if err := r.Status().Patch(ctx, cfg, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// SetupWithManager wires the reconciler.
func (r *ConfigStatusReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("dns-detect-cfgstatus").
		For(&securityv1alpha1.DNSDetectConfig{}).
		Complete(r)
}
