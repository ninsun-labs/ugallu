// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package webhookauditor

import (
	"context"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// ConfigStatusReconciler periodically refreshes the singleton
// WebhookAuditorConfig.Status fields with operator-observed counts.
// Cadence is fixed at 30s via RequeueAfter — config CR mutations are
// rare enough that the cost of a list+patch every 30s is negligible
// (a few KB of apiserver traffic).
type ConfigStatusReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// ConfigName is the singleton CR name (default "default").
	ConfigName string
}

// Reconcile reads the current MWC+VWC count and writes it to
// Status.ObservedWebhooks + Status.LastConfigLoadAt. The CR Spec is
// never mutated. Skipped when the CR is absent (chart pre-install).
func (r *ConfigStatusReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rlog := log.FromContext(ctx).WithName("webhook-auditor-cfgstatus").WithValues("name", req.Name)

	cfg := &securityv1alpha1.WebhookAuditorConfig{}
	if err := r.Get(ctx, req.NamespacedName, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	mwcList := &admissionregistrationv1.MutatingWebhookConfigurationList{}
	if err := r.List(ctx, mwcList); err != nil {
		return ctrl.Result{}, err
	}
	vwcList := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	if err := r.List(ctx, vwcList); err != nil {
		return ctrl.Result{}, err
	}
	total := int32(len(mwcList.Items) + len(vwcList.Items))

	now := metav1.Now()
	patch := client.MergeFrom(cfg.DeepCopy())
	cfg.Status.ObservedWebhooks = total
	cfg.Status.LastConfigLoadAt = &now

	if err := r.Status().Patch(ctx, cfg, patch); err != nil {
		return ctrl.Result{}, err
	}
	rlog.V(1).Info("status updated", "observedWebhooks", total)

	observedCount.Set(float64(total))
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// SetupWithManager wires the reconciler. Watches the
// WebhookAuditorConfig CRD only (we don't react to MWC/VWC events
// here — that's the score reconciler's job; here the count is
// recomputed on the 30s tick).
func (r *ConfigStatusReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("webhook-auditor-cfgstatus").
		For(&securityv1alpha1.WebhookAuditorConfig{}).
		Complete(r)
}
