// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package ttl

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/worm"
)

// EventResponseTTLReconciler garbage-collects EventResponse CRs.
//
// TTL strategy: matchParent — the ER inherits the parent SE's severity
// TTL. When the parent SE is gone (already archived), the ER falls
// back to the medium-severity default (24h) anchored to its own
// CreationTimestamp.
type EventResponseTTLReconciler struct {
	client.Client
	Scheme                  *runtime.Scheme
	WormUploader            worm.Uploader
	PostponeOnMissingBundle time.Duration
	TTLConfigNamespace      string
}

// Reconcile evaluates the ER TTL state machine.
func (r *EventResponseTTLReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rlog := log.FromContext(ctx).WithValues("eventresponse", req.Name)

	if r.WormUploader == nil {
		return ctrl.Result{}, fmt.Errorf("EventResponseTTLReconciler.WormUploader is nil; call SetupReconcilers")
	}

	er := &securityv1alpha1.EventResponse{}
	if err := r.Get(ctx, req.NamespacedName, er); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	annos := er.GetAnnotations()
	if isFrozen(annos) {
		return ctrl.Result{}, nil
	}

	now := time.Now()
	if pp := postponedUntil(annos); !pp.IsZero() && pp.After(now) {
		recordPostpone(kindER, postponeReasonAnnotation)
		return ctrl.Result{RequeueAfter: time.Until(pp)}, nil
	}

	cfg, err := loadEffectiveTTLConfig(ctx, r.Client, r.TTLConfigNamespace)
	if err != nil {
		recordFailure(kindER, failureStageConfig)
		return ctrl.Result{}, fmt.Errorf("load TTLConfig: %w", err)
	}
	ttl, ok := annotationOverrideTTL(annos)
	if !ok {
		ttl = r.parentSeverityTTL(ctx, er, cfg)
	}
	expiry := er.CreationTimestamp.Add(ttl)
	if now.Before(expiry) {
		recordPostpone(kindER, postponeReasonNotExpired)
		return ctrl.Result{RequeueAfter: time.Until(expiry)}, nil
	}

	if annos[AnnotationTTLForce] != "true" {
		bundleName := fmt.Sprintf("att-er-%s", er.Name)
		sealed, sErr := bundleSealed(ctx, r.Client, bundleName)
		if sErr != nil {
			recordFailure(kindER, failureStagePrecondition)
			return ctrl.Result{}, fmt.Errorf("check bundle sealed: %w", sErr)
		}
		if !sealed {
			postpone := r.PostponeOnMissingBundle
			if postpone <= 0 {
				postpone = time.Hour
			}
			recordPostpone(kindER, postponeReasonBundleNotSealed)
			return ctrl.Result{RequeueAfter: postpone}, nil
		}
	}

	pipelineStart := time.Now()
	clusterID := r.parentClusterID(ctx, er)
	ref, err := snapshotAndDelete(ctx, r.Client, r.WormUploader, er,
		clusterID, now.Add(cfg.bundleGrace()))
	if err != nil {
		recordFailure(kindER, failureStageSnapshot)
		return ctrl.Result{}, err
	}
	severity := "unknown"
	parent := &securityv1alpha1.SecurityEvent{}
	if pErr := r.Get(ctx, client.ObjectKey{Name: er.Spec.SecurityEventRef.Name}, parent); pErr == nil {
		severity = string(parent.Spec.Severity)
	}
	recordArchive(kindER, severity, pipelineStart)
	rlog.Info("EventResponse archived to WORM and deleted",
		"wormURL", ref.URL,
		"wormSHA256", ref.SHA256,
		"size", ref.Size,
	)
	return ctrl.Result{}, nil
}

// parentSeverityTTL fetches the parent SE and returns its severity TTL
// (resolved against the loaded TTLConfig), falling back to a
// conservative default when the parent is gone or unreachable.
func (r *EventResponseTTLReconciler) parentSeverityTTL(ctx context.Context, er *securityv1alpha1.EventResponse, cfg effectiveTTLConfig) time.Duration {
	parent := &securityv1alpha1.SecurityEvent{}
	err := r.Get(ctx, client.ObjectKey{Name: er.Spec.SecurityEventRef.Name}, parent)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return cfg.severityTTL(securityv1alpha1.SeverityMedium)
		}
		// On transient errors return a conservative TTL so the reconciler
		// requeues; do not delete prematurely.
		return cfg.severityTTL(securityv1alpha1.SeverityCritical)
	}
	return cfg.severityTTL(parent.Spec.Severity)
}

// parentClusterID returns the parent SE's clusterID, or "" when the
// parent is no longer available.
func (r *EventResponseTTLReconciler) parentClusterID(ctx context.Context, er *securityv1alpha1.EventResponse) string {
	parent := &securityv1alpha1.SecurityEvent{}
	if err := r.Get(ctx, client.ObjectKey{Name: er.Spec.SecurityEventRef.Name}, parent); err != nil {
		return ""
	}
	return parent.Spec.ClusterIdentity.ClusterID
}

// SetupWithManager wires the reconciler with controller-runtime
// defaults. Prefer SetupWithManagerAndOptions in production wiring
// so TTLConfig.spec.worker tuning takes effect.
func (r *EventResponseTTLReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, controller.Options{})
}

// SetupWithManagerAndOptions registers the reconciler with the
// supplied controller.Options.
func (r *EventResponseTTLReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts controller.Options) error { //nolint:gocritic // mirrors controller-runtime's by-value Options API
	return ctrl.NewControllerManagedBy(mgr).
		Named("eventresponse-ttl").
		For(&securityv1alpha1.EventResponse{}).
		WithOptions(opts).
		Complete(r)
}
