// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package ttl

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/worm"
)

// SecurityEventTTLReconciler garbage-collects SecurityEvent CRs once
// their TTL has elapsed and the parent AttestationBundle is Sealed
// (precondition T2.1).
type SecurityEventTTLReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	WormUploader worm.Uploader
	// PostponeOnMissingBundle is the requeue interval used when the
	// parent bundle is not yet Sealed. Defaults to 1h.
	PostponeOnMissingBundle time.Duration
	// TTLConfigNamespace is the namespace consulted for the TTLConfig
	// singleton. Defaults to "ugallu-system".
	TTLConfigNamespace string
}

// Reconcile evaluates the SE TTL state machine.
func (r *SecurityEventTTLReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rlog := log.FromContext(ctx).WithValues("securityevent", req.Name)

	if r.WormUploader == nil {
		return ctrl.Result{}, fmt.Errorf("SecurityEventTTLReconciler.WormUploader is nil; call SetupReconcilers")
	}

	se := &securityv1alpha1.SecurityEvent{}
	if err := r.Get(ctx, req.NamespacedName, se); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	annos := se.GetAnnotations()
	if isFrozen(annos) {
		rlog.V(1).Info("SE frozen by annotation; skipping")
		return ctrl.Result{}, nil
	}

	now := time.Now()

	if pp := postponedUntil(annos); !pp.IsZero() && pp.After(now) {
		recordPostpone(kindSE, postponeReasonAnnotation)
		return ctrl.Result{RequeueAfter: time.Until(pp)}, nil
	}

	cfg, err := loadEffectiveTTLConfig(ctx, r.Client, r.TTLConfigNamespace)
	if err != nil {
		recordFailure(kindSE, failureStageConfig)
		return ctrl.Result{}, fmt.Errorf("load TTLConfig: %w", err)
	}
	ttl := cfg.severityTTL(se.Spec.Severity)
	if d, ok := annotationOverrideTTL(annos); ok {
		ttl = d
	}
	expiry := se.CreationTimestamp.Add(ttl)
	if now.Before(expiry) {
		recordPostpone(kindSE, postponeReasonNotExpired)
		return ctrl.Result{RequeueAfter: time.Until(expiry)}, nil
	}

	// Precondition: parent bundle must be Sealed (or T8 force annotation).
	if annos[AnnotationTTLForce] != "true" {
		bundleName := fmt.Sprintf("att-se-%s", se.Name)
		sealed, sErr := bundleSealed(ctx, r.Client, bundleName)
		if sErr != nil {
			recordFailure(kindSE, failureStagePrecondition)
			return ctrl.Result{}, fmt.Errorf("check bundle sealed: %w", sErr)
		}
		if !sealed {
			postpone := r.PostponeOnMissingBundle
			if postpone <= 0 {
				postpone = time.Hour
			}
			recordPostpone(kindSE, postponeReasonBundleNotSealed)
			rlog.V(1).Info("parent bundle not Sealed; postponing", "after", postpone)
			return ctrl.Result{RequeueAfter: postpone}, nil
		}
	}

	pipelineStart := time.Now()
	ref, err := snapshotAndDelete(ctx, r.Client, r.WormUploader, se,
		se.Spec.ClusterIdentity.ClusterID, now.Add(cfg.bundleGrace()))
	if err != nil {
		recordFailure(kindSE, failureStageSnapshot)
		return ctrl.Result{}, err
	}
	recordArchive(kindSE, string(se.Spec.Severity), pipelineStart)
	rlog.Info("SecurityEvent archived to WORM and deleted",
		"wormURL", ref.URL,
		"wormSHA256", ref.SHA256,
		"size", ref.Size,
	)
	return ctrl.Result{}, nil
}

// SetupWithManager wires the reconciler with controller-runtime
// defaults (single worker, default workqueue rate limiter).
func (r *SecurityEventTTLReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, controller.Options{})
}

// SetupWithManagerAndOptions wires the reconciler with caller-supplied
// controller.Options (typically MaxConcurrentReconciles + a tuned
// RateLimiter). Used by SetupReconcilers to apply TTLConfig.spec.worker
// uniformly across the three TTL reconcilers.
func (r *SecurityEventTTLReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts controller.Options) error { //nolint:gocritic // mirrors controller-runtime's by-value Options API
	return ctrl.NewControllerManagedBy(mgr).
		Named("securityevent-ttl").
		For(&securityv1alpha1.SecurityEvent{}).
		WithOptions(opts).
		Complete(r)
}
