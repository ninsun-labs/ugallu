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

// AttestationBundleTTLReconciler garbage-collects AttestationBundle
// CRs once they are Sealed and have aged past sealedAt + grace
// (parent TTL + 7d).
//
// The DSSE envelope persists in WORM independently of the CR (it was
// archived by the attestor). This reconciler only reclaims etcd by
// removing the CR; a final YAML snapshot is also archived for forensic
// reconstruction.
type AttestationBundleTTLReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	WormUploader worm.Uploader
	// Grace overrides the default sealed-to-archive grace window. When
	// zero, the loaded TTLConfig.bundleGrace is used (and falls back to
	// 7d when no TTLConfig exists).
	Grace              time.Duration
	TTLConfigNamespace string
}

// Reconcile evaluates the AB TTL state machine.
func (r *AttestationBundleTTLReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rlog := log.FromContext(ctx).WithValues("attestationbundle", req.Name)

	if r.WormUploader == nil {
		return ctrl.Result{}, fmt.Errorf("AttestationBundleTTLReconciler.WormUploader is nil; call SetupReconcilers")
	}

	bundle := &securityv1alpha1.AttestationBundle{}
	if err := r.Get(ctx, req.NamespacedName, bundle); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	annos := bundle.GetAnnotations()
	if isFrozen(annos) {
		return ctrl.Result{}, nil
	}

	// Bundle must be Sealed before deletion: the WORM archive of the
	// DSSE envelope must already exist.
	if bundle.Status.Phase != securityv1alpha1.AttestationBundlePhaseSealed {
		recordPostpone(kindAB, postponeReasonNotExpired)
		return ctrl.Result{RequeueAfter: time.Hour}, nil
	}

	cfg, err := loadEffectiveTTLConfig(ctx, r.Client, r.TTLConfigNamespace)
	if err != nil {
		recordFailure(kindAB, failureStageConfig)
		return ctrl.Result{}, fmt.Errorf("load TTLConfig: %w", err)
	}
	grace := r.Grace
	if grace <= 0 {
		grace = cfg.bundleGrace()
	}
	if d, ok := annotationOverrideTTL(annos); ok {
		grace = d
	}

	anchor := timeOrCreated(bundle.Status.SealedAt, bundle.CreationTimestamp)
	expiry := anchor.Add(grace)

	now := time.Now()
	if pp := postponedUntil(annos); !pp.IsZero() && pp.After(now) {
		recordPostpone(kindAB, postponeReasonAnnotation)
		return ctrl.Result{RequeueAfter: time.Until(pp)}, nil
	}
	if now.Before(expiry) {
		recordPostpone(kindAB, postponeReasonNotExpired)
		return ctrl.Result{RequeueAfter: time.Until(expiry)}, nil
	}

	pipelineStart := time.Now()
	ref, err := snapshotAndDelete(ctx, r.Client, r.WormUploader, bundle,
		"", now.Add(grace))
	if err != nil {
		recordFailure(kindAB, failureStageSnapshot)
		return ctrl.Result{}, err
	}
	recordArchive(kindAB, "", pipelineStart)
	rlog.Info("AttestationBundle archived to WORM and deleted",
		"wormURL", ref.URL,
		"wormSHA256", ref.SHA256,
		"size", ref.Size,
	)
	return ctrl.Result{}, nil
}

// SetupWithManager wires the reconciler with controller-runtime
// defaults. Prefer SetupWithManagerAndOptions in production wiring
// so TTLConfig.spec.worker tuning takes effect.
func (r *AttestationBundleTTLReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, controller.Options{})
}

// SetupWithManagerAndOptions registers the reconciler with the
// supplied controller.Options.
func (r *AttestationBundleTTLReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts controller.Options) error { //nolint:gocritic // mirrors controller-runtime's by-value Options API
	return ctrl.NewControllerManagedBy(mgr).
		Named("attestationbundle-ttl").
		For(&securityv1alpha1.AttestationBundle{}).
		WithOptions(opts).
		Complete(r)
}
