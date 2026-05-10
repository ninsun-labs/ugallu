// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package ttl

import (
	"context"
	"fmt"
	"sync"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// Watchdog defaults.
const (
	AttestorLeaseName         = "ugallu-attestor-leader"
	DefaultLeaseStaleAfter    = 5 * time.Minute
	DefaultWatchdogDedup      = 5 * time.Minute
	DefaultLeaseProbeInterval = time.Minute
)

// AttestorWatchdogReconciler watches the attestor's leader-election
// Lease and emits anomaly SecurityEvents when the attestor falls
// behind on its renewal cadence.
//
// Emission is deduplicated within DedupWindow so a sustained outage
// produces at most one SE per window. On recovery (a fresh renewTime
// after a previously-stale state), an AttestorRecovered SE is emitted
// so downstream consumers can clear backpressure.
type AttestorWatchdogReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	LeaseNamespace string

	// StaleAfter is the maximum allowed gap between Lease.Spec.RenewTime
	// and now() before the attestor is treated as down. Defaults to 5m.
	StaleAfter time.Duration

	// DedupWindow caps the rate at which anomaly events are emitted for
	// the same outage. Defaults to 5m.
	DedupWindow time.Duration

	// ProbeInterval controls how often Reconcile re-checks the Lease in
	// the absence of a Lease event (necessary because a stale Lease
	// generates no events). Defaults to 1m.
	ProbeInterval time.Duration

	mu    sync.Mutex
	state watchdogState
}

type watchdogState struct {
	down     bool
	lastEmit time.Time
}

// Reconcile evaluates the attestor's Lease freshness.
func (r *AttestorWatchdogReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rlog := log.FromContext(ctx).WithValues("lease", req.NamespacedName)

	ns := r.namespace()
	if req.Name != AttestorLeaseName || req.Namespace != ns {
		return ctrl.Result{}, nil
	}

	lease := &coordinationv1.Lease{}
	err := r.Get(ctx, req.NamespacedName, lease)
	switch {
	case err == nil:
		// fall through
	case apierrors.IsNotFound(err):
		// No Lease yet — attestor never came up. Treat as stale.
		return r.handleStale(ctx, time.Time{})
	default:
		return ctrl.Result{}, fmt.Errorf("get attestor Lease: %w", err)
	}

	var renew time.Time
	if lease.Spec.RenewTime != nil {
		renew = lease.Spec.RenewTime.Time
	}
	if r.isStale(renew) {
		rlog.V(1).Info("attestor Lease is stale", "renewTime", renew)
		return r.handleStale(ctx, renew)
	}
	return r.handleFresh(ctx, renew)
}

// isStale reports whether the given renewTime is older than StaleAfter.
func (r *AttestorWatchdogReconciler) isStale(renew time.Time) bool {
	threshold := r.StaleAfter
	if threshold <= 0 {
		threshold = DefaultLeaseStaleAfter
	}
	return renew.IsZero() || time.Since(renew) > threshold
}

// handleStale emits an AttestorUnavailable SE if dedup permits.
func (r *AttestorWatchdogReconciler) handleStale(ctx context.Context, renew time.Time) (ctrl.Result, error) {
	dedup := r.dedupWindow()

	r.mu.Lock()
	now := time.Now()
	emit := !r.state.down || now.Sub(r.state.lastEmit) >= dedup
	if emit {
		r.state.down = true
		r.state.lastEmit = now
	}
	r.mu.Unlock()

	if emit {
		if err := r.emitSE(ctx,
			securityv1alpha1.TypeAttestorUnavailable,
			securityv1alpha1.SeverityHigh,
			fmt.Sprintf("attestor Lease stale; renewTime=%s", renew.Format(time.RFC3339)),
		); err != nil {
			// Roll back the emit marker so the next reconcile re-tries.
			r.mu.Lock()
			r.state.lastEmit = time.Time{}
			r.mu.Unlock()
			return ctrl.Result{}, err
		}
	}
	setWatchdogUnavailable(true)
	return ctrl.Result{RequeueAfter: r.probeInterval()}, nil
}

// handleFresh notes recovery and, when the watchdog was previously
// down, emits an AttestorRecovered SE.
func (r *AttestorWatchdogReconciler) handleFresh(ctx context.Context, renew time.Time) (ctrl.Result, error) {
	r.mu.Lock()
	wasDown := r.state.down
	if wasDown {
		r.state.down = false
		r.state.lastEmit = time.Now()
	}
	r.mu.Unlock()

	if wasDown {
		if err := r.emitSE(ctx,
			securityv1alpha1.TypeAttestorRecovered,
			securityv1alpha1.SeverityInfo,
			fmt.Sprintf("attestor Lease fresh again; renewTime=%s", renew.Format(time.RFC3339)),
		); err != nil {
			return ctrl.Result{}, err
		}
	}
	setWatchdogUnavailable(false)
	return ctrl.Result{RequeueAfter: r.probeInterval()}, nil
}

// emitSE creates an anomaly SecurityEvent describing the attestor state.
func (r *AttestorWatchdogReconciler) emitSE(ctx context.Context, t string, sev securityv1alpha1.Severity, msg string) error {
	se := &securityv1alpha1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "attestor-watchdog-",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "ugallu-ttl",
				"ugallu.io/watchdog":           "attestor",
			},
		},
		Spec: securityv1alpha1.SecurityEventSpec{
			Class:    securityv1alpha1.ClassAnomaly,
			Type:     t,
			Severity: sev,
			ClusterIdentity: securityv1alpha1.ClusterIdentity{
				ClusterName: "local",
			},
			Source: securityv1alpha1.SourceRef{
				Kind: "Controller",
				Name: "ugallu-ttl",
			},
			Subject: securityv1alpha1.SubjectTier1{
				Kind: "External",
				Name: "ugallu-attestor",
				External: &securityv1alpha1.ExternalSubject{
					Kind:     "ExternalEndpoint",
					Identity: "ugallu-attestor",
					Source:   "ugallu-ttl-watchdog",
				},
			},
			DetectedAt: metav1.Now(),
			Signals:    map[string]string{"message": msg},
		},
	}
	if err := r.Create(ctx, se); err != nil {
		return fmt.Errorf("create watchdog SE: %w", err)
	}
	return nil
}

func (r *AttestorWatchdogReconciler) namespace() string {
	if r.LeaseNamespace == "" {
		return DefaultTTLConfigNamespace
	}
	return r.LeaseNamespace
}

func (r *AttestorWatchdogReconciler) dedupWindow() time.Duration {
	if r.DedupWindow <= 0 {
		return DefaultWatchdogDedup
	}
	return r.DedupWindow
}

func (r *AttestorWatchdogReconciler) probeInterval() time.Duration {
	if r.ProbeInterval <= 0 {
		return DefaultLeaseProbeInterval
	}
	return r.ProbeInterval
}

// SetupWithManager wires the reconciler. We filter to the single
// attestor Lease at the controller level via a name+namespace
// predicate so the reconcile budget isn't spent on every Lease in the
// cluster.
func (r *AttestorWatchdogReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ns := r.namespace()
	leaseFilter := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetName() == AttestorLeaseName && obj.GetNamespace() == ns
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("attestor-watchdog").
		For(&coordinationv1.Lease{}, builder.WithPredicates(leaseFilter)).
		Complete(r)
}
