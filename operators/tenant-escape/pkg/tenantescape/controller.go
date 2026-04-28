// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package tenantescape

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/boundary"
)

// TenantBoundaryReconciler watches every TenantBoundary CR, refreshes
// the in-memory boundary index, and writes the resolved
// MatchedNamespaces / MatchedPods back to .status.
type TenantBoundaryReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Index  *boundary.Index
}

// Reconcile re-derives MatchedNamespaces from Spec.NamespaceSelector,
// updates Status, then refreshes the global index from the full CR
// list (one CR's status change can shift the overlap picture).
func (r *TenantBoundaryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	tb := &securityv1alpha1.TenantBoundary{}
	if err := r.Get(ctx, req.NamespacedName, tb); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		// Deleted → rebuild the index without it.
		if err := r.refreshIndex(ctx); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	matchedNS, matchedPods, err := r.resolveMatched(ctx, tb)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("resolve matched namespaces: %w", err)
	}

	now := metav1.Now()
	tb.Status.MatchedNamespaces = matchedNS
	tb.Status.MatchedPods = matchedPods
	tb.Status.LastReconcileAt = &now
	if err := r.Status().Update(ctx, tb); err != nil {
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	if err := r.refreshIndex(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// resolveMatched expands Spec.NamespaceSelector against the live
// Namespace list and counts the running Pods across the matches.
// Empty / nil selector ⇒ match-none (defensive default — the admin
// must opt namespaces in explicitly).
func (r *TenantBoundaryReconciler) resolveMatched(ctx context.Context, tb *securityv1alpha1.TenantBoundary) (matchedNamespaces []string, podCount int32, err error) {
	if tb.Spec.NamespaceSelector == nil ||
		(len(tb.Spec.NamespaceSelector.MatchLabels) == 0 && len(tb.Spec.NamespaceSelector.MatchExpressions) == 0) {
		return nil, 0, nil
	}
	sel, selErr := metav1.LabelSelectorAsSelector(tb.Spec.NamespaceSelector)
	if selErr != nil {
		return nil, 0, fmt.Errorf("parse namespaceSelector: %w", selErr)
	}
	var nsList corev1.NamespaceList
	if listErr := r.List(ctx, &nsList, &client.ListOptions{LabelSelector: sel}); listErr != nil {
		return nil, 0, fmt.Errorf("list namespaces: %w", listErr)
	}
	matchedNamespaces = make([]string, 0, len(nsList.Items))
	for ix := range nsList.Items {
		matchedNamespaces = append(matchedNamespaces, nsList.Items[ix].Name)
	}
	for _, ns := range matchedNamespaces {
		var pods corev1.PodList
		if listErr := r.List(ctx, &pods, client.InNamespace(ns), &client.ListOptions{LabelSelector: labels.Everything()}); listErr != nil {
			return nil, 0, fmt.Errorf("list pods in %s: %w", ns, listErr)
		}
		// #nosec G115 - pod count is bounded by API server limits, well within int32.
		podCount += int32(len(pods.Items))
	}
	return matchedNamespaces, podCount, nil
}

// refreshIndex rebuilds the global BoundarySet from every
// TenantBoundary CR in the cluster.
func (r *TenantBoundaryReconciler) refreshIndex(ctx context.Context) error {
	var list securityv1alpha1.TenantBoundaryList
	if err := r.List(ctx, &list); err != nil {
		return fmt.Errorf("list tenantboundaries: %w", err)
	}
	r.Index.Refresh(list.Items)
	return nil
}

// SetupWithManager registers the reconciler.
func (r *TenantBoundaryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.TenantBoundary{}).
		Complete(r)
}
