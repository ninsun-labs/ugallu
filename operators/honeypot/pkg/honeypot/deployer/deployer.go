// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package deployer materialises HoneypotConfig.Spec.Decoys[] into
// live K8s resources (Secret, ServiceAccount in v1alpha1) and
// keeps the honeypot index in sync. Each decoy carries:
//   - label `ugallu.io/decoy=true`
//   - annotation `ugallu.io/honeypot-config=<cr-name>`
//   - ownerReference to the HoneypotConfig CR (cascade-delete)
package deployer

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/index"
)

// LabelDecoy + AnnotationConfig stamp every materialised decoy so
// the deployer can list/own them and so an admin can grep the
// cluster for honeypots.
const (
	LabelDecoy        = "ugallu.io/decoy"
	AnnotationConfig  = "ugallu.io/honeypot-config"
	finalizerHoneypot = "honeypot.ugallu.io/decoys-cleanup"
)

// HoneypotConfigReconciler reconciles HoneypotConfig CRs into live
// decoy resources + a refreshed index snapshot.
type HoneypotConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Index  *index.Index
}

// Reconcile is the controller-runtime entry point.
func (r *HoneypotConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	cfg := &securityv1alpha1.HoneypotConfig{}
	if err := r.Get(ctx, req.NamespacedName, cfg); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		// CR deleted → ownerReferences cascade-delete the decoys, the
		// index refresh below picks up the now-empty state.
		return ctrl.Result{}, r.refreshIndexFromAll(ctx)
	}

	deployed, err := r.materialiseDecoys(ctx, cfg)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("materialise decoys: %w", err)
	}

	now := metav1.Now()
	cfg.Status.DeployedDecoys = deployed
	cfg.Status.LastReconcileAt = &now
	if err := r.Status().Update(ctx, cfg); err != nil {
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	if err := r.refreshIndexFromAll(ctx); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// materialiseDecoys reconciles every Spec.Decoys entry to a live
// resource. Idempotent - Server-Side-Apply via Patch with manager
// `ugallu-honeypot-deployer` keeps the resource in sync.
func (r *HoneypotConfigReconciler) materialiseDecoys(ctx context.Context, cfg *securityv1alpha1.HoneypotConfig) ([]securityv1alpha1.DeployedDecoy, error) {
	out := make([]securityv1alpha1.DeployedDecoy, 0, len(cfg.Spec.Decoys))
	for ix := range cfg.Spec.Decoys {
		d := &cfg.Spec.Decoys[ix]
		obj, err := r.renderDecoy(cfg, d)
		if err != nil {
			return nil, fmt.Errorf("render %s/%s: %w", d.Namespace, d.Name, err)
		}
		if err := r.applyDecoy(ctx, obj); err != nil {
			return nil, fmt.Errorf("apply %s/%s: %w", d.Namespace, d.Name, err)
		}
		out = append(out, securityv1alpha1.DeployedDecoy{
			Kind:      d.Kind,
			Namespace: d.Namespace,
			Name:      d.Name,
			UID:       string(obj.GetUID()),
		})
	}
	return out, nil
}

// renderDecoy builds the K8s object for one Spec.Decoys entry.
func (r *HoneypotConfigReconciler) renderDecoy(cfg *securityv1alpha1.HoneypotConfig, d *securityv1alpha1.HoneypotDecoy) (client.Object, error) {
	meta := metav1.ObjectMeta{
		Name:      d.Name,
		Namespace: d.Namespace,
		Labels: map[string]string{
			LabelDecoy: "true",
		},
		Annotations: map[string]string{
			AnnotationConfig: cfg.Name,
		},
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion:         securityv1alpha1.GroupVersion.String(),
				Kind:               "HoneypotConfig",
				Name:               cfg.Name,
				UID:                cfg.UID,
				Controller:         ptrTo(true),
				BlockOwnerDeletion: ptrTo(true),
			},
		},
	}

	switch d.Kind {
	case "Secret":
		s := &corev1.Secret{ObjectMeta: meta, Type: corev1.SecretTypeOpaque}
		if len(d.Data) > 0 {
			s.StringData = make(map[string]string, len(d.Data))
			for k, v := range d.Data {
				s.StringData[k] = v
			}
		}
		return s, nil
	case "ServiceAccount":
		return &corev1.ServiceAccount{ObjectMeta: meta}, nil
	default:
		return nil, fmt.Errorf("unsupported decoy kind %q", d.Kind)
	}
}

// applyDecoy creates the resource if missing, updates it if drifted.
// Implementation is Get → Create-or-Update so the deployer remains
// idempotent across reconciles.
func (r *HoneypotConfigReconciler) applyDecoy(ctx context.Context, obj client.Object) error {
	key := client.ObjectKeyFromObject(obj)
	existing := obj.DeepCopyObject().(client.Object)
	if err := r.Get(ctx, key, existing); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		return r.Create(ctx, obj)
	}
	// Resource exists. Capture the live UID so the caller can record
	// it on Status.DeployedDecoys without a second round-trip.
	obj.SetUID(existing.GetUID())
	obj.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, obj)
}

// refreshIndexFromAll lists every HoneypotConfig + every materialised
// decoy and rebuilds the global index snapshot.
func (r *HoneypotConfigReconciler) refreshIndexFromAll(ctx context.Context) error {
	var list securityv1alpha1.HoneypotConfigList
	if err := r.List(ctx, &list); err != nil {
		return fmt.Errorf("list honeypotconfigs: %w", err)
	}
	entries := []*index.Entry{}
	for cx := range list.Items {
		cfg := &list.Items[cx]
		allowed := map[string]bool{}
		for _, a := range cfg.Spec.AllowlistedActors {
			allowed[a] = true
		}
		for _, d := range cfg.Status.DeployedDecoys {
			entries = append(entries, &index.Entry{
				Key: index.Key{
					Resource:  resourceFromKind(d.Kind),
					Namespace: d.Namespace,
					Name:      d.Name,
				},
				UID:            types.UID(d.UID),
				HoneypotConfig: cfg.Name,
				AllowedActors:  allowed,
				EmitOnRead:     cfg.Spec.EmitOnRead,
			})
		}
	}
	r.Index.Set(entries)
	return nil
}

// resourceFromKind maps the CRD enum to the audit-log resource form.
func resourceFromKind(kind string) string {
	switch kind {
	case "Secret":
		return "secrets"
	case "ServiceAccount":
		return "serviceaccounts"
	}
	return ""
}

// SetupWithManager registers the reconciler.
func (r *HoneypotConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.HoneypotConfig{}).
		Complete(r)
}

func ptrTo[T any](v T) *T { return &v }
