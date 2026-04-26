// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// AttestationBundleReconciler drives the Pending -> Sealed lifecycle.
//
// SKELETON: this iteration skips the real Sign -> Log -> Archive pipeline
// and promotes Pending bundles directly to Sealed with a digest derived
// from the parent CR. Once the Signer interface (design 06) and the
// Rekor/WORM clients land, the reconciler will instead drive the bundle
// through Pending -> Signed -> Logged -> Sealed.
type AttestationBundleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile drives the pipeline for one AttestationBundle.
func (r *AttestationBundleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("bundle", req.Name)

	bundle := &securityv1alpha1.AttestationBundle{}
	if err := r.Get(ctx, req.NamespacedName, bundle); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Already done.
	if bundle.Status.Phase == securityv1alpha1.AttestationBundlePhaseSealed {
		return ctrl.Result{}, nil
	}

	// Compute placeholder digest from parent CR JSON.
	digest, err := r.parentDigest(ctx, &bundle.Spec.AttestedFor)
	if err != nil {
		logger.Error(err, "compute parent digest failed")
		return ctrl.Result{}, err
	}

	now := metav1.Now()
	patch := client.MergeFrom(bundle.DeepCopy())
	bundle.Status.Phase = securityv1alpha1.AttestationBundlePhaseSealed
	bundle.Status.StatementDigest = digest
	if bundle.Status.SignedAt == nil {
		bundle.Status.SignedAt = &now
	}
	bundle.Status.SealedAt = &now
	bundle.Status.Signature = &securityv1alpha1.SignatureInfo{
		Mode:  securityv1alpha1.SigningModeFulcioKeyless,
		KeyID: "skeleton-not-real",
	}

	if err := r.Status().Patch(ctx, bundle, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch bundle status: %w", err)
	}
	logger.Info("AttestationBundle Sealed (skeleton)", "digest", digest)

	if err := r.markParentAttested(ctx, bundle); err != nil {
		// Non-fatal: bundle is already Sealed; the parent can be patched on the
		// next reconcile of the bundle.
		logger.Error(err, "mark parent Attested failed (will retry)")
	}
	return ctrl.Result{}, nil
}

// parentDigest produces a stable sha256 over the parent CR's canonical
// JSON marshaling. For SecurityEvent and EventResponse this is the Spec
// only; for any other Kind the whole object is hashed.
func (r *AttestationBundleReconciler) parentDigest(ctx context.Context, ref *corev1.ObjectReference) (string, error) {
	switch ref.Kind {
	case "SecurityEvent":
		se := &securityv1alpha1.SecurityEvent{}
		if err := r.Get(ctx, client.ObjectKey{Name: ref.Name}, se); err != nil {
			if apierrors.IsNotFound(err) {
				return "sha256:parent-not-found", nil
			}
			return "", err
		}
		return canonicalDigest(se.Spec)
	case "EventResponse":
		er := &securityv1alpha1.EventResponse{}
		if err := r.Get(ctx, client.ObjectKey{Name: ref.Name}, er); err != nil {
			if apierrors.IsNotFound(err) {
				return "sha256:parent-not-found", nil
			}
			return "", err
		}
		return canonicalDigest(er.Spec)
	default:
		return "sha256:unsupported-kind-" + ref.Kind, nil
	}
}

// markParentAttested patches the parent SE / ER status to Attested.
func (r *AttestationBundleReconciler) markParentAttested(ctx context.Context, bundle *securityv1alpha1.AttestationBundle) error {
	switch bundle.Spec.AttestedFor.Kind {
	case "SecurityEvent":
		se := &securityv1alpha1.SecurityEvent{}
		if err := r.Get(ctx, client.ObjectKey{Name: bundle.Spec.AttestedFor.Name}, se); err != nil {
			return client.IgnoreNotFound(err)
		}
		if se.Status.Phase == securityv1alpha1.SecurityEventPhaseAttested ||
			se.Status.Phase == securityv1alpha1.SecurityEventPhaseArchived {
			return nil
		}
		patch := client.MergeFrom(se.DeepCopy())
		se.Status.Phase = securityv1alpha1.SecurityEventPhaseAttested
		se.Status.AttestationDigest = bundle.Status.StatementDigest
		se.Status.AttestationBundleRef = &corev1.ObjectReference{
			APIVersion: securityv1alpha1.GroupVersion.String(),
			Kind:       "AttestationBundle",
			Name:       bundle.Name,
			UID:        bundle.UID,
		}
		return r.Status().Patch(ctx, se, patch)
	case "EventResponse":
		er := &securityv1alpha1.EventResponse{}
		if err := r.Get(ctx, client.ObjectKey{Name: bundle.Spec.AttestedFor.Name}, er); err != nil {
			return client.IgnoreNotFound(err)
		}
		// EventResponse has no phase=Attested; we record the digest
		// in Conditions on a future iteration.
		return nil
	}
	return nil
}

// SetupWithManager wires the reconciler to a controller-runtime manager.
func (r *AttestationBundleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("attestationbundle").
		For(&securityv1alpha1.AttestationBundle{}).
		Complete(r)
}

func canonicalDigest(v any) (string, error) {
	// json.Marshal is stable per Go runtime version for the types we use
	// (no random-iteration maps in Spec). It is sufficient for the
	// skeleton; the real implementation will use a JSON canonicalizer.
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
