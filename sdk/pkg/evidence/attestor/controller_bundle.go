// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/logger"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

// AttestationBundleReconciler drives the Pending -> Sealed lifecycle.
//
// Iteration 3 (this commit): pipeline now passes through the full
// transparency-log step. The flow is:
//
//	Pending  -- Signer.Sign ------> envelope (Conditions: Signed=True)
//	         -- Logger.Log -------> log entry (Conditions: Logged=True)
//	         -- WORM archival ----> (skipped in this iter; WORMArchival=False
//	                                 Reason=NotImplemented Condition)
//	         -- mark parent Att'd
//	Sealed
//
// Phase ends as Sealed because all signed-and-logged information is in
// the bundle Status; the WORM upload of the DSSE envelope arrives in a
// follow-up commit. Verifiers should consult the WORMArchival Condition
// to know whether the persistence side is complete.
type AttestationBundleReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Signer       sign.Signer
	Logger       logger.Logger
	AttestorMeta sign.AttestorMeta
}

// Reconcile drives the pipeline for one AttestationBundle.
func (r *AttestationBundleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rlog := log.FromContext(ctx).WithValues("bundle", req.Name)

	if r.Signer == nil {
		return ctrl.Result{}, errors.New("AttestationBundleReconciler.Signer is nil; call SetupReconcilers")
	}
	if r.Logger == nil {
		return ctrl.Result{}, errors.New("AttestationBundleReconciler.Logger is nil; call SetupReconcilers")
	}

	bundle := &securityv1alpha1.AttestationBundle{}
	if err := r.Get(ctx, req.NamespacedName, bundle); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Already Sealed: idempotent no-op.
	if bundle.Status.Phase == securityv1alpha1.AttestationBundlePhaseSealed {
		return ctrl.Result{}, nil
	}

	now := metav1.Now()

	// Build the in-toto Statement for the parent CR.
	stmt, statementBytes, err := r.buildStatement(ctx, &bundle.Spec.AttestedFor, now)
	if err != nil {
		rlog.Error(err, "build statement failed")
		return ctrl.Result{}, err
	}

	// Statement digest.
	digest, err := stmt.SHA256()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("compute statement digest: %w", err)
	}

	// Sign the canonical Statement bytes via DSSE.
	envelope, err := r.Signer.Sign(ctx, statementBytes, sign.StatementMediaType)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("sign statement: %w", err)
	}
	if envelope == nil || len(envelope.Signatures) == 0 {
		return ctrl.Result{}, errors.New("signer returned empty envelope")
	}

	// Publish to the transparency log.
	logEntry, err := r.Logger.Log(ctx, envelope)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("publish to transparency log: %w", err)
	}
	if logEntry == nil {
		return ctrl.Result{}, errors.New("logger returned nil entry")
	}

	// Update bundle Status.
	patch := client.MergeFrom(bundle.DeepCopy())
	bundle.Status.Phase = securityv1alpha1.AttestationBundlePhaseSealed
	bundle.Status.StatementDigest = digest
	if bundle.Status.SignedAt == nil {
		bundle.Status.SignedAt = &now
	}
	bundle.Status.SealedAt = &now
	bundle.Status.Signature = &securityv1alpha1.SignatureInfo{
		Mode:  r.Signer.Mode(),
		KeyID: r.Signer.KeyID(),
	}
	bundle.Status.RekorEntry = &securityv1alpha1.RekorEntry{
		LogIndex: logEntry.LogIndex,
		UUID:     logEntry.UUID,
	}
	if logEntry.InclusionProof != nil {
		bundle.Status.RekorEntry.InclusionProof = &securityv1alpha1.InclusionProof{
			TreeSize: logEntry.InclusionProof.TreeSize,
			LogIndex: logEntry.InclusionProof.LogIndex,
			RootHash: logEntry.InclusionProof.RootHash,
			Hashes:   logEntry.InclusionProof.Hashes,
		}
	}
	bundle.Status.Conditions = mergeConditions(bundle.Status.Conditions,
		metav1.Condition{
			Type:               "Signed",
			Status:             metav1.ConditionTrue,
			Reason:             "SignerOK",
			Message:            fmt.Sprintf("DSSE envelope produced via %s", r.Signer.Mode()),
			LastTransitionTime: now,
		},
		metav1.Condition{
			Type:               "Logged",
			Status:             metav1.ConditionTrue,
			Reason:             "LoggerOK",
			Message:            fmt.Sprintf("logged at %s index=%d", r.Logger.Endpoint(), logEntry.LogIndex),
			LastTransitionTime: now,
		},
		metav1.Condition{
			Type:               "WORMArchival",
			Status:             metav1.ConditionFalse,
			Reason:             "NotImplemented",
			Message:            "WORM uploader pending; envelope not yet persisted off-cluster",
			LastTransitionTime: now,
		},
	)

	if err := r.Status().Patch(ctx, bundle, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch bundle status: %w", err)
	}
	rlog.Info("AttestationBundle Sealed",
		"digest", digest,
		"keyID", r.Signer.KeyID(),
		"mode", r.Signer.Mode(),
		"logEndpoint", r.Logger.Endpoint(),
		"logIndex", logEntry.LogIndex,
		"logUUID", logEntry.UUID,
	)

	if err := r.markParentAttested(ctx, bundle); err != nil {
		// Non-fatal: bundle is already Sealed; the parent can be patched
		// on the next reconcile of the bundle.
		rlog.Error(err, "mark parent Attested failed (will retry)")
	}
	return ctrl.Result{}, nil
}

// mergeConditions adds or replaces the given conditions in the slice
// (matched by Type), preserving any existing condition not being updated.
func mergeConditions(existing []metav1.Condition, news ...metav1.Condition) []metav1.Condition {
	out := make([]metav1.Condition, 0, len(existing)+len(news))
	skip := make(map[string]struct{}, len(news))
	for _, n := range news {
		skip[n.Type] = struct{}{}
	}
	for _, c := range existing {
		if _, replaced := skip[c.Type]; !replaced {
			out = append(out, c)
		}
	}
	out = append(out, news...)
	return out
}

// buildStatement fetches the parent CR and produces an in-toto Statement
// plus its canonical JSON bytes.
func (r *AttestationBundleReconciler) buildStatement(ctx context.Context, ref *corev1.ObjectReference, signedAt metav1.Time) (sign.Statement, []byte, error) {
	switch ref.Kind {
	case "SecurityEvent":
		se := &securityv1alpha1.SecurityEvent{}
		if err := r.Get(ctx, client.ObjectKey{Name: ref.Name}, se); err != nil {
			if apierrors.IsNotFound(err) {
				return sign.Statement{}, nil, fmt.Errorf("parent SecurityEvent %q not found", ref.Name)
			}
			return sign.Statement{}, nil, err
		}
		stmt, err := sign.BuildSecurityEventStatement(se, r.AttestorMeta, signedAt)
		if err != nil {
			return sign.Statement{}, nil, err
		}
		b, err := stmt.MarshalCanonical()
		return stmt, b, err
	case "EventResponse":
		er := &securityv1alpha1.EventResponse{}
		if err := r.Get(ctx, client.ObjectKey{Name: ref.Name}, er); err != nil {
			if apierrors.IsNotFound(err) {
				return sign.Statement{}, nil, fmt.Errorf("parent EventResponse %q not found", ref.Name)
			}
			return sign.Statement{}, nil, err
		}
		stmt, err := sign.BuildEventResponseStatement(er, r.AttestorMeta, signedAt)
		if err != nil {
			return sign.Statement{}, nil, err
		}
		b, err := stmt.MarshalCanonical()
		return stmt, b, err
	default:
		return sign.Statement{}, nil, fmt.Errorf("unsupported AttestedFor.Kind %q", ref.Kind)
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
		// EventResponse has no Phase=Attested; the bundle's existence and
		// its label ugallu.io/event-response-uid is the back-link. A future
		// iteration will record the digest in Conditions.
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
