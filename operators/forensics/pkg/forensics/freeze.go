// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CiliumNetworkPolicyGVK identifies the Cilium CRD the freezer
// builds via unstructured (avoiding a hard import on the cilium
// API module).
var CiliumNetworkPolicyGVK = schema.GroupVersionKind{
	Group:   "cilium.io",
	Version: "v2",
	Kind:    "CiliumNetworkPolicy",
}

// FrozenLabel is the Pod label forensics writes to mark a suspect.
// Admission policy 7 reserves writes to this label to the forensics
// SA; the corresponding (Cilium)NetworkPolicy selects on this label
// so the network isolation is keyed on the freeze itself, not on the
// pre-existing labels of the suspect (which the attacker may control).
const FrozenLabel = "ugallu.io/frozen"

// FrozenPodUIDLabel marks the (Cilium)NetworkPolicy with the suspect
// Pod's UID so manual unfreeze + crash recovery can find it cluster-
// wide without parsing names.
const FrozenPodUIDLabel = "ugallu.io/frozen-pod-uid"

// ManagedByValue is the label value the freeze step writes on the
// network policy so a `kubectl get cnp -l
// app.kubernetes.io/managed-by=ugallu-forensics` surfaces every
// active freeze.
const ManagedByValue = "ugallu-forensics"

// FreezerOptions configures a Freezer instance.
type FreezerOptions struct {
	// Client is a controller-runtime client with cluster-wide write
	// access to (Cilium)NetworkPolicies and patch access to Pods
	// (label only, gated by admission policy 7).
	Client client.Client

	// Backend selects which NetworkPolicy API to apply.
	Backend FreezeBackend

	// ForensicsNamespace is where the operator runs. Used as the
	// allowed-egress target in the policy template.
	ForensicsNamespace string

	// ForensicsAppLabel is the value forensics pods carry on
	// app.kubernetes.io/name, used as the egress endpoint selector.
	ForensicsAppLabel string
}

// Freezer applies (and removes) the network isolation + Pod label
// that compose a forensic freeze. Idempotent: re-applying produces
// the same NetworkPolicy + label state, so crash recovery can
// safely rerun the step.
type Freezer struct {
	opts FreezerOptions
}

// NewFreezer validates opts and returns a Freezer.
func NewFreezer(opts *FreezerOptions) (*Freezer, error) {
	if opts == nil || opts.Client == nil {
		return nil, errors.New("freezer: Client is required")
	}
	if opts.ForensicsNamespace == "" {
		return nil, errors.New("freezer: ForensicsNamespace is required")
	}
	if opts.ForensicsAppLabel == "" {
		opts.ForensicsAppLabel = "ugallu-forensics"
	}
	return &Freezer{opts: *opts}, nil
}

// Freeze isolates the supplied Pod by:
//  1. Patching the Pod with `ugallu.io/frozen=<pod-uid>` (admission
//     policy 7 enforces that only forensics writes this label).
//  2. Creating an idempotent (Cilium)NetworkPolicy that selects on
//     the same label, denies all ingress, and allows egress only to
//     the forensics workload (so the snapshot ephemeral container's
//     S3 traffic still reaches the operator-side WORM endpoint).
func (f *Freezer) Freeze(ctx context.Context, pod *corev1.Pod) error {
	if pod == nil || pod.UID == "" {
		return errors.New("freezer: pod with UID is required")
	}
	if err := f.labelPod(ctx, pod, string(pod.UID)); err != nil {
		return fmt.Errorf("label suspect: %w", err)
	}
	switch f.opts.Backend {
	case FreezeBackendCilium:
		return f.applyCiliumPolicy(ctx, pod)
	default:
		return f.applyCorePolicy(ctx, pod)
	}
}

// Unfreeze reverses Freeze: removes the Pod label and deletes the
// (Cilium)NetworkPolicy. Each step is delete-if-exists so the
// operator can replay it safely after a crash.
func (f *Freezer) Unfreeze(ctx context.Context, pod *corev1.Pod) error {
	if pod == nil {
		return errors.New("freezer: pod is required")
	}
	if err := f.labelPod(ctx, pod, ""); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("remove label: %w", err)
	}
	switch f.opts.Backend {
	case FreezeBackendCilium:
		return f.deleteCiliumPolicy(ctx, pod)
	default:
		return f.deleteCorePolicy(ctx, pod)
	}
}

// labelPod patches `metadata.labels[ugallu.io/frozen]` to value (or
// removes the label when value=="") via a JSON merge patch keyed on
// the Pod's resourceVersion. Uses strategic merge so concurrent
// unrelated label changes from the attacker survive (forensics owns
// only its own label).
func (f *Freezer) labelPod(ctx context.Context, pod *corev1.Pod, value string) error {
	patch, err := buildLabelPatch(value)
	if err != nil {
		return err
	}
	return f.opts.Client.Patch(ctx, pod, client.RawPatch(types.MergePatchType, patch))
}

// buildLabelPatch returns a JSON merge patch that sets or removes
// the frozen label. Using nil to remove keys via JSON merge patch is
// the standard pattern — null on a key clears it.
func buildLabelPatch(value string) ([]byte, error) {
	var labelsPatch map[string]any
	if value == "" {
		labelsPatch = map[string]any{FrozenLabel: nil}
	} else {
		labelsPatch = map[string]any{FrozenLabel: value}
	}
	return json.Marshal(map[string]any{
		"metadata": map[string]any{"labels": labelsPatch},
	})
}

// applyCorePolicy creates the v1 NetworkPolicy fallback. Idempotent
// via Server-Side Apply (or Create-then-Update if the object
// pre-exists with managed-by=forensics).
func (f *Freezer) applyCorePolicy(ctx context.Context, pod *corev1.Pod) error {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      f.policyName(pod),
			Namespace: pod.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": ManagedByValue,
				FrozenPodUIDLabel:              string(pod.UID),
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{FrozenLabel: string(pod.UID)},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": f.opts.ForensicsNamespace,
								},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app.kubernetes.io/name": f.opts.ForensicsAppLabel,
								},
							},
						},
					},
				},
			},
		},
	}
	return f.createOrUpdate(ctx, policy)
}

// applyCiliumPolicy creates the cilium.io/v2 CiliumNetworkPolicy
// equivalent, expressed via unstructured to keep this module free of
// the cilium API dependency. Same selector + same egress allowance
// as the core fallback.
func (f *Freezer) applyCiliumPolicy(ctx context.Context, pod *corev1.Pod) error {
	cnp := &unstructured.Unstructured{}
	cnp.SetGroupVersionKind(CiliumNetworkPolicyGVK)
	cnp.SetName(f.policyName(pod))
	cnp.SetNamespace(pod.Namespace)
	cnp.SetLabels(map[string]string{
		"app.kubernetes.io/managed-by": ManagedByValue,
		FrozenPodUIDLabel:              string(pod.UID),
	})
	if err := unstructured.SetNestedMap(cnp.Object, map[string]any{
		"endpointSelector": map[string]any{
			"matchLabels": map[string]any{FrozenLabel: string(pod.UID)},
		},
		"ingress": []any{},
		"egress": []any{
			map[string]any{
				"toEndpoints": []any{
					map[string]any{
						"matchLabels": map[string]any{
							"k8s:io.kubernetes.pod.namespace": f.opts.ForensicsNamespace,
							"app.kubernetes.io/name":          f.opts.ForensicsAppLabel,
						},
					},
				},
			},
		},
	}, "spec"); err != nil {
		return fmt.Errorf("build cilium spec: %w", err)
	}
	return f.createOrUpdate(ctx, cnp)
}

// deleteCorePolicy removes the v1 NetworkPolicy. NotFound is
// treated as success (the operator may be replaying a freeze that
// already cleaned up).
func (f *Freezer) deleteCorePolicy(ctx context.Context, pod *corev1.Pod) error {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: f.policyName(pod), Namespace: pod.Namespace},
	}
	if err := f.opts.Client.Delete(ctx, policy); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete networkpolicy: %w", err)
	}
	return nil
}

// deleteCiliumPolicy removes the CNP. Same NotFound-tolerance.
func (f *Freezer) deleteCiliumPolicy(ctx context.Context, pod *corev1.Pod) error {
	cnp := &unstructured.Unstructured{}
	cnp.SetGroupVersionKind(CiliumNetworkPolicyGVK)
	cnp.SetName(f.policyName(pod))
	cnp.SetNamespace(pod.Namespace)
	if err := f.opts.Client.Delete(ctx, cnp); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete ciliumnetworkpolicy: %w", err)
	}
	return nil
}

// createOrUpdate is the small idempotency primitive: create on
// first apply, no-op when the object already carries the same
// managed-by label (Sprint 3 will swap this for SSA proper).
func (f *Freezer) createOrUpdate(ctx context.Context, obj client.Object) error {
	if err := f.opts.Client.Create(ctx, obj); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create %T: %w", obj, err)
	}
	return nil
}

// policyName builds the deterministic NetworkPolicy name. The
// pod-UID prefix keeps the cluster-wide listing stable across
// recovery and avoids collisions when two pods of the same name
// freeze in different namespaces.
func (f *Freezer) policyName(pod *corev1.Pod) string {
	return fmt.Sprintf("ugallu-forensics-freeze-%s", pod.UID)
}
