// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package seccompgen

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestSelectPods_RatioLeavesOneUntrained pins the production-friendly
// invariant: even at ratio=100% the engine leaves a control group
// when the workload has 2+ replicas.
func TestSelectPods_RatioLeavesOneUntrained(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	pods := []*corev1.Pod{
		mkPod("ns", "a", map[string]string{"app": "x"}),
		mkPod("ns", "b", map[string]string{"app": "x"}),
		mkPod("ns", "c", map[string]string{"app": "x"}),
	}
	objs := []runtime.Object{}
	for _, p := range pods {
		objs = append(objs, p)
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()
	r := &TrainingRunReconciler{Client: fc, Scheme: scheme}

	got, err := r.selectPods(context.Background(), "ns", labels.SelectorFromSet(labels.Set{"app": "x"}), 100)
	if err != nil {
		t.Fatalf("selectPods: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("ratio=100 with 3 pods should pick 2 (leave one untrained); got %d", len(got))
	}
}

// TestSelectPods_RatioRoundsUp confirms the (N*ratio+99)/100 rule
// produces at least one match for tiny replica counts.
func TestSelectPods_RatioRoundsUp(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fc := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(
		mkPod("ns", "only", map[string]string{"app": "y"}),
	).Build()
	r := &TrainingRunReconciler{Client: fc, Scheme: scheme}

	got, err := r.selectPods(context.Background(), "ns", labels.SelectorFromSet(labels.Set{"app": "y"}), 1)
	if err != nil {
		t.Fatalf("selectPods: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("single pod + ratio=1%% should still pick 1; got %d", len(got))
	}
}

func mkPod(ns, name string, lbls map[string]string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: lbls}}
}
