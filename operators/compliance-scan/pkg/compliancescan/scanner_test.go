// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package compliancescan

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// TestCELCustomScanner_FlagsRootPodsAndRWFS pins the two production
// failure modes the in-tree scanner catches.
func TestCELCustomScanner_FlagsRootPodsAndRWFS(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	rwroot := false
	pods := []*corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "root-pod"}, Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c"}}, // no securityContext → root, RW rootfs.
		}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ok-pod"}, Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)},
			Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: ptr(true)},
			}},
		}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rw-pod"}, Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)},
			Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &rwroot},
			}},
		}},
	}
	objs := []runtime.Object{}
	for _, p := range pods {
		objs = append(objs, p)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()

	s := &celCustomScanner{}
	out, err := s.Scan(context.Background(), c, &securityv1alpha1.ComplianceScanRunSpec{
		Backend: securityv1alpha1.ComplianceScanBackendCELCustom,
		Profile: "default",
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(out.Checks) != 3 {
		t.Fatalf("expected 3 checks, got %d", len(out.Checks))
	}
	if out.Checks[0].Outcome != "fail" {
		t.Errorf("root-pod check should fail; got %q", out.Checks[0].Outcome)
	}
	if out.Checks[1].Outcome != "fail" {
		t.Errorf("rw-rootfs check should fail; got %q", out.Checks[1].Outcome)
	}
}

// TestCELCustomScanner_AllCleanCluster covers the happy path where
// every pod is hardened.
func TestCELCustomScanner_AllCleanCluster(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ok"},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)},
			Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: ptr(true)},
			}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(pod).Build()
	s := &celCustomScanner{}
	out, err := s.Scan(context.Background(), c, &securityv1alpha1.ComplianceScanRunSpec{
		Backend: securityv1alpha1.ComplianceScanBackendCELCustom,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if out.Checks[0].Outcome != "pass" || out.Checks[1].Outcome != "pass" {
		t.Errorf("happy path should pass first two checks; got %+v / %+v", out.Checks[0].Outcome, out.Checks[1].Outcome)
	}
}

// TestDecorateWithMappings stamps each check with the framework
// metadata when a mapping matches.
func TestDecorateWithMappings(t *testing.T) {
	checks := []securityv1alpha1.ComplianceCheckResult{
		{CheckID: "ugallu.cel.pods-run-as-non-root", Outcome: "fail"},
		{CheckID: "no-mapping", Outcome: "pass"},
	}
	mappings := []securityv1alpha1.ControlMapping{
		{
			CheckID: "ugallu.cel.pods-run-as-non-root",
			Frameworks: []securityv1alpha1.FrameworkControl{
				{Name: "soc2", ControlID: "CC6.6"},
			},
		},
	}
	out := decorateWithMappings(checks, mappings)
	if len(out[0].Frameworks) != 1 || out[0].Frameworks[0].ControlID != "CC6.6" {
		t.Errorf("first check should be decorated: %+v", out[0])
	}
	if len(out[1].Frameworks) != 0 {
		t.Errorf("unmapped check should stay bare: %+v", out[1])
	}
}

func ptr(b bool) *bool { return &b }
