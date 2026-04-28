// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package forensics

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// TestEvalPredicate covers each branch of the trigger filter so a
// silent regression in the SE watcher doesn't quietly stop firing
// captures (or, worse, fire on every benign Detection).
func TestEvalPredicate(t *testing.T) {
	pod := func(t string, sev securityv1alpha1.Severity, attested bool, ns string) *securityv1alpha1.SecurityEvent {
		se := &securityv1alpha1.SecurityEvent{
			ObjectMeta: metav1.ObjectMeta{Name: "x"},
			Spec: securityv1alpha1.SecurityEventSpec{
				Class:    "Detection",
				Type:     t,
				Severity: sev,
				Subject:  securityv1alpha1.SubjectTier1{Kind: "Pod", Name: "p", Namespace: ns},
			},
		}
		if attested {
			se.Status.Phase = securityv1alpha1.SecurityEventPhaseAttested
		}
		return se
	}
	trig := &securityv1alpha1.ForensicsTrigger{
		Classes:         []securityv1alpha1.Class{"Detection"},
		MinSeverities:   []securityv1alpha1.Severity{"high", "critical"},
		RequireAttested: true,
	}
	whitelist := []string{securityv1alpha1.TypeClusterAdminGranted}

	cases := []struct {
		name string
		se   *securityv1alpha1.SecurityEvent
		want string
	}{
		{
			name: "matches",
			se:   pod(securityv1alpha1.TypeClusterAdminGranted, "high", true, "default"),
			want: "",
		},
		{
			name: "wrong class",
			se: &securityv1alpha1.SecurityEvent{
				Spec: securityv1alpha1.SecurityEventSpec{
					Class:    "Audit",
					Type:     securityv1alpha1.TypeClusterAdminGranted,
					Severity: "high",
					Subject:  securityv1alpha1.SubjectTier1{Kind: "Pod", Name: "p", Namespace: "default"},
				},
				Status: securityv1alpha1.SecurityEventStatus{Phase: securityv1alpha1.SecurityEventPhaseAttested},
			},
			want: "class_mismatch",
		},
		{
			name: "severity below min",
			se:   pod(securityv1alpha1.TypeClusterAdminGranted, "low", true, "default"),
			want: "severity_below_min",
		},
		{
			name: "type not whitelisted",
			se:   pod(securityv1alpha1.TypeKubernetesAPICall, "high", true, "default"),
			want: "type_not_whitelisted",
		},
		{
			name: "not attested",
			se:   pod(securityv1alpha1.TypeClusterAdminGranted, "critical", false, "default"),
			want: "not_attested",
		},
		{
			name: "non pod subject",
			se: &securityv1alpha1.SecurityEvent{
				Spec: securityv1alpha1.SecurityEventSpec{
					Class:    "Detection",
					Type:     securityv1alpha1.TypeClusterAdminGranted,
					Severity: "high",
					Subject:  securityv1alpha1.SubjectTier1{Kind: "Node", Name: "n", Namespace: ""},
				},
				Status: securityv1alpha1.SecurityEventStatus{Phase: securityv1alpha1.SecurityEventPhaseAttested},
			},
			want: "non_pod_subject",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalPredicate(tc.se, trig, whitelist)
			if got != tc.want {
				t.Errorf("evalPredicate = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEvalPredicate_NamespaceAllowlist isolates the allowlist
// branch since the test above defaults to empty allowlist
// (match-all).
func TestEvalPredicate_NamespaceAllowlist(t *testing.T) {
	se := &securityv1alpha1.SecurityEvent{
		Spec: securityv1alpha1.SecurityEventSpec{
			Class:    "Detection",
			Type:     securityv1alpha1.TypeClusterAdminGranted,
			Severity: "high",
			Subject:  securityv1alpha1.SubjectTier1{Kind: "Pod", Name: "p", Namespace: "kube-system"},
		},
		Status: securityv1alpha1.SecurityEventStatus{Phase: securityv1alpha1.SecurityEventPhaseAttested},
	}
	trig := &securityv1alpha1.ForensicsTrigger{
		Classes:            []securityv1alpha1.Class{"Detection"},
		MinSeverities:      []securityv1alpha1.Severity{"high"},
		RequireAttested:    true,
		NamespaceAllowlist: []string{"workload-a", "workload-b"},
	}
	if got := evalPredicate(se, trig, []string{securityv1alpha1.TypeClusterAdminGranted}); got != "namespace_filtered" {
		t.Errorf("evalPredicate = %q, want namespace_filtered", got)
	}
	se.Spec.Subject.Namespace = "workload-a"
	if got := evalPredicate(se, trig, []string{securityv1alpha1.TypeClusterAdminGranted}); got != "" {
		t.Errorf("evalPredicate = %q, want \"\"", got)
	}
}

// TestNewIncident_DerivesUID checks the deterministic UID derivation
// so re-runs on the same trigger SE produce the same incident UID
// (and therefore the same NetworkPolicy / S3 key).
func TestNewIncident_DerivesUID(t *testing.T) {
	se := &securityv1alpha1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{UID: "trigger-abcdef"},
		Spec: securityv1alpha1.SecurityEventSpec{
			Subject: securityv1alpha1.SubjectTier1{Kind: "Pod", Name: "p", Namespace: "default"},
		},
	}
	a := NewIncident(se)
	b := NewIncident(se)
	if a == nil || b == nil {
		t.Fatal("NewIncident returned nil")
	}
	if a.UID != b.UID {
		t.Errorf("UID drift: %s vs %s", a.UID, b.UID)
	}
	if len(a.UID) != 16 {
		t.Errorf("UID length = %d, want 16 (hex of 8 bytes)", len(a.UID))
	}
}

// TestNewIncident_RejectsNonPodSubject covers the defense-in-depth
// guard the predicate filter already enforces.
func TestNewIncident_RejectsNonPodSubject(t *testing.T) {
	se := &securityv1alpha1.SecurityEvent{
		Spec: securityv1alpha1.SecurityEventSpec{
			Subject: securityv1alpha1.SubjectTier1{Kind: "Node", Name: "n"},
		},
	}
	if got := NewIncident(se); got != nil {
		t.Errorf("NewIncident on Node subject = %+v, want nil", got)
	}
}
