// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

func TestBuildSecurityEventStatement_Schema(t *testing.T) {
	se := &securityv1alpha1.SecurityEvent{
		Spec: securityv1alpha1.SecurityEventSpec{
			Class:    securityv1alpha1.ClassDetection,
			Type:     securityv1alpha1.TypePrivilegedPodChange,
			Severity: securityv1alpha1.SeverityHigh,
			ClusterIdentity: securityv1alpha1.ClusterIdentity{
				ClusterName: "cluster-1",
				ClusterID:   "cid",
			},
			Source: securityv1alpha1.SourceRef{Kind: "Controller", Name: "ad"},
			Subject: securityv1alpha1.SubjectTier1{
				Kind: "Pod",
				Name: "p",
				Pod:  &securityv1alpha1.PodSubject{NodeName: "n"},
			},
			DetectedAt: metav1.Now(),
		},
	}
	se.Name = "se-statement"
	se.UID = "se-uid-1"

	att := sign.AttestorMeta{Name: "ugallu-attestor", Version: "v0.0.1-alpha", Instance: "att-pod-1"}
	stmt, err := sign.BuildSecurityEventStatement(se, att, metav1.Now())
	if err != nil {
		t.Fatalf("BuildSecurityEventStatement: %v", err)
	}

	if stmt.Type != sign.StatementType {
		t.Errorf("Type = %q, want %q", stmt.Type, sign.StatementType)
	}
	if stmt.PredicateType != sign.PredicateTypeSecurityEvent {
		t.Errorf("PredicateType = %q, want %q", stmt.PredicateType, sign.PredicateTypeSecurityEvent)
	}
	if len(stmt.Subject) != 1 {
		t.Fatalf("Subject len = %d, want 1", len(stmt.Subject))
	}
	wantName := sign.SubjectName("SecurityEvent", se.Name)
	if stmt.Subject[0].Name != wantName {
		t.Errorf("Subject[0].Name = %q, want %q", stmt.Subject[0].Name, wantName)
	}
	if d := stmt.Subject[0].Digest["sha256"]; len(d) != 64 {
		t.Errorf("Subject[0].Digest sha256 len = %d, want 64 hex chars", len(d))
	}

	digest, err := stmt.SHA256()
	if err != nil {
		t.Fatalf("SHA256: %v", err)
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != 7+64 {
		t.Errorf("SHA256 = %q, want sha256:<64 hex>", digest)
	}

	incident, ok := stmt.Predicate["incident"].(map[string]any)
	if !ok {
		t.Fatal("predicate.incident not a map")
	}
	if incident["securityEventUID"] != "se-uid-1" {
		t.Errorf("incident.securityEventUID = %v, want se-uid-1", incident["securityEventUID"])
	}
	if incident["type"] != securityv1alpha1.TypePrivilegedPodChange {
		t.Errorf("incident.type = %v", incident["type"])
	}
}

func TestBuildEventResponseStatement_Schema(t *testing.T) {
	er := &securityv1alpha1.EventResponse{
		Spec: securityv1alpha1.EventResponseSpec{
			SecurityEventRef: securityv1alpha1.SecurityEventRef{
				Name: "parent-se",
				UID:  "p-uid",
			},
			Responder: securityv1alpha1.ResponderRef{Kind: "Controller", Name: "forensics"},
			Action: securityv1alpha1.Action{
				Type: securityv1alpha1.ActionPodFreeze,
			},
		},
	}
	er.Name = "er-stmt"
	er.UID = "er-uid"

	att := sign.AttestorMeta{Name: "ugallu-attestor", Version: "v0.0.1-alpha"}
	stmt, err := sign.BuildEventResponseStatement(er, att, metav1.Now())
	if err != nil {
		t.Fatalf("BuildEventResponseStatement: %v", err)
	}

	if stmt.PredicateType != sign.PredicateTypeEventResponse {
		t.Errorf("PredicateType = %q", stmt.PredicateType)
	}
	resp, ok := stmt.Predicate["response"].(map[string]any)
	if !ok {
		t.Fatal("predicate.response not a map")
	}
	if resp["action"] != string(securityv1alpha1.ActionPodFreeze) {
		t.Errorf("response.action = %v", resp["action"])
	}
}
