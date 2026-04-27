// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// Spec constants for the in-toto Statement and the ugallu predicates
// (design 05 A3).
const (
	StatementType = "https://in-toto.io/Statement/v1"

	PredicateTypeSecurityEvent = "https://ugallu.io/attestation/security-event/v1"
	PredicateTypeEventResponse = "https://ugallu.io/attestation/event-response/v1"

	StatementMediaType = "application/vnd.in-toto+json"
)

// Statement is a slim in-toto Statement (v1).
type Statement struct {
	Type          string         `json:"_type"`
	Subject       []SubjectRef   `json:"subject"`
	PredicateType string         `json:"predicateType"`
	Predicate     map[string]any `json:"predicate"`
}

// SubjectRef references a single subject of the attestation.
type SubjectRef struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// AttestorMeta describes the attestor instance signing the statement
// (recorded in the predicate).
type AttestorMeta struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Instance string `json:"instance,omitempty"`
}

// MarshalCanonical serializes the Statement as JSON. It is not a full
// RFC 8785 canonicalizer; it relies on encoding/json's deterministic
// output for the Go types in use (no random-iteration maps in subject
// and predicate body apart from the Predicate map itself, which is
// sorted by encoding/json since Go 1.12).
func (s Statement) MarshalCanonical() ([]byte, error) {
	return json.Marshal(s)
}

// SHA256 returns the hex-encoded sha256 of the canonical statement JSON,
// prefixed with "sha256:". Used as Status.StatementDigest.
func (s Statement) SHA256() (string, error) {
	b, err := s.MarshalCanonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// BuildSecurityEventStatement produces an in-toto Statement attesting
// to a SecurityEvent. The subject digest is a sha256 of the canonical
// SE Spec JSON.
func BuildSecurityEventStatement(se *securityv1alpha1.SecurityEvent, attestor AttestorMeta, signedAt metav1.Time) (Statement, error) {
	specBytes, err := json.Marshal(se.Spec)
	if err != nil {
		return Statement{}, fmt.Errorf("marshal SE spec: %w", err)
	}
	specSum := sha256.Sum256(specBytes)
	specDigest := hex.EncodeToString(specSum[:])

	predicate := map[string]any{
		"incident": map[string]any{
			"securityEventUID": string(se.UID),
			"class":            string(se.Spec.Class),
			"type":             se.Spec.Type,
			"severity":         string(se.Spec.Severity),
			"detectedAt":       se.Spec.DetectedAt.Format(metav1.RFC3339Micro),
			"clusterIdentity":  se.Spec.ClusterIdentity,
		},
		"attestor": map[string]any{
			"name":       attestor.Name,
			"version":    attestor.Version,
			"instance":   attestor.Instance,
			"attestedAt": signedAt.Format(metav1.RFC3339Micro),
		},
		"tooling": map[string]any{
			"ugalluVersion":    attestor.Version,
			"signingPredicate": PredicateTypeSecurityEvent,
		},
	}

	return Statement{
		Type:          StatementType,
		Subject:       []SubjectRef{{Name: SubjectName("SecurityEvent", se.Name), Digest: map[string]string{"sha256": specDigest}}},
		PredicateType: PredicateTypeSecurityEvent,
		Predicate:     predicate,
	}, nil
}

// BuildEventResponseStatement produces an in-toto Statement attesting
// to an EventResponse.
func BuildEventResponseStatement(er *securityv1alpha1.EventResponse, attestor AttestorMeta, signedAt metav1.Time) (Statement, error) {
	specBytes, err := json.Marshal(er.Spec)
	if err != nil {
		return Statement{}, fmt.Errorf("marshal ER spec: %w", err)
	}
	specSum := sha256.Sum256(specBytes)
	specDigest := hex.EncodeToString(specSum[:])

	predicate := map[string]any{
		"response": map[string]any{
			"eventResponseUID":  string(er.UID),
			"securityEventName": er.Spec.SecurityEventRef.Name,
			"securityEventUID":  string(er.Spec.SecurityEventRef.UID),
			"action":            string(er.Spec.Action.Type),
			"responder":         er.Spec.Responder,
		},
		"attestor": map[string]any{
			"name":       attestor.Name,
			"version":    attestor.Version,
			"instance":   attestor.Instance,
			"attestedAt": signedAt.Format(metav1.RFC3339Micro),
		},
		"tooling": map[string]any{
			"signingPredicate": PredicateTypeEventResponse,
		},
	}

	return Statement{
		Type:          StatementType,
		Subject:       []SubjectRef{{Name: SubjectName("EventResponse", er.Name), Digest: map[string]string{"sha256": specDigest}}},
		PredicateType: PredicateTypeEventResponse,
		Predicate:     predicate,
	}, nil
}

// SubjectName produces a stable Subject.Name for the in-toto Statement.
// Format: "<Kind>/<name>@v1alpha1".
func SubjectName(kind, name string) string {
	return fmt.Sprintf("%s/%s@v1alpha1", kind, name)
}

// SubjectFromRef produces a stable Subject.Name from a corev1.ObjectReference.
func SubjectFromRef(ref *corev1.ObjectReference) string {
	return SubjectName(ref.Kind, ref.Name)
}
