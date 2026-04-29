// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"testing"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/honeypot/pkg/honeypot/index"
)

func indexWithSecretDecoy(t *testing.T) *index.Index {
	t.Helper()
	idx := index.New()
	idx.Set([]*index.Entry{
		{
			Key:            index.Key{Resource: "secrets", Namespace: "team-a", Name: "decoy-creds"},
			UID:            "secret-uid",
			HoneypotConfig: "hp-1",
			AllowedActors:  map[string]bool{"system:serviceaccount:backup:operator": true},
			EmitOnRead:     true,
		},
		{
			Key:            index.Key{Resource: "serviceaccounts", Namespace: "team-a", Name: "decoy-uploader"},
			UID:            "sa-uid",
			HoneypotConfig: "hp-1",
			EmitOnRead:     true,
		},
	})
	return idx
}

// --- Triggered ----------------------------------------------------

func TestHoneypotTriggered_FiresOnRead(t *testing.T) {
	idx := indexWithSecretDecoy(t)
	in := &AuditInput{
		Verb:            "get",
		UserUsername:    "system:serviceaccount:team-a:bot",
		ObjectResource:  "secrets",
		ObjectNamespace: "team-a",
		ObjectName:      "decoy-creds",
	}
	got := NewHoneypotTriggeredDetector(idx).Evaluate(in)
	if !got.Has() {
		t.Fatalf("expected fire, got none")
	}
	if got.Type != securityv1alpha1.TypeHoneypotTriggered {
		t.Errorf("Type = %q, want HoneypotTriggered", got.Type)
	}
	if got.Severity != string(securityv1alpha1.SeverityCritical) {
		t.Errorf("severity = %q, want critical", got.Severity)
	}
}

func TestHoneypotTriggered_AllowlistedSAFilters(t *testing.T) {
	idx := indexWithSecretDecoy(t)
	in := &AuditInput{
		Verb:            "get",
		UserUsername:    "system:serviceaccount:backup:operator",
		ObjectResource:  "secrets",
		ObjectNamespace: "team-a",
		ObjectName:      "decoy-creds",
	}
	if got := NewHoneypotTriggeredDetector(idx).Evaluate(in); got.Has() {
		t.Errorf("allowlisted SA must not fire: %+v", got)
	}
}

func TestHoneypotTriggered_NonDecoyResource(t *testing.T) {
	idx := indexWithSecretDecoy(t)
	in := &AuditInput{
		Verb:            "get",
		UserUsername:    "system:serviceaccount:team-a:bot",
		ObjectResource:  "secrets",
		ObjectNamespace: "team-a",
		ObjectName:      "real-creds",
	}
	if got := NewHoneypotTriggeredDetector(idx).Evaluate(in); got.Has() {
		t.Errorf("non-decoy must not fire")
	}
}

func TestHoneypotTriggered_EmitOnReadFalseSkipsReadVerbs(t *testing.T) {
	idx := index.New()
	idx.Set([]*index.Entry{
		{
			Key:            index.Key{Resource: "secrets", Namespace: "team-a", Name: "decoy"},
			HoneypotConfig: "hp-quiet",
			EmitOnRead:     false,
		},
	})
	getInput := &AuditInput{
		Verb: "get", ObjectResource: "secrets", ObjectNamespace: "team-a", ObjectName: "decoy",
	}
	if got := NewHoneypotTriggeredDetector(idx).Evaluate(getInput); got.Has() {
		t.Errorf("EmitOnRead=false must skip get")
	}
	updateInput := &AuditInput{
		Verb: "update", ObjectResource: "secrets", ObjectNamespace: "team-a", ObjectName: "decoy",
	}
	if got := NewHoneypotTriggeredDetector(idx).Evaluate(updateInput); !got.Has() {
		t.Errorf("EmitOnRead=false must still fire on mutating verbs")
	}
}

func TestHoneypotTriggered_LookupByUIDPreferred(t *testing.T) {
	idx := indexWithSecretDecoy(t)
	// Different name (e.g. attacker recreated the decoy with same
	// UID before the audit log lands) but UID matches.
	in := &AuditInput{
		Verb:            "delete",
		ObjectResource:  "secrets",
		ObjectNamespace: "team-a",
		ObjectName:      "spoofed-name",
		ObjectUID:       "secret-uid",
	}
	if got := NewHoneypotTriggeredDetector(idx).Evaluate(in); !got.Has() {
		t.Errorf("UID-based lookup must hit even when name differs")
	}
}

// --- Misplaced ----------------------------------------------------

func TestHoneypotMisplaced_FiresOnVolumeMount(t *testing.T) {
	idx := indexWithSecretDecoy(t)
	body := `{"spec":{"volumes":[{"name":"creds","secret":{"secretName":"decoy-creds"}}]}}`
	in := &AuditInput{
		Verb:            "create",
		ObjectResource:  "pods",
		ObjectNamespace: "team-a",
		ObjectName:      "exfil-pod",
		RequestObject:   []byte(body),
	}
	got := NewHoneypotMisplacedDetector(idx).Evaluate(in)
	if !got.Has() {
		t.Fatalf("expected fire on volume mount")
	}
	if got.Type != securityv1alpha1.TypeHoneypotMisplaced {
		t.Errorf("Type = %q", got.Type)
	}
	if got.Signals["decoy.name"] != "decoy-creds" {
		t.Errorf("decoy.name = %q, want decoy-creds", got.Signals["decoy.name"])
	}
}

func TestHoneypotMisplaced_FiresOnEnvFrom(t *testing.T) {
	idx := indexWithSecretDecoy(t)
	body := `{"spec":{"containers":[{"envFrom":[{"secretRef":{"name":"decoy-creds"}}]}]}}`
	in := &AuditInput{
		Verb:            "create",
		ObjectResource:  "pods",
		ObjectNamespace: "team-a",
		RequestObject:   []byte(body),
	}
	if got := NewHoneypotMisplacedDetector(idx).Evaluate(in); !got.Has() {
		t.Errorf("expected fire on envFrom secretRef")
	}
}

func TestHoneypotMisplaced_FiresOnServiceAccount(t *testing.T) {
	idx := indexWithSecretDecoy(t)
	body := `{"spec":{"serviceAccountName":"decoy-uploader"}}`
	in := &AuditInput{
		Verb:            "create",
		ObjectResource:  "pods",
		ObjectNamespace: "team-a",
		RequestObject:   []byte(body),
	}
	if got := NewHoneypotMisplacedDetector(idx).Evaluate(in); !got.Has() {
		t.Errorf("expected fire on serviceAccountName decoy")
	}
}

func TestHoneypotMisplaced_RealReferencesSkipped(t *testing.T) {
	idx := indexWithSecretDecoy(t)
	body := `{"spec":{"volumes":[{"name":"creds","secret":{"secretName":"real-creds"}}]}}`
	in := &AuditInput{
		Verb:            "create",
		ObjectResource:  "pods",
		ObjectNamespace: "team-a",
		RequestObject:   []byte(body),
	}
	if got := NewHoneypotMisplacedDetector(idx).Evaluate(in); got.Has() {
		t.Errorf("real secret reference must not fire")
	}
}
