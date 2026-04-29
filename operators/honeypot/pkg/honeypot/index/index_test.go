// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package index

import "testing"

func TestSet_LookupByKey(t *testing.T) {
	idx := New()
	idx.Set([]*Entry{
		{Key: Key{Resource: "secrets", Namespace: "team-a", Name: "decoy-creds"}, UID: "u-1", HoneypotConfig: "hp-1"},
	})
	if got := idx.Lookup("secrets", "team-a", "decoy-creds"); got == nil {
		t.Fatalf("Lookup miss")
	}
	if got := idx.Lookup("secrets", "team-a", "real-creds"); got != nil {
		t.Errorf("Lookup hit on non-decoy")
	}
	if got := idx.Lookup("configmaps", "team-a", "decoy-creds"); got != nil {
		t.Errorf("Lookup must filter on resource kind")
	}
}

func TestSet_CaseInsensitiveResource(t *testing.T) {
	idx := New()
	idx.Set([]*Entry{
		{Key: Key{Resource: "secrets", Namespace: "team-a", Name: "decoy"}},
	})
	if got := idx.Lookup("Secrets", "team-a", "decoy"); got == nil {
		t.Errorf("Lookup must lowercase the resource arg")
	}
}

func TestSet_LookupByUID(t *testing.T) {
	idx := New()
	idx.Set([]*Entry{
		{Key: Key{Resource: "secrets", Namespace: "team-a", Name: "decoy"}, UID: "u-42"},
	})
	if got := idx.LookupUID("u-42"); got == nil {
		t.Fatalf("LookupUID miss")
	}
	if got := idx.LookupUID("u-99"); got != nil {
		t.Errorf("LookupUID hit on missing UID")
	}
	if got := idx.LookupUID(""); got != nil {
		t.Errorf("LookupUID('') must return nil")
	}
}

func TestSet_AllowedActors(t *testing.T) {
	idx := New()
	idx.Set([]*Entry{
		{
			Key:            Key{Resource: "secrets", Namespace: "team-a", Name: "decoy"},
			HoneypotConfig: "hp-1",
			AllowedActors:  map[string]bool{"system:serviceaccount:backup:operator": true},
		},
	})
	if !idx.IsAllowedActor("hp-1", "system:serviceaccount:backup:operator") {
		t.Errorf("backup operator should be allowed")
	}
	if idx.IsAllowedActor("hp-1", "system:serviceaccount:other:bot") {
		t.Errorf("non-listed SA must not be allowed")
	}
	if idx.IsAllowedActor("", "system:serviceaccount:backup:operator") {
		t.Errorf("empty hp must short-circuit")
	}
}

func TestSet_ReplaceClearsOld(t *testing.T) {
	idx := New()
	idx.Set([]*Entry{
		{Key: Key{Resource: "secrets", Namespace: "team-a", Name: "first"}, UID: "u-1"},
	})
	if got := idx.Size(); got != 1 {
		t.Fatalf("Size=%d, want 1", got)
	}
	idx.Set([]*Entry{
		{Key: Key{Resource: "secrets", Namespace: "team-a", Name: "second"}, UID: "u-2"},
	})
	if got := idx.Lookup("secrets", "team-a", "first"); got != nil {
		t.Errorf("first decoy must be gone after Set replacement")
	}
	if got := idx.LookupUID("u-1"); got != nil {
		t.Errorf("first decoy UID must be gone after Set replacement")
	}
	if got := idx.Lookup("secrets", "team-a", "second"); got == nil {
		t.Errorf("second decoy must be present")
	}
}

func TestSet_IgnoresInvalidEntries(t *testing.T) {
	idx := New()
	idx.Set([]*Entry{
		nil,
		{Key: Key{Resource: "", Namespace: "team-a", Name: "x"}}, // empty resource
		{Key: Key{Resource: "secrets", Namespace: "team-a", Name: ""}},
		{Key: Key{Resource: "secrets", Namespace: "team-a", Name: "valid"}},
	})
	if got := idx.Size(); got != 1 {
		t.Errorf("Size=%d, want 1 (only the valid entry)", got)
	}
}
