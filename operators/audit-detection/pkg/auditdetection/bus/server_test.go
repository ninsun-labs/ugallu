// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"testing"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection"
)

func TestFilterMatch_EmptyFilterMatchesAll(t *testing.T) {
	ev := &auditdetection.AuditEvent{Verb: "get"}
	if !filterMatch(&securityv1alpha1.AuditDetectionConsumerFilter{}, ev) {
		t.Errorf("empty filter must match")
	}
}

func TestFilterMatch_NamespaceRequired(t *testing.T) {
	f := &securityv1alpha1.AuditDetectionConsumerFilter{ObjectRefHasNamespace: true}

	cluster := &auditdetection.AuditEvent{Verb: "get"}
	if filterMatch(f, cluster) {
		t.Errorf("cluster-scoped event should be dropped")
	}
	ns := &auditdetection.AuditEvent{Verb: "get", ObjectRef: &auditdetection.ObjectReference{Namespace: "team-a"}}
	if !filterMatch(f, ns) {
		t.Errorf("namespaced event should pass")
	}
}

func TestFilterMatch_VerbAllowlist(t *testing.T) {
	f := &securityv1alpha1.AuditDetectionConsumerFilter{VerbAllowlist: []string{"create", "update"}}

	if filterMatch(f, &auditdetection.AuditEvent{Verb: "get"}) {
		t.Errorf("verb get should be dropped by create/update allowlist")
	}
	if !filterMatch(f, &auditdetection.AuditEvent{Verb: "create"}) {
		t.Errorf("verb create should pass")
	}
}

func TestNew_DefaultsRingBuffer(t *testing.T) {
	s, err := New(Config{ListenAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.cfg.RingBuffer != DefaultRingBuffer {
		t.Errorf("RingBuffer = %d, want %d", s.cfg.RingBuffer, DefaultRingBuffer)
	}
}

func TestNew_RejectsEmptyListenAddr(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Errorf("expected error on empty ListenAddr")
	}
}

func TestPublish_NoSubscribers_NoOps(t *testing.T) {
	s, err := New(Config{ListenAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Nil event must be safe.
	s.Publish(nil)
	// Real event with no subscribers must not panic.
	s.Publish(&auditdetection.AuditEvent{Verb: "get"})
}
