// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package logger_test

import (
	"context"
	"testing"

	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/logger"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

func TestStubLogger_Log_DeterministicUUID(t *testing.T) {
	signer, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	env, err := signer.Sign(context.Background(), []byte(`{"x":1}`), "application/json")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	stub := logger.NewStubLogger()
	first, err := stub.Log(context.Background(), env)
	if err != nil {
		t.Fatalf("first Log: %v", err)
	}
	second, err := stub.Log(context.Background(), env)
	if err != nil {
		t.Fatalf("second Log: %v", err)
	}
	if first.UUID != second.UUID {
		t.Errorf("UUID not deterministic: %q vs %q", first.UUID, second.UUID)
	}
	if second.LogIndex != first.LogIndex+1 {
		t.Errorf("LogIndex not monotonic: %d -> %d", first.LogIndex, second.LogIndex)
	}
}

func TestStubLogger_Log_DistinctEnvelopesDifferentUUID(t *testing.T) {
	signer, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	envA, _ := signer.Sign(context.Background(), []byte("a"), "x")
	envB, _ := signer.Sign(context.Background(), []byte("b"), "x")

	stub := logger.NewStubLogger()
	a, _ := stub.Log(context.Background(), envA)
	b, _ := stub.Log(context.Background(), envB)
	if a.UUID == b.UUID {
		t.Errorf("distinct envelopes produced same UUID %q", a.UUID)
	}
}

func TestStubLogger_Log_NilEnvelopeErrors(t *testing.T) {
	stub := logger.NewStubLogger()
	if _, err := stub.Log(context.Background(), nil); err == nil {
		t.Fatal("expected error on nil envelope")
	}
}

func TestStubLogger_Endpoint(t *testing.T) {
	if got := logger.NewStubLogger().Endpoint(); got != "stub:dev" {
		t.Errorf("Endpoint = %q, want stub:dev", got)
	}
}
