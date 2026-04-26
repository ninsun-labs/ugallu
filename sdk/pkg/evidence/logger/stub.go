// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

// StubLogger is an in-process transparency log replacement for dev / test.
// It is deterministic up to wall-clock time: for the same envelope, it
// always returns the same UUID; LogIndex is monotonic per process.
//
// Production deployments must use a real transparency log (RekorLogger
// arrives in a follow-up iteration).
type StubLogger struct {
	mu      sync.Mutex
	counter int64
	now     func() time.Time // overridable in tests
}

// NewStubLogger returns a StubLogger using time.Now for IntegratedTime.
func NewStubLogger() *StubLogger {
	return &StubLogger{now: time.Now}
}

// Log records the envelope and returns a synthetic LogEntry.
func (s *StubLogger) Log(_ context.Context, envelope *sign.SignedEnvelope) (*LogEntry, error) {
	if envelope == nil {
		return nil, fmt.Errorf("nil envelope")
	}
	s.mu.Lock()
	idx := atomic.AddInt64(&s.counter, 1)
	now := s.now()
	s.mu.Unlock()

	uuid, err := envelopeUUID(envelope)
	if err != nil {
		return nil, fmt.Errorf("compute envelope UUID: %w", err)
	}
	return &LogEntry{
		LogIndex:       idx,
		UUID:           uuid,
		IntegratedTime: now.Unix(),
	}, nil
}

// Endpoint returns the stub's identifier.
func (s *StubLogger) Endpoint() string { return "stub:dev" }

// envelopeUUID derives a UUID by hashing the canonical JSON of the
// envelope (deterministic for the same envelope).
func envelopeUUID(env *sign.SignedEnvelope) (string, error) {
	b, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
