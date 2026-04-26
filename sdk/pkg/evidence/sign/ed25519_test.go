// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

func TestEd25519Signer_SignVerifyRoundtrip(t *testing.T) {
	signer, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	if !strings.HasPrefix(signer.KeyID(), "ed25519:") {
		t.Errorf("KeyID = %q, want ed25519: prefix", signer.KeyID())
	}

	payload := []byte(`{"hello":"world"}`)
	env, err := signer.Sign(context.Background(), payload, "application/vnd.in-toto+json")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if env.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("PayloadType = %q", env.PayloadType)
	}
	if !bytes.Equal(env.Payload, payload) {
		t.Errorf("Payload mismatch")
	}
	if len(env.Signatures) != 1 {
		t.Fatalf("Signatures len = %d, want 1", len(env.Signatures))
	}
	if env.Signatures[0].KeyID != signer.KeyID() {
		t.Errorf("Signatures[0].KeyID = %q, want %q", env.Signatures[0].KeyID, signer.KeyID())
	}

	if err := sign.VerifyDSSE(signer.PublicKey(), env, signer.KeyID()); err != nil {
		t.Errorf("VerifyDSSE: %v", err)
	}
}

func TestEd25519Signer_TamperedPayloadFailsVerify(t *testing.T) {
	signer, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	env, err := signer.Sign(context.Background(), []byte("original"), "x")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Tamper with the payload.
	env.Payload = []byte("tampered")
	if err := sign.VerifyDSSE(signer.PublicKey(), env, signer.KeyID()); err == nil {
		t.Fatal("VerifyDSSE on tampered payload should fail")
	}
}

func TestEd25519Signer_WrongKeyFailsVerify(t *testing.T) {
	signer, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	env, err := signer.Sign(context.Background(), []byte("p"), "x")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	if err := sign.VerifyDSSE(otherPub, env, signer.KeyID()); err == nil {
		t.Fatal("VerifyDSSE with wrong public key should fail")
	}
}

func TestEd25519FromKeys_RejectsBadLengths(t *testing.T) {
	_, err := sign.Ed25519FromKeys(make(ed25519.PublicKey, 5), make(ed25519.PrivateKey, 5))
	if err == nil {
		t.Fatal("Ed25519FromKeys with bad lengths should error")
	}
}
