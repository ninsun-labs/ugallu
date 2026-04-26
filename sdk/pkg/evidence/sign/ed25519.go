// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// Ed25519Signer is a minimal Signer using an in-process Ed25519 keypair.
// For dev / test use only: the keypair lives in the process and is lost
// on restart; signatures verifiable across attestor restarts require
// the Fulcio or OpenBao back-ends.
type Ed25519Signer struct {
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	keyID string
}

// NewEd25519Signer generates a fresh Ed25519 keypair and returns a
// Signer that uses it.
func NewEd25519Signer() (*Ed25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return Ed25519FromKeys(pub, priv)
}

// Ed25519FromKeys returns a Signer wrapping the given keypair (test
// helper to enable deterministic signatures under known-seed keys).
func Ed25519FromKeys(pub ed25519.PublicKey, priv ed25519.PrivateKey) (*Ed25519Signer, error) {
	if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 keypair length")
	}
	sum := sha256.Sum256(pub)
	return &Ed25519Signer{
		pub:   pub,
		priv:  priv,
		keyID: "ed25519:" + hex.EncodeToString(sum[:8]),
	}, nil
}

// Sign produces a DSSE envelope.
func (s *Ed25519Signer) Sign(_ context.Context, payload []byte, payloadType string) (*SignedEnvelope, error) {
	pae := PAE(payloadType, payload)
	sig := ed25519.Sign(s.priv, pae)
	return &SignedEnvelope{
		PayloadType: payloadType,
		Payload:     payload,
		Signatures: []EnvelopeSignature{
			{KeyID: s.keyID, Sig: sig},
		},
	}, nil
}

// KeyID returns the stable identifier of the key.
func (s *Ed25519Signer) KeyID() string { return s.keyID }

// Mode returns the SigningMode for status reporting.
func (s *Ed25519Signer) Mode() securityv1alpha1.SigningMode {
	return securityv1alpha1.SigningModeEd25519Dev
}

// PublicKey returns the Ed25519 public key (for verifying tests).
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey { return s.pub }

// VerifyDSSE verifies a DSSE envelope was signed by the given Ed25519
// public key. Test helper.
func VerifyDSSE(pub ed25519.PublicKey, env *SignedEnvelope, expectedKeyID string) error {
	if env == nil || len(env.Signatures) == 0 {
		return errors.New("empty envelope")
	}
	pae := PAE(env.PayloadType, env.Payload)
	for _, sig := range env.Signatures {
		if sig.KeyID != expectedKeyID {
			continue
		}
		if ed25519.Verify(pub, pae, sig.Sig) {
			return nil
		}
		return errors.New("signature verification failed")
	}
	return errors.New("no signature for expected keyID")
}
