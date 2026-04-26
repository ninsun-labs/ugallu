// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"context"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// SignedEnvelope is a DSSE-formatted signed payload.
//
// JSON serialization of an Envelope conforms to the DSSE spec: payload
// and signature bytes are base64-encoded. The Go struct holds raw bytes
// so callers do not have to decode/encode at every step.
type SignedEnvelope struct {
	PayloadType string              `json:"payloadType"`
	Payload     []byte              `json:"payload"`
	Signatures  []EnvelopeSignature `json:"signatures"`
}

// EnvelopeSignature is one signature in a DSSE envelope.
type EnvelopeSignature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

// Signer abstracts the signing back-end. Implementations:
//   - Ed25519Signer (sign/ed25519.go)            in-process keypair, dev/test only
//   - FulcioSigner  (sign/fulcio.go, next round) keyless via OIDC + Fulcio CA
//   - OpenBaoSigner (sign/openbao.go, later)     OpenBao transit
//
// Sign accepts the canonicalized payload and the payload media type
// (typically "application/vnd.in-toto+json") and returns a complete
// envelope. Implementations are responsible for computing PAE and any
// required encoding.
type Signer interface {
	Sign(ctx context.Context, payload []byte, payloadType string) (*SignedEnvelope, error)
	KeyID() string
	Mode() securityv1alpha1.SigningMode
}
