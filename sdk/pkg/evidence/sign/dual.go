// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"context"
	"errors"
	"fmt"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// DualSigner produces DSSE envelopes carrying signatures from two
// independent back-ends — typically Fulcio (keyless) + OpenBao
// (transit). Each leg signs the same PAE, and the resulting envelope
// has two EnvelopeSignatures whose KeyIDs let verifiers tell them
// apart.
//
// Verification semantics live in the consumer: dual mode supports
// either OR (any leg verifies) or AND (RequireAll, both legs must
// verify) policies. See DualModeConfig in v1alpha1.
type DualSigner struct {
	primary   Signer
	secondary Signer
}

// NewDualSigner returns a DualSigner that delegates to primary and
// secondary in that order. The primary signer's KeyID prefix wins for
// the composite KeyID() to keep dashboards stable, and its public key
// is the one PublicKeyPEM exposes for Rekor (Rekor accepts one
// verifier key per entry; the secondary key surfaces via its own
// KeyID in the envelope so verifiers can fetch it out-of-band).
func NewDualSigner(primary, secondary Signer) *DualSigner {
	return &DualSigner{primary: primary, secondary: secondary}
}

// Sign produces a DSSE envelope with signatures from both legs. Both
// legs must succeed; partial success is an error.
func (d *DualSigner) Sign(ctx context.Context, payload []byte, payloadType string) (*SignedEnvelope, error) {
	if d.primary == nil || d.secondary == nil {
		return nil, errors.New("dual signer: both legs must be configured")
	}
	primary, err := d.primary.Sign(ctx, payload, payloadType)
	if err != nil {
		return nil, fmt.Errorf("dual: primary (%s): %w", d.primary.Mode(), err)
	}
	secondary, err := d.secondary.Sign(ctx, payload, payloadType)
	if err != nil {
		return nil, fmt.Errorf("dual: secondary (%s): %w", d.secondary.Mode(), err)
	}
	if len(primary.Signatures) == 0 || len(secondary.Signatures) == 0 {
		return nil, errors.New("dual: a leg returned an envelope with no signatures")
	}
	return &SignedEnvelope{
		PayloadType: payloadType,
		Payload:     payload,
		Signatures: []EnvelopeSignature{
			primary.Signatures[0],
			secondary.Signatures[0],
		},
	}, nil
}

// KeyID returns a composite identifier of the form
// "dual:<primary-keyid>+<secondary-keyid>" so consumers can identify
// the two legs at a glance.
func (d *DualSigner) KeyID() string {
	if d.primary == nil || d.secondary == nil {
		return "dual:incomplete"
	}
	return "dual:" + d.primary.KeyID() + "+" + d.secondary.KeyID()
}

// Mode reports dual.
func (d *DualSigner) Mode() securityv1alpha1.SigningMode {
	return securityv1alpha1.SigningModeDual
}

// PublicKeyPEM forwards to the primary leg when it implements the
// exporter — Rekor entries carry a single verifier key, so only the
// leg most likely to drive transparency-log verification is exposed
// here (Fulcio in the typical deployment).
func (d *DualSigner) PublicKeyPEM() ([]byte, error) {
	exp, ok := d.primary.(PublicKeyExporter)
	if !ok {
		return nil, fmt.Errorf("dual: primary signer (%T) does not export a public key", d.primary)
	}
	return exp.PublicKeyPEM()
}

// SecondaryPublicKeyPEM returns the secondary leg's public key when
// available. Used by callers that want to record both verifier keys
// alongside the bundle (e.g. WORM annotations).
func (d *DualSigner) SecondaryPublicKeyPEM() ([]byte, error) {
	exp, ok := d.secondary.(PublicKeyExporter)
	if !ok {
		return nil, fmt.Errorf("dual: secondary signer (%T) does not export a public key", d.secondary)
	}
	return exp.PublicKeyPEM()
}

// Compile-time assertion: DualSigner satisfies Signer + PublicKeyExporter.
var (
	_ Signer            = (*DualSigner)(nil)
	_ PublicKeyExporter = (*DualSigner)(nil)
)
