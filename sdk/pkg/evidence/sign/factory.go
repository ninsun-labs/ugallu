// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"errors"
	"fmt"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// NewSigner returns a Signer for the requested mode. The empty mode and
// "ed25519-dev" both produce an in-process Ed25519 signer. Modes that
// require external infrastructure (Fulcio, OpenBao, dual) are stubbed
// as ErrNotImplemented in the current iteration.
func NewSigner(mode securityv1alpha1.SigningMode) (Signer, error) {
	switch mode {
	case "", securityv1alpha1.SigningModeEd25519Dev:
		return NewEd25519Signer()
	case securityv1alpha1.SigningModeFulcioKeyless:
		return nil, fmt.Errorf("%w: fulcio-keyless is implemented in a follow-up iteration", ErrNotImplemented)
	case securityv1alpha1.SigningModeOpenBaoTransit:
		return nil, fmt.Errorf("%w: openbao-transit is implemented in a follow-up iteration", ErrNotImplemented)
	case securityv1alpha1.SigningModeDual:
		return nil, fmt.Errorf("%w: dual signing is implemented in a follow-up iteration", ErrNotImplemented)
	default:
		return nil, fmt.Errorf("unknown signing mode %q", mode)
	}
}

// ErrNotImplemented is returned when a mode requested by config is not
// yet wired in the current build.
var ErrNotImplemented = errors.New("signing mode not implemented")
