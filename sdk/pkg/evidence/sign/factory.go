// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"context"
	"errors"
	"fmt"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// FactoryOptions carries the per-mode configuration consumed by
// NewSigner. Fields are mode-specific; only the relevant subset is
// read for the requested mode.
type FactoryOptions struct {
	// OpenBao is consulted when mode == openbao-transit (or dual).
	OpenBao *OpenBaoSignerOptions
}

// NewSigner returns a Signer for the requested mode.
//   - "" / ed25519-dev   → in-process Ed25519 keypair (test only).
//   - openbao-transit    → OpenBaoSigner; opts.OpenBao must be set.
//   - fulcio-keyless     → ErrNotImplemented (Sprint 2 follow-up).
//   - dual               → ErrNotImplemented (Sprint 2 follow-up).
func NewSigner(ctx context.Context, mode securityv1alpha1.SigningMode, opts *FactoryOptions) (Signer, error) {
	switch mode {
	case "", securityv1alpha1.SigningModeEd25519Dev:
		return NewEd25519Signer()
	case securityv1alpha1.SigningModeOpenBaoTransit:
		if opts == nil || opts.OpenBao == nil {
			return nil, fmt.Errorf("openbao-transit requires FactoryOptions.OpenBao")
		}
		return NewOpenBaoSigner(ctx, opts.OpenBao)
	case securityv1alpha1.SigningModeFulcioKeyless:
		return nil, fmt.Errorf("%w: fulcio-keyless is implemented in Sprint 2", ErrNotImplemented)
	case securityv1alpha1.SigningModeDual:
		return nil, fmt.Errorf("%w: dual signing is implemented in Sprint 2", ErrNotImplemented)
	default:
		return nil, fmt.Errorf("unknown signing mode %q", mode)
	}
}

// ErrNotImplemented is returned when a mode requested by config is not
// yet wired in the current build.
var ErrNotImplemented = errors.New("signing mode not implemented")
