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
	// OpenBao is consulted when mode == openbao-transit or dual.
	OpenBao *OpenBaoSignerOptions

	// Fulcio is consulted when mode == fulcio-keyless or dual.
	Fulcio *FulcioSignerOptions
}

// NewSigner returns a Signer for the requested mode.
//   - "" / ed25519-dev   → in-process Ed25519 keypair (test only).
//   - openbao-transit    → OpenBaoSigner; opts.OpenBao must be set.
//   - fulcio-keyless     → FulcioSigner; opts.Fulcio must be set.
//   - dual               → DualSigner over Fulcio + OpenBao; both opts required.
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
		if opts == nil || opts.Fulcio == nil {
			return nil, fmt.Errorf("fulcio-keyless requires FactoryOptions.Fulcio")
		}
		return NewFulcioSigner(ctx, opts.Fulcio)
	case securityv1alpha1.SigningModeDual:
		if opts == nil || opts.Fulcio == nil || opts.OpenBao == nil {
			return nil, fmt.Errorf("dual signing requires both FactoryOptions.Fulcio and FactoryOptions.OpenBao")
		}
		fulcio, err := NewFulcioSigner(ctx, opts.Fulcio)
		if err != nil {
			return nil, fmt.Errorf("dual: fulcio leg: %w", err)
		}
		openbao, err := NewOpenBaoSigner(ctx, opts.OpenBao)
		if err != nil {
			return nil, fmt.Errorf("dual: openbao leg: %w", err)
		}
		return NewDualSigner(fulcio, openbao), nil
	default:
		return nil, fmt.Errorf("unknown signing mode %q", mode)
	}
}

// ErrNotImplemented is returned when a mode requested by config is not
// yet wired in the current build.
var ErrNotImplemented = errors.New("signing mode not implemented")
