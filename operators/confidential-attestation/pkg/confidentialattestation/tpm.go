// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package confidentialattestation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/google/go-tpm-tools/client"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// realTPMQuote opens the configured TPM character device, fetches a
// PCR quote over slots 0-7 bound to the run nonce, and returns the
// raw evidence + per-slot digests. The quote signature chains to
// the TPM's Attestation Key (AK) - verifiers downstream check it
// against the manufacturer cert chain.
//
// Returns ErrTPMUnavailable when the device file is missing so the
// caller can mark the run indeterminate without erroring out.
func realTPMQuote(devicePath, nonce string) (*AttestOutcome, error) {
	if _, err := os.Stat(devicePath); err != nil {
		return nil, errTPMUnavailable{path: devicePath, cause: err}
	}
	rwc, err := tpm2legacy.OpenTPM(devicePath)
	if err != nil {
		return nil, errTPMUnavailable{path: devicePath, cause: err}
	}
	defer func() { _ = rwc.Close() }()

	ak, err := client.AttestationKeyECC(rwc)
	if err != nil {
		return nil, fmt.Errorf("AttestationKeyECC: %w", err)
	}
	defer ak.Close()

	pcrSel := tpm2legacy.PCRSelection{
		Hash: tpm2legacy.AlgSHA256,
		PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7},
	}
	quoted, err := ak.Quote(pcrSel, []byte(nonce))
	if err != nil {
		return nil, fmt.Errorf("TPM2_Quote: %w", err)
	}

	out := &AttestOutcome{
		Quote:     quoted.GetQuote(),
		Signature: quoted.GetRawSig(),
	}
	for slot, digest := range quoted.GetPcrs().GetPcrs() {
		out.Measurements = append(out.Measurements, securityv1alpha1.ConfidentialAttestationMeasurement{
			Slot:   fmt.Sprintf("%d", slot),
			Digest: hex.EncodeToString(digest),
		})
	}

	// Without a PolicyRef the verifier has nothing to compare
	// against; record the quote but stay in report-only mode.
	out.Verdict = securityv1alpha1.ConfidentialAttestationVerdictIndeterminate
	out.VerifierNotes = "TPM quote captured (no PolicyRef → report-only); verifier chain check needs the AK cert + PCR baseline (post-Wave-4)."

	// Defence in depth: bind the nonce into a synthetic digest the
	// downstream consumers can use to dedup, even if the upstream
	// quote bytes are opaque to them.
	syntheticHash := sha256.Sum256(append([]byte(nonce), out.Quote...))
	out.Measurements = append(out.Measurements, securityv1alpha1.ConfidentialAttestationMeasurement{
		Slot:   "nonce-bound",
		Digest: hex.EncodeToString(syntheticHash[:]),
	})
	return out, nil
}

// errTPMUnavailable signals a missing-device condition so the caller
// emits the indeterminate-verdict path instead of a hard failure.
type errTPMUnavailable struct {
	path  string
	cause error
}

func (e errTPMUnavailable) Error() string {
	return fmt.Sprintf("TPM device %s unavailable: %v", e.path, e.cause)
}

func isTPMUnavailable(err error) bool {
	_, ok := err.(errTPMUnavailable)
	return ok
}
