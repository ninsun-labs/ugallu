// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package confidentialattestation

import (
	"os"
	"path/filepath"
	"testing"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// TestTPMAttester_DeviceMissing pins the indeterminate-verdict path
// for the common case (lab clusters without a TPM passthrough).
func TestTPMAttester_DeviceMissing(t *testing.T) {
	a := &tpmAttester{device: "/dev/does-not-exist"}
	out, err := a.Attest(&securityv1alpha1.ConfidentialAttestationRunSpec{
		Backend: securityv1alpha1.ConfidentialAttestationBackendTPM,
		Nonce:   "nonce-1234567890abcdef",
	})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if out.Verdict != securityv1alpha1.ConfidentialAttestationVerdictIndeterminate {
		t.Errorf("Verdict = %q, want indeterminate", out.Verdict)
	}
}

// TestTPMAttester_DevicePresent_StubProducesNonceBoundEvidence covers
// the path where the device exists (simulated via tempfile).
func TestTPMAttester_DevicePresent_StubProducesNonceBoundEvidence(t *testing.T) {
	dir := t.TempDir()
	dev := filepath.Join(dir, "tpm0")
	if err := os.WriteFile(dev, []byte{}, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	a := &tpmAttester{device: dev}
	out, err := a.Attest(&securityv1alpha1.ConfidentialAttestationRunSpec{
		Backend: securityv1alpha1.ConfidentialAttestationBackendTPM,
		Nonce:   "nonce-1234567890abcdef",
	})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if len(out.Measurements) != 8 {
		t.Errorf("expected 8 PCR slots, got %d", len(out.Measurements))
	}
	if out.Verdict != securityv1alpha1.ConfidentialAttestationVerdictIndeterminate {
		t.Errorf("Verdict = %q (no PolicyRef → indeterminate expected)", out.Verdict)
	}
	if len(out.Quote) == 0 || len(out.Signature) != 64 {
		t.Errorf("Quote/Signature shape: quoteLen=%d sigLen=%d", len(out.Quote), len(out.Signature))
	}
}

// TestStubOutcome_DifferentNoncesDifferentDigests confirms anti-
// replay: re-running with a fresh nonce changes every digest.
func TestStubOutcome_DifferentNoncesDifferentDigests(t *testing.T) {
	a := stubOutcome(&securityv1alpha1.ConfidentialAttestationRunSpec{Nonce: "aaaaaaaaaaaaaaaa"}, "tpm", []string{"0", "1"})
	b := stubOutcome(&securityv1alpha1.ConfidentialAttestationRunSpec{Nonce: "bbbbbbbbbbbbbbbb"}, "tpm", []string{"0", "1"})
	for i := range a.Measurements {
		if a.Measurements[i].Digest == b.Measurements[i].Digest {
			t.Errorf("digest collision at slot %s — nonce binding broken", a.Measurements[i].Slot)
		}
	}
}

// TestAttesterFor_AllBackendsResolve smoke-checks the dispatcher.
func TestAttesterFor_AllBackendsResolve(t *testing.T) {
	for _, b := range []securityv1alpha1.ConfidentialAttestationBackend{
		securityv1alpha1.ConfidentialAttestationBackendTPM,
		securityv1alpha1.ConfidentialAttestationBackendSEVSNP,
		securityv1alpha1.ConfidentialAttestationBackendTDX,
	} {
		a, err := AttesterFor(&securityv1alpha1.ConfidentialAttestationRunSpec{Backend: b},
			"/dev/tpm0", "/dev/sev-guest", "/dev/tdx-guest")
		if err != nil || a == nil {
			t.Errorf("AttesterFor(%q): a=%v err=%v", b, a, err)
		}
	}
}
