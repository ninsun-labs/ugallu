// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package confidentialattestation

import (
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

// (A "device-present-but-not-a-real-TPM" test would be ideal here
// but go-tpm's OpenTPM is permissive on regular files — the real
// failure surfaces only later, on the first TPM2_Quote command,
// which requires actual TPM IO. That path is exercised by the
// reconciler converting the err into a Phase=Failed run; the
// inverse "missing device → indeterminate" path is covered
// explicitly above.)

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
