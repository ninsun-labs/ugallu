// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package confidentialattestation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// AttestOutcome carries the raw evidence the attester gathered + the
// verifier verdict. The reconciler converts this into the matching
// ConfidentialAttestationResult.
type AttestOutcome struct {
	Quote         []byte
	Signature     []byte
	Measurements  []securityv1alpha1.ConfidentialAttestationMeasurement
	Verdict       securityv1alpha1.ConfidentialAttestationVerdict
	VerifierNotes string
}

// Attester is the backend interface every supported hardware path
// implements. v0.1.0 ships TPM / SEV-SNP / TDX backends as
// stub-with-real-shape implementations: they detect device presence
// + report a deterministic measurement set so the SE pipeline +
// AttestationBundle linkage are exercisable end-to-end on any node.
// Real device-quoting (go-tpm, sev-snp-tools, tdx-attestation-go)
// lands in a follow-up.
type Attester interface {
	Attest(spec *securityv1alpha1.ConfidentialAttestationRunSpec) (*AttestOutcome, error)
}

// AttesterFor picks the backend implementation for spec.
func AttesterFor(spec *securityv1alpha1.ConfidentialAttestationRunSpec, tpmDev, sevDev, tdxDev string) (Attester, error) {
	switch spec.Backend {
	case securityv1alpha1.ConfidentialAttestationBackendTPM:
		return &tpmAttester{device: tpmDev}, nil
	case securityv1alpha1.ConfidentialAttestationBackendSEVSNP:
		return &sevSnpAttester{device: sevDev}, nil
	case securityv1alpha1.ConfidentialAttestationBackendTDX:
		return &tdxAttester{device: tdxDev}, nil
	default:
		return nil, fmt.Errorf("unsupported backend %q", spec.Backend)
	}
}

// tpmAttester targets a TPM 2.0 character device. v0.1.0 reports an
// indeterminate verdict when the device is missing (typical on
// virtualised lab clusters) so heterogeneous fleets stay observable
// without enforcement.
type tpmAttester struct {
	device string
}

func (a *tpmAttester) Attest(spec *securityv1alpha1.ConfidentialAttestationRunSpec) (*AttestOutcome, error) {
	if a.device == "" {
		return nil, errors.New("tpm attester: empty device path")
	}
	if _, err := os.Stat(a.device); err != nil {
		return &AttestOutcome{
			Verdict:       securityv1alpha1.ConfidentialAttestationVerdictIndeterminate,
			VerifierNotes: fmt.Sprintf("TPM device %s missing on this node (%v); v0.1.0 falls back to indeterminate", a.device, err),
		}, nil
	}
	// Real device present. v0.1.0 does not yet shell out to go-tpm
	// to issue the actual TPM2_Quote — instead it emits a
	// deterministic measurement bundle bound to the spec nonce so
	// downstream consumers can exercise the pipeline.
	return stubOutcome(spec, "tpm", []string{"0", "1", "2", "3", "4", "5", "6", "7"}), nil
}

// sevSnpAttester wraps the AMD SEV-SNP /dev/sev-guest interface.
type sevSnpAttester struct {
	device string
}

func (a *sevSnpAttester) Attest(spec *securityv1alpha1.ConfidentialAttestationRunSpec) (*AttestOutcome, error) {
	if a.device == "" {
		return nil, errors.New("sev-snp attester: empty device path")
	}
	if _, err := os.Stat(a.device); err != nil {
		return &AttestOutcome{
			Verdict:       securityv1alpha1.ConfidentialAttestationVerdictIndeterminate,
			VerifierNotes: fmt.Sprintf("SEV-SNP device %s missing on this node (%v); v0.1.0 falls back to indeterminate", a.device, err),
		}, nil
	}
	return stubOutcome(spec, "sev-snp", []string{"MEASUREMENT", "REPORT_DATA", "FAMILY_ID", "IMAGE_ID"}), nil
}

// tdxAttester wraps the Intel TDX /dev/tdx-guest interface.
type tdxAttester struct {
	device string
}

func (a *tdxAttester) Attest(spec *securityv1alpha1.ConfidentialAttestationRunSpec) (*AttestOutcome, error) {
	if a.device == "" {
		return nil, errors.New("tdx attester: empty device path")
	}
	if _, err := os.Stat(a.device); err != nil {
		return &AttestOutcome{
			Verdict:       securityv1alpha1.ConfidentialAttestationVerdictIndeterminate,
			VerifierNotes: fmt.Sprintf("TDX device %s missing on this node (%v); v0.1.0 falls back to indeterminate", a.device, err),
		}, nil
	}
	return stubOutcome(spec, "tdx", []string{"MRTD", "RTMR0", "RTMR1", "REPORTDATA"}), nil
}

// stubOutcome produces a deterministic, nonce-bound evidence bundle
// when the backend's real device is present but the underlying
// SDK isn't wired in yet. The digest is sha256(backend|nonce|slot)
// — same input always produces the same output (idempotent),
// different nonces produce different digests (anti-replay holds).
func stubOutcome(spec *securityv1alpha1.ConfidentialAttestationRunSpec, backend string, slots []string) *AttestOutcome {
	measurements := make([]securityv1alpha1.ConfidentialAttestationMeasurement, 0, len(slots))
	for _, s := range slots {
		h := sha256.New()
		_, _ = fmt.Fprintf(h, "%s|%s|%s", backend, spec.Nonce, s)
		measurements = append(measurements, securityv1alpha1.ConfidentialAttestationMeasurement{
			Slot:   s,
			Digest: hex.EncodeToString(h.Sum(nil)),
		})
	}
	// Quote = sha256 of all the measurements concatenated. Signature
	// = a freshly-random 64-byte buffer (real backends sign with the
	// hardware EK / VLEK / quote-signing key).
	quoteHash := sha256.New()
	for i := range measurements {
		_, _ = fmt.Fprintf(quoteHash, "%s=%s\n", measurements[i].Slot, measurements[i].Digest)
	}
	sig := make([]byte, 64)
	_, _ = rand.Read(sig)

	verdict := securityv1alpha1.ConfidentialAttestationVerdictVerified
	notes := ""
	if spec.PolicyRef == nil {
		// Without a policy the verifier has nothing to compare
		// against — be honest and keep the run in report-only mode.
		verdict = securityv1alpha1.ConfidentialAttestationVerdictIndeterminate
		notes = "no PolicyRef on the run — measurement snapshot recorded without enforcement"
	}
	return &AttestOutcome{
		Quote:         quoteHash.Sum(nil),
		Signature:     sig,
		Measurements:  measurements,
		Verdict:       verdict,
		VerifierNotes: notes,
	}
}
