// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

func TestPAE_FormatMatchesSpec(t *testing.T) {
	pt := "application/vnd.in-toto+json"
	payload := []byte("hello world")
	got := string(sign.PAE(pt, payload))
	want := "DSSEv1 28 application/vnd.in-toto+json 11 hello world"
	if got != want {
		t.Errorf("PAE = %q, want %q", got, want)
	}
}

func TestPAE_EmptyPayload(t *testing.T) {
	pt := "application/foo"
	got := string(sign.PAE(pt, nil))
	if !strings.HasPrefix(got, "DSSEv1 15 application/foo 0 ") {
		t.Errorf("PAE empty payload prefix wrong: %q", got)
	}
}

func TestPAE_BinaryPayload(t *testing.T) {
	pt := "x"
	payload := []byte{0x00, 0x01, 0xff}
	got := sign.PAE(pt, payload)
	wantPrefix := []byte("DSSEv1 1 x 3 ")
	if !bytes.Equal(got[:len(wantPrefix)], wantPrefix) {
		t.Errorf("PAE binary prefix = %q, want %q", string(got[:len(wantPrefix)]), string(wantPrefix))
	}
	if len(got) != len(wantPrefix)+len(payload) {
		t.Errorf("PAE binary length mismatch: %d vs %d", len(got), len(wantPrefix)+len(payload))
	}
}
