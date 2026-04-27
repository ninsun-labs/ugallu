// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	"github.com/ninsun-labs/ugallu/sdk/pkg/evidence/sign"
)

// TestDualSigner_ProducesTwoSignatures verifies the envelope carries
// signatures from both legs and that each leg verifies independently.
func TestDualSigner_ProducesTwoSignatures(t *testing.T) {
	f := newFakeFulcio(t)
	jwt := makeFakeOIDCToken(t, "system:serviceaccount:ugallu-system:attestor", "attestor@ugallu.io")
	tokenPath := writeOIDCToken(t, jwt)

	bao := newFakeOpenBao(t)
	saPath := writeSAToken(t)

	signer, err := sign.NewSigner(
		context.Background(),
		securityv1alpha1.SigningModeDual,
		&sign.FactoryOptions{
			Fulcio: &sign.FulcioSignerOptions{
				FulcioURL:     f.srv.URL,
				OIDCTokenPath: tokenPath,
			},
			OpenBao: &sign.OpenBaoSignerOptions{
				Address:     bao.srv.URL,
				KeyName:     "ugallu-attestor",
				AuthRole:    "ugallu-attestor",
				SATokenPath: saPath,
			},
		},
	)
	if err != nil {
		t.Fatalf("NewSigner(dual): %v", err)
	}
	if signer.Mode() != securityv1alpha1.SigningModeDual {
		t.Errorf("Mode = %q, want dual", signer.Mode())
	}
	if !strings.HasPrefix(signer.KeyID(), "dual:") {
		t.Errorf("KeyID = %q, want dual:* prefix", signer.KeyID())
	}

	payload := []byte(`{"hello":"dual"}`)
	env, err := signer.Sign(context.Background(), payload, sign.StatementMediaType)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(env.Signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(env.Signatures))
	}

	// Primary leg = Fulcio: verify with the leaf cert's public key.
	dual, ok := signer.(*sign.DualSigner)
	if !ok {
		t.Fatalf("signer = %T, want *DualSigner", signer)
	}
	leafPEM, err := dual.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM(primary): %v", err)
	}
	block, _ := pem.Decode(leafPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	fulcioPub := cert.PublicKey.(ed25519.PublicKey)

	// Secondary leg = OpenBao: pull the PEM from its dedicated accessor.
	baoPEM, err := dual.SecondaryPublicKeyPEM()
	if err != nil {
		t.Fatalf("SecondaryPublicKeyPEM: %v", err)
	}
	baoBlock, _ := pem.Decode(baoPEM)
	baoAny, err := x509.ParsePKIXPublicKey(baoBlock.Bytes)
	if err != nil {
		t.Fatalf("parse openbao pub: %v", err)
	}
	baoPub := baoAny.(ed25519.PublicKey)

	pae := sign.PAE(sign.StatementMediaType, payload)
	if !ed25519.Verify(fulcioPub, pae, env.Signatures[0].Sig) {
		t.Error("primary (fulcio) signature did not verify")
	}
	if !ed25519.Verify(baoPub, pae, env.Signatures[1].Sig) {
		t.Error("secondary (openbao) signature did not verify")
	}
	if !strings.HasPrefix(env.Signatures[0].KeyID, "fulcio:") {
		t.Errorf("primary KeyID = %q, want fulcio:* prefix", env.Signatures[0].KeyID)
	}
	if !strings.HasPrefix(env.Signatures[1].KeyID, "openbao:") {
		t.Errorf("secondary KeyID = %q, want openbao:* prefix", env.Signatures[1].KeyID)
	}
}

// TestDualSigner_FactoryRejectsPartialOpts asserts the factory fails
// fast when only one leg's options are supplied.
func TestDualSigner_FactoryRejectsPartialOpts(t *testing.T) {
	cases := []struct {
		name string
		opts *sign.FactoryOptions
	}{
		{"nil opts", nil},
		{"only fulcio", &sign.FactoryOptions{Fulcio: &sign.FulcioSignerOptions{FulcioURL: "https://x"}}},
		{"only openbao", &sign.FactoryOptions{OpenBao: &sign.OpenBaoSignerOptions{Address: "https://x", KeyName: "k", AuthRole: "r"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sign.NewSigner(
				context.Background(),
				securityv1alpha1.SigningModeDual,
				tc.opts,
			); err == nil {
				t.Errorf("NewSigner(dual) accepted incomplete opts %+v", tc.opts)
			}
		})
	}
}
