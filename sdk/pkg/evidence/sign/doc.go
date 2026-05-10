// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package sign provides the cryptographic primitives used by the attestor:
// the Signer interface, the in-toto Statement builder, and a DSSE
// envelope encoder.
//
// Implementations:
//   - Ed25519Signer  in-process keypair. For dev / test only. Default when
//     no other mode is configured.
//   - FulcioSigner   (next iteration) Fulcio keyless via OIDC.
//   - OpenBaoSigner  (later) OpenBao transit signing.
//   - DualSigner     (later) signs with both Fulcio and OpenBao.
//
// Statement schema:
//
//	{
//	  "_type": "https://in-toto.io/Statement/v1",
//	  "subject": [{"name": "...", "digest": {"sha256": "..."}}],
//	  "predicateType": "https://ugallu.io/attestation/{security-event,event-response}/v1",
//	  "predicate": { ... }
//	}
//
// DSSE pre-authentication encoding (PAE) is implemented per
// https://github.com/secure-systems-lab/dsse/blob/master/protocol.md.
package sign
