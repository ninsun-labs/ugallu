// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"fmt"
)

// PAE returns the DSSE Pre-Authentication Encoding bytes for the given
// payload + payloadType. The PAE is what implementations actually sign;
// the raw payload alone is never signed.
//
// Format: "DSSEv1 SP <len(payloadType)> SP <payloadType> SP <len(payload)> SP <payload>"
// where SP is a literal space character.
//
// Reference: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
func PAE(payloadType string, payload []byte) []byte {
	header := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, 0, len(header)+len(payload))
	out = append(out, []byte(header)...)
	out = append(out, payload...)
	return out
}
