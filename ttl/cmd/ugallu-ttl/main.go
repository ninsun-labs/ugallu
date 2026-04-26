// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-ttl runs the leader-elected Deployment responsible for
// TTL-based archiving of SecurityEvent / EventResponse / AttestationBundle
// CRs and acts as a watchdog for the attestor. Implementation pending.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ugallu-ttl: scaffold (implementation pending)")
	os.Exit(0)
}
