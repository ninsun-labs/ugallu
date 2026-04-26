// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-attestor runs the leader-elected Deployment that signs
// SecurityEvent and EventResponse facts as in-toto attestations and stores
// them on Rekor + WORM. Implementation pending.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ugallu-attestor: scaffold (implementation pending)")
	os.Exit(0)
}
