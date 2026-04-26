// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-audit-detection is the DaemonSet that consumes the
// Kubernetes audit log via webhook backend, applies Sigma-style rules,
// and emits SecurityEvent CRs. Implementation pending.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ugallu-audit-detection: scaffold (implementation pending)")
	os.Exit(0)
}
