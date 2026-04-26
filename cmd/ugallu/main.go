// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu is the standalone CLI for the ugallu platform.
//
// Subcommands (planned):
//   - ugallu attest verify <bundle-uid>   : verify a signed attestation
//   - ugallu doctor                       : preflight check of the cluster
//   - ugallu debug ...                    : diagnostic helpers
//   - ugallu version                      : print version
//
// Implementation pending; only `version` works at the moment.
package main

import (
	"fmt"
	"os"
)

const version = "v0.0.1-alpha.1"

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	fmt.Fprintln(os.Stderr, "ugallu: scaffold (implementation pending)")
	fmt.Fprintln(os.Stderr, "Run 'ugallu version' to print the version.")
	os.Exit(0)
}
