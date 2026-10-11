// SPDX-License-Identifier: BSD-3-Clause-Clear

// Command tzun-verify verifies a Tzun evidence record's b1 proof bundle
// without Tzun code and without asking Tzun.
//
//	tzun-verify [flags] <bundle.json>
//
// Offline, it recomputes the record's digest and checks the anchor's
// checkpoints, Merkle proofs and publications from the bundle alone; the
// on-chain facts stay NOT CHECKED. With --evm-rpc, the auditor's own
// Ethereum node confirms that the publication's block is canonical and
// final. Exit codes (Verification §6.6): 0 everything present checked and
// correct; 1 something is wrong; 2 the bundle could not be read or was
// abstained on; 3 a --require or --require-rung was not met; 4 something
// present was abstained on or not checked (0 with --allow-unchecked).
package main

import (
	"os"

	"github.com/TzunAI/tzun-verify/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
