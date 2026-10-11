// SPDX-License-Identifier: BSD-3-Clause-Clear

// Package publishers holds the publisher manifest pinned in this release
// (Anchor §9), whose address is https://tzun.ai/anchors/publishers.json:
// the manifest tzun-verify uses when the auditor passes no --publishers file.
package publishers

import (
	"crypto/sha256"
	"encoding/hex"

	_ "embed"
)

// Pinned is the manifest's bytes.
//
//go:embed publishers.json
var Pinned []byte

// SHA256 is the SHA-256 of the pinned manifest's bytes, lowercase hex: the
// digest a report names it by (Verification §6.2), and the one to compare
// with a copy fetched from the manifest's address.
func SHA256() string {
	sum := sha256.Sum256(Pinned)
	return hex.EncodeToString(sum[:])
}
