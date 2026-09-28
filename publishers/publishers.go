// Package publishers holds the publisher manifest pinned in this release
// (Anchor §9): the copy of https://tzun.ai/anchors/publishers.json
// that tzun-verify uses when the auditor passes no --publishers file.
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
// with the site copy's.
func SHA256() string {
	sum := sha256.Sum256(Pinned)
	return hex.EncodeToString(sum[:])
}
