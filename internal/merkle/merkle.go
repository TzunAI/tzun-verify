// SPDX-License-Identifier: BSD-3-Clause-Clear

// Package merkle checks RFC 6962 proofs over Tzun logs (Tree, the tree
// profile revision 2) with transparency-dev/merkle, pinned at main
// commit fbbcd741: that commit refuses every invalid consistency vector,
// including the five first = 0 cases its v0.0.2 tag accepts
// (Tree §9).
//
// This package adds only what the library leaves to its caller: the hash
// encoding rule of Tree §4 and the size preconditions.
package merkle

import (
	"encoding/hex"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

var hasher = rfc6962.DefaultHasher

// ParseHashString applies the Tree §4 encoding rule: exactly 64 hex
// digits, either case, nothing else (no 0x, no whitespace, no newline).
func ParseHashString(s string) ([]byte, bool) {
	if len(s) != 64 {
		return nil, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return nil, false
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// ParseHash reads a JSON value as a hash under Tree §4. A non-string is
// refused.
func ParseHash(v *jsonv.Value) ([]byte, bool) {
	s, ok := v.Str()
	if !ok {
		return nil, false
	}
	return ParseHashString(s)
}

// ParsePath reads a proof: a JSON array whose every element is a hash.
// null is not an empty proof.
func ParsePath(v *jsonv.Value) ([][]byte, bool) {
	if v == nil || v.Kind != jsonv.Array {
		return nil, false
	}
	out := make([][]byte, 0, len(v.A))
	for _, e := range v.A {
		h, ok := ParseHash(e)
		if !ok {
			return nil, false
		}
		out = append(out, h)
	}
	return out, true
}

// LeafHash is SHA-256(0x00 ‖ d).
func LeafHash(d []byte) []byte { return hasher.HashLeaf(d) }

// VerifyInclusion checks Tree §3.4: leafDigest at index in the tree of size
// whose root is root, by path.
func VerifyInclusion(leafDigest []byte, index, size uint64, path [][]byte, root []byte) bool {
	if size == 0 || index >= size || len(root) != 32 {
		return false
	}
	return proof.VerifyInclusion(hasher, index, size, LeafHash(leafDigest), path, root) == nil
}

// VerifyConsistency checks Tree §3.5 with its edge rules: 0 < first ≤
// second; equal sizes verify only with an empty proof and equal roots.
func VerifyConsistency(first, second uint64, path [][]byte, firstRoot, secondRoot []byte) bool {
	if first == 0 || first > second || len(firstRoot) != 32 || len(secondRoot) != 32 {
		return false
	}
	if first == second {
		return len(path) == 0 && string(firstRoot) == string(secondRoot)
	}
	return proof.VerifyConsistency(hasher, first, second, path, firstRoot, secondRoot) == nil
}

// Root is MTH over the leaf digests (Tree §3.1), through the library's
// compact range. The empty list gives SHA-256 of the empty string.
func Root(leafDigests [][]byte) []byte {
	if len(leafDigests) == 0 {
		return hasher.EmptyRoot()
	}
	f := compact.RangeFactory{Hash: hasher.HashChildren}
	r := f.NewEmptyRange(0)
	for _, d := range leafDigests {
		if err := r.Append(hasher.HashLeaf(d), nil); err != nil {
			return nil
		}
	}
	root, err := r.GetRootHash(nil)
	if err != nil {
		return nil
	}
	return root
}
