// SPDX-License-Identifier: BSD-3-Clause-Clear

package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Merkle tree hash, audit paths and consistency proofs of RFC 6962
// §2.1, transcribed as the RFC states them, recursively, as a reference
// for this package and the library under it.

func refLeaf(d []byte) []byte {
	h := sha256.Sum256(append([]byte{0}, d...))
	return h[:]
}

func refNode(l, r []byte) []byte {
	h := sha256.Sum256(append(append([]byte{1}, l...), r...))
	return h[:]
}

// split is k, the largest power of two smaller than n (n > 1).
func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// refRoot is MTH(D[n]).
func refRoot(d [][]byte) []byte {
	switch len(d) {
	case 0:
		h := sha256.Sum256(nil)
		return h[:]
	case 1:
		return refLeaf(d[0])
	}
	k := split(len(d))
	return refNode(refRoot(d[:k]), refRoot(d[k:]))
}

// refPath is PATH(m, D[n]).
func refPath(m int, d [][]byte) [][]byte {
	if len(d) <= 1 {
		return nil
	}
	k := split(len(d))
	if m < k {
		return append(refPath(m, d[:k]), refRoot(d[k:]))
	}
	return append(refPath(m-k, d[k:]), refRoot(d[:k]))
}

// refProof is PROOF(m, D[n]) = SUBPROOF(m, D[n], true).
func refProof(m int, d [][]byte) [][]byte { return refSubproof(m, d, true) }

func refSubproof(m int, d [][]byte, b bool) [][]byte {
	n := len(d)
	if m == n {
		if b {
			return nil
		}
		return [][]byte{refRoot(d)}
	}
	k := split(n)
	if m <= k {
		return append(refSubproof(m, d[:k], b), refRoot(d[k:]))
	}
	return append(refSubproof(m-k, d[k:], false), refRoot(d[:k]))
}

// FuzzProofs holds Root, VerifyInclusion and VerifyConsistency to RFC 6962
// as transcribed above, on trees of 1 to 300 leaves whose digests the fuzzer
// chooses: Root is MTH; the reference audit path of a leaf verifies, and
// fails once any element of it, the leaf, the index or the root changes, or
// once a hash is appended to it or its last hash left out; a reference
// consistency proof between two sizes verifies, and fails once any element
// of it or either root changes, or once a hash is appended to it or its
// last hash left out.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzProofs fuzzes.
func FuzzProofs(f *testing.F) {
	// The target reads size as one less than the number of leaves and first
	// as one less than the older size, so these are trees of exactly 1, 2, 3,
	// 4, 5, 7, 8, 9, 64, 65 and 255 leaves; the second seed of each proves
	// the last leaf and the tree consistent with itself, the older size
	// equal to the newer.
	for _, n := range []uint16{1, 2, 3, 4, 5, 7, 8, 9, 64, 65, 255} {
		f.Add([]byte("leaves"), n-1, n/2, n/3, uint16(0))
		f.Add([]byte("leaves"), n-1, n-1, n-1, uint16(9))
	}
	f.Fuzz(func(t *testing.T, salt []byte, size, index, first, flip uint16) {
		n := int(size)%300 + 1
		d := make([][]byte, n)
		for i := range d {
			h := sha256.Sum256(append(append([]byte{}, salt...), byte(i), byte(i>>8)))
			d[i] = h[:]
		}
		root := Root(d)
		if !bytes.Equal(root, refRoot(d)) {
			t.Fatalf("n=%d: Root %x, MTH %x", n, root, refRoot(d))
		}
		m := int(index) % n
		path := refPath(m, d)
		if !VerifyInclusion(d[m], uint64(m), uint64(n), path, root) {
			t.Fatalf("n=%d: the audit path of leaf %d does not verify", n, m)
		}
		bit := byte(1) << (flip % 8)
		if len(path) > 0 {
			bad := cloneFlip(path, int(flip)%len(path), int(flip/8)%32, bit)
			if VerifyInclusion(d[m], uint64(m), uint64(n), bad, root) {
				t.Fatalf("n=%d leaf %d: a changed audit path verifies", n, m)
			}
		}
		// A path is exactly as long as the index and size give (RFC 9162
		// §2.1.3.2): one hash more, or its last hash left out, does not verify.
		extra := sha256.Sum256(append([]byte("extra"), salt...))
		if VerifyInclusion(d[m], uint64(m), uint64(n), appendOne(path, extra[:]), root) {
			t.Fatalf("n=%d leaf %d: the audit path with a hash appended verifies", n, m)
		}
		if len(path) > 0 && VerifyInclusion(d[m], uint64(m), uint64(n), path[:len(path)-1], root) {
			t.Fatalf("n=%d leaf %d: the audit path without its last hash verifies", n, m)
		}
		if VerifyInclusion(flipped(d[m], bit), uint64(m), uint64(n), path, root) ||
			VerifyInclusion(d[m], uint64(m), uint64(n), path, flipped(root, bit)) ||
			(n > 1 && VerifyInclusion(d[m], uint64((m+1)%n), uint64(n), path, root)) {
			t.Fatalf("n=%d leaf %d: a changed leaf, root or index verifies", n, m)
		}
		k := int(first)%n + 1
		proof := refProof(k, d)
		oldRoot := refRoot(d[:k])
		if !VerifyConsistency(uint64(k), uint64(n), proof, oldRoot, root) {
			t.Fatalf("consistency %d to %d does not verify", k, n)
		}
		if k < n {
			if VerifyConsistency(uint64(k), uint64(n), proof, flipped(oldRoot, bit), root) ||
				VerifyConsistency(uint64(k), uint64(n), proof, oldRoot, flipped(root, bit)) {
				t.Fatalf("consistency %d to %d verifies with a changed root", k, n)
			}
			if len(proof) > 0 {
				bad := cloneFlip(proof, int(flip)%len(proof), int(flip/8)%32, bit)
				if VerifyConsistency(uint64(k), uint64(n), bad, oldRoot, root) {
					t.Fatalf("consistency %d to %d verifies with a changed proof", k, n)
				}
				if VerifyConsistency(uint64(k), uint64(n), proof[:len(proof)-1], oldRoot, root) {
					t.Fatalf("consistency %d to %d verifies without the proof's last hash", k, n)
				}
			}
		}
		if VerifyConsistency(uint64(k), uint64(n), appendOne(proof, extra[:]), oldRoot, root) {
			t.Fatalf("consistency %d to %d verifies with a hash appended to the proof", k, n)
		}
	})
}

// appendOne is p with h after its last element, p itself unchanged.
func appendOne(p [][]byte, h []byte) [][]byte {
	return append(append(make([][]byte, 0, len(p)+1), p...), h)
}

func flipped(b []byte, bit byte) []byte {
	c := append([]byte{}, b...)
	c[0] ^= bit
	return c
}

func cloneFlip(p [][]byte, i, at int, bit byte) [][]byte {
	c := make([][]byte, len(p))
	copy(c, p)
	c[i] = append([]byte{}, p[i]...)
	c[i][at] ^= bit
	return c
}

// FuzzVerify runs VerifyInclusion and VerifyConsistency on anything at all:
// sizes and indices up to 2^64 - 1, paths of any length and roots of any
// length. Neither panics, and neither verifies a size the preconditions of
// Tree §3.4 and §3.5 refuse. The seeds are the RFC 6962 and consistency
// vectors, valid and invalid.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzVerify fuzzes.
func FuzzVerify(f *testing.F) {
	dir := filepath.Join("..", "..", "testdata", "vectors")
	var trees struct {
		Trees []struct {
			TreeSize    uint64   `json:"treeSize"`
			LeafDigests []string `json:"leafDigests"`
			Root        string   `json:"root"`
			Proofs      []struct {
				Index uint64   `json:"leafIndex"`
				Path  []string `json:"auditPath"`
			} `json:"proofs"`
		} `json:"trees"`
	}
	readJSON(f, filepath.Join(dir, "merkle-rfc6962-vectors.json"), &trees)
	for _, tr := range trees.Trees {
		for _, p := range tr.Proofs {
			if p.Index < uint64(len(tr.LeafDigests)) {
				f.Add(unhex(tr.LeafDigests[p.Index]), p.Index, tr.TreeSize, joined(p.Path), unhex(tr.Root), uint64(0), uint64(0), []byte(nil))
			}
		}
	}
	var cons struct {
		Valid, Invalid []struct {
			First      uint64   `json:"first"`
			Second     uint64   `json:"second"`
			FirstRoot  string   `json:"firstRoot"`
			SecondRoot string   `json:"secondRoot"`
			Proof      []string `json:"proof"`
		}
	}
	readJSON(f, filepath.Join(dir, "merkle-consistency-vectors.json"), &cons)
	for _, c := range append(cons.Valid, cons.Invalid...) {
		f.Add([]byte(nil), uint64(0), uint64(0), joined(c.Proof), unhex(c.SecondRoot), c.First, c.Second, unhex(c.FirstRoot))
	}
	f.Fuzz(func(t *testing.T, leaf []byte, index, size uint64, path, root []byte, first, second uint64, firstRoot []byte) {
		p := chunks(path)
		if VerifyInclusion(leaf, index, size, p, root) && (size == 0 || index >= size || len(root) != 32) {
			t.Fatalf("inclusion verifies at index %d of size %d with a root of %d bytes", index, size, len(root))
		}
		if VerifyConsistency(first, second, p, firstRoot, root) && (first == 0 || first > second || len(firstRoot) != 32 || len(root) != 32) {
			t.Fatalf("consistency verifies from %d to %d", first, second)
		}
	})
}

// FuzzParseHashString holds the encoding rule of Tree §4 to any string: a
// hash is exactly 64 hex digits of either case, and reads as the 32 bytes
// they spell.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzParseHashString fuzzes.
func FuzzParseHashString(f *testing.F) {
	for _, s := range []string{strings.Repeat("ab", 32), strings.Repeat("AB", 32), "0x" + strings.Repeat("0", 62),
		strings.Repeat("0", 63) + "\n", strings.Repeat("g", 64), strings.Repeat("0", 65), ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, ok := ParseHashString(s)
		hexOnly := len(s) == 64 && strings.Trim(s, "0123456789abcdefABCDEF") == ""
		if ok != hexOnly {
			t.Fatalf("%q: read %v", s, ok)
		}
		if ok && (len(b) != 32 || hex.EncodeToString(b) != strings.ToLower(s)) {
			t.Fatalf("%q reads as %x", s, b)
		}
	})
}

func readJSON(f *testing.F, path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		f.Fatalf("%s: %v", path, err)
	}
}

func unhex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func joined(hs []string) []byte {
	var out []byte
	for _, h := range hs {
		out = append(out, unhex(h)...)
	}
	return out
}

// chunks splits a byte string into 32-byte hashes, the last one short when
// the length is not a multiple of 32.
func chunks(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 32 {
		out = append(out, b[:32])
		b = b[32:]
	}
	if len(b) > 0 {
		out = append(out, b)
	}
	return out
}
