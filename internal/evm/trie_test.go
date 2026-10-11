// SPDX-License-Identifier: BSD-3-Clause-Clear

package evm

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// TestWalkProofOverTries walks go-ethereum's own proofs of every key of
// tries whose values are short enough for nodes to be embedded in their
// parents and long enough for none to be, up to 300 keys (keys of one and
// of two bytes under rlp(index)). A key the trie lacks is refused.
func TestWalkProofOverTries(t *testing.T) {
	for _, n := range []int{1, 2, 17, 130, 300} {
		for _, vlen := range []int{1, 3, 20, 40, 200} {
			tr := trie.NewEmpty(nil)
			value := func(i int) []byte {
				v := bytes.Repeat([]byte{byte(i%250 + 1)}, vlen)
				v[0] = byte(i)
				return v
			}
			for i := 0; i < n; i++ {
				k, _ := rlp.EncodeToBytes(uint64(i))
				if err := tr.Update(k, value(i)); err != nil {
					t.Fatal(err)
				}
			}
			root := tr.Hash()
			for i := 0; i <= n; i++ {
				k, _ := rlp.EncodeToBytes(uint64(i))
				var p orderedProof
				if err := tr.Prove(k, &p); err != nil {
					t.Fatal(err)
				}
				got, err := walkProof(root, uint64(i), p)
				switch {
				case i == n && err == nil:
					t.Errorf("n=%d vlen=%d: key %d is not in the trie, and the walk returned %x", n, vlen, i, got)
				case i < n && (err != nil || !bytes.Equal(got, value(i))):
					t.Errorf("n=%d vlen=%d key %d: %x, %v", n, vlen, i, got, err)
				}
			}
		}
	}
}
