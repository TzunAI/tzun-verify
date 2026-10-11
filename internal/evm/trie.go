// SPDX-License-Identifier: BSD-3-Clause-Clear

package evm

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// walkProof walks txProof as an ordered path through the transactions trie
// (Anchor §10.4 item 6), from the header's transactionsRoot along
// the key rlp(txIndex), and returns the value it reaches.
//
// The proof is read as a list, not as a set of nodes: its first node must
// hash to the root, each later node must be the one its predecessor
// references by hash at the next step of the key, and the walk must end at
// the last node, with every node used once. A node small enough to be
// embedded in its parent (under 32 bytes, Yellow Paper Appendix D) is read
// there, never looked up. Reordered, repeated, foreign or extra nodes
// therefore fail, as does a proof that ends early or proves the key absent,
// and so does a node that breaks the depth limit of rlpDepthOK.
func walkProof(root common.Hash, index uint64, nodes [][]byte) (val []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			val, err = nil, fmt.Errorf("trie proof walk: %v", r)
		}
	}()
	k, err := rlp.EncodeToBytes(index)
	if err != nil {
		return nil, err
	}
	key := nibbles(k)
	want := root.Bytes()
	for used := 0; ; {
		if used == len(nodes) {
			return nil, errors.New("the proof ends before the key does")
		}
		node := nodes[used]
		used++
		if !bytes.Equal(crypto.Keccak256(node), want) {
			return nil, fmt.Errorf("node %d is not the node its parent references", used-1)
		}
		if !rlpDepthOK(node) {
			return nil, fmt.Errorf("node %d nests lists more than %d deep, or holds a list that is not RLP", used-1, maxRLPDepth)
		}
		content, rest, err := rlp.SplitList(node)
		if err != nil || len(rest) != 0 {
			return nil, fmt.Errorf("node %d is not one RLP list", used-1)
		}
		value, next, err := descend(content, &key)
		if err != nil {
			return nil, fmt.Errorf("node %d: %w", used-1, err)
		}
		if value != nil {
			if used != len(nodes) {
				return nil, fmt.Errorf("%d nodes after the value", len(nodes)-used)
			}
			return value, nil
		}
		want = next
	}
}

type rlpItem struct {
	kind rlp.Kind
	val  []byte
}

func items(content []byte) ([]rlpItem, error) {
	var out []rlpItem
	for len(content) > 0 {
		kind, val, rest, err := rlp.Split(content)
		if err != nil {
			return nil, err
		}
		if kind == rlp.Byte {
			// A single byte below 0x80 is its own encoding: a string of one.
			kind = rlp.String
		}
		out = append(out, rlpItem{kind, val})
		content = rest
	}
	return out, nil
}

// descend follows the key through one hashed node and the nodes embedded in
// it. It returns the value when the key ends at a value here, or the hash of
// the next node to read, consuming the key's nibbles as it goes.
func descend(content []byte, key *[]byte) (value, next []byte, err error) {
	for {
		its, err := items(content)
		if err != nil {
			return nil, nil, err
		}
		var child rlpItem
		switch len(its) {
		case 17: // branch: sixteen children, then a value
			if len(*key) == 0 {
				v := its[16]
				if v.kind != rlp.String || len(v.val) == 0 {
					return nil, nil, errors.New("the key ends at a branch with no value")
				}
				return v.val, nil, nil
			}
			child = its[(*key)[0]]
			*key = (*key)[1:]
		case 2: // leaf or extension: a hex-prefix path, then a value or a child
			path, leaf, ok := hexPrefix(its[0])
			if !ok {
				return nil, nil, errors.New("a malformed hex-prefix path")
			}
			if leaf {
				v := its[1]
				if !bytes.Equal(path, *key) || v.kind != rlp.String || len(v.val) == 0 {
					return nil, nil, errors.New("the leaf is not the key's")
				}
				*key = nil
				return v.val, nil, nil
			}
			if len(path) == 0 || len(path) > len(*key) || !bytes.Equal(path, (*key)[:len(path)]) {
				return nil, nil, errors.New("the extension is not on the key's path")
			}
			*key = (*key)[len(path):]
			child = its[1]
		default:
			return nil, nil, fmt.Errorf("a node of %d items", len(its))
		}
		switch {
		case child.kind == rlp.String && len(child.val) == 32:
			return nil, child.val, nil
		case child.kind == rlp.List && len(child.val) < 31:
			// Embedded: its whole encoding, header included, is under 32
			// bytes, and the parent's hash already covers it.
			content = child.val
		case child.kind == rlp.String && len(child.val) == 0:
			return nil, nil, errors.New("the key is not in the trie")
		default:
			return nil, nil, errors.New("a malformed child reference")
		}
	}
}

func nibbles(b []byte) []byte {
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, c>>4, c&0x0f)
	}
	return out
}

// hexPrefix decodes a hex-prefix path (Yellow Paper Appendix C): the high
// nibble of the first byte is 0 or 1 for an extension, 2 or 3 for a leaf,
// odd when the path has an odd number of nibbles, whose first is then the
// first byte's low nibble; an even path pads that nibble with 0.
func hexPrefix(it rlpItem) (path []byte, leaf, ok bool) {
	if it.kind != rlp.String || len(it.val) == 0 {
		return nil, false, false
	}
	flag, low := it.val[0]>>4, it.val[0]&0x0f
	if flag > 3 {
		return nil, false, false
	}
	leaf = flag&2 != 0
	if flag&1 == 1 {
		path = append([]byte{low}, nibbles(it.val[1:])...)
	} else {
		if low != 0 {
			return nil, false, false
		}
		path = nibbles(it.val[1:])
	}
	return path, leaf, true
}
