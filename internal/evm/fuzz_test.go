// SPDX-License-Identifier: BSD-3-Clause-Clear

package evm

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// evmVectors is what the fuzz seeds take from evm-anchor-vectors.json.
type evmVectors struct {
	P            string          `json:"p"`
	AnchorOrigin string          `json:"anchorOrigin"`
	Publication  json.RawMessage `json:"publication"`
	ManifestEnt  json.RawMessage `json:"manifestEntry"`
	HeaderSource struct {
		ChainID   uint64 `json:"chainId"`
		Finalized uint64 `json:"finalizedBlockNumber"`
		Blocks    []struct {
			Number    uint64 `json:"number"`
			Hash      string `json:"hash"`
			Timestamp uint64 `json:"timestamp"`
		} `json:"blocks"`
		Transactions []struct {
			TransactionID string `json:"transactionId"`
			BlockHash     string `json:"blockHash"`
			BlockNumber   uint64 `json:"blockNumber"`
			From          string `json:"from"`
		} `json:"transactions"`
	} `json:"headerSource"`
	ValidityBounds []struct {
		Bounds map[string]any `json:"bounds"`
	} `json:"validityBounds"`
}

func readEVMVectors(f *testing.F) (v evmVectors, pubs []map[string]any) {
	dir := filepath.Join("..", "..", "testdata", "vectors")
	b, err := os.ReadFile(filepath.Join(dir, "evm-anchor-vectors.json"))
	if err != nil {
		f.Fatal(err)
	}
	if err := json.Unmarshal(b, &v); err != nil {
		f.Fatal(err)
	}
	var pub map[string]any
	if err := json.Unmarshal(v.Publication, &pub); err != nil {
		f.Fatal(err)
	}
	pubs = append(pubs, pub)
	b, err = os.ReadFile(filepath.Join(dir, "anchor-e2e-vectors.json"))
	if err != nil {
		f.Fatal(err)
	}
	var e2e struct {
		Epochs []struct {
			Publication map[string]any `json:"publication"`
		} `json:"epochs"`
	}
	if err := json.Unmarshal(b, &e2e); err != nil {
		f.Fatal(err)
	}
	for _, e := range e2e.Epochs {
		pubs = append(pubs, e.Publication)
	}
	return v, pubs
}

func hexBytes(v any) []byte {
	s, _ := v.(string)
	b, _ := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	return b
}

// seedTxs signs one transaction of each type this verifier reads, under a
// fixed test key, and returns their encodings.
func seedTxs(f *testing.F) [][]byte {
	key, err := crypto.HexToECDSA("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	if err != nil {
		f.Fatal(err)
	}
	to := crypto.PubkeyToAddress(key.PublicKey)
	cid := big.NewInt(31337)
	data := bytes.Repeat([]byte{0xab}, 32)
	var out [][]byte
	for _, c := range []struct {
		inner  types.TxData
		signer types.Signer
	}{
		{&types.LegacyTx{Nonce: 1, GasPrice: big.NewInt(1e9), Gas: 30000, To: &to, Data: data}, types.HomesteadSigner{}},
		{&types.LegacyTx{Nonce: 2, GasPrice: big.NewInt(1e9), Gas: 30000, To: &to, Data: data}, types.NewEIP155Signer(cid)},
		{&types.AccessListTx{ChainID: cid, Nonce: 3, GasPrice: big.NewInt(1e9), Gas: 30000, To: &to, Data: data,
			AccessList: types.AccessList{{Address: to, StorageKeys: []common.Hash{{1}}}}}, types.NewLondonSigner(cid)},
		{&types.DynamicFeeTx{ChainID: cid, Nonce: 4, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(3e9), Gas: 30000, Data: data},
			types.NewLondonSigner(cid)},
	} {
		tx, err := types.SignNewTx(key, c.signer, c.inner)
		if err != nil {
			f.Fatal(err)
		}
		raw, err := tx.MarshalBinary()
		if err != nil {
			f.Fatal(err)
		}
		out = append(out, raw)
	}
	return out
}

// The type 2 and type 1 transactions fuzzing found that sign chain id 0.
const (
	chainZeroType2 = "02e080800101809409000000000000000000000000000000000000008080c0800507"
	chainZeroType1 = "01df808001809409000000000000000000000000000000000000008080c0010507"
)

// refSender is the reading item 2 of Anchor §10.4 gives a raw transaction,
// stated apart from decodeTx and txRulesOK. go-ethereum decodes it; a
// transaction that signs a chain id signs 1 or more, which refuses a typed
// transaction that signs chain id 0 and a legacy one with v 35 or 36; a
// type 2 maxPriorityFeePerGas is at most its maxFeePerGas; the recovery id v
// gives (v - 27, v - chainId*2 - 35, or a typed transaction's yParity) is 0
// or 1, and r and s pass go-ethereum's own test of their range and of a low
// s (crypto.ValidateSignatureValues). The sender is then what go-ethereum's
// latest signer recovers, for the chain id signed, or for chain 1 when none
// is. go-ethereum alone recovers a sender from a legacy transaction that
// signs chain id 0 and from a type 2 transaction whose tip exceeds its cap.
func refSender(raw []byte) (common.Address, error) {
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(raw); err != nil {
		return common.Address{}, err
	}
	v, r, s := tx.RawSignatureValues()
	id := tx.ChainId()
	recID := new(big.Int).Set(v)
	switch {
	case tx.Type() == types.LegacyTxType && !tx.Protected():
		id = big.NewInt(1)
		recID.Sub(v, big.NewInt(27))
	case id.Sign() <= 0:
		return common.Address{}, errors.New("signs chain id 0")
	case tx.Type() == types.LegacyTxType:
		recID.Sub(v, new(big.Int).Add(new(big.Int).Lsh(id, 1), big.NewInt(35)))
	}
	if tx.Type() == types.DynamicFeeTxType && tx.GasTipCap().Cmp(tx.GasFeeCap()) > 0 {
		return common.Address{}, errors.New("maxPriorityFeePerGas above maxFeePerGas")
	}
	if !recID.IsUint64() || recID.Uint64() > 1 || !crypto.ValidateSignatureValues(byte(recID.Uint64()), r, s, true) {
		return common.Address{}, errors.New("signature values")
	}
	return types.Sender(types.LatestSignerForChainID(id), tx)
}

// FuzzDecodeTx holds item 2 of Anchor §10.4 to any raw transaction: it is
// refused as malformed or unsupported, or it decodes to a transaction of
// type 0, 1 or 2 whose encoding is the raw bytes and whose hash, the id
// the chain knows it by, is keccak256 of them, which is the transactionId
// the verifier reports and compares (item 3). TxID agrees. A transaction of
// type 0, 1 or 2 yields a sender exactly when refSender, the rules of item 2
// stated a second way over go-ethereum, recovers one, and it is the same
// sender.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzDecodeTx fuzzes.
func FuzzDecodeTx(f *testing.F) {
	_, pubs := readEVMVectors(f)
	for _, p := range pubs {
		f.Add(hexBytes(p["rawTransaction"]))
	}
	for _, raw := range seedTxs(f) {
		f.Add(raw)
	}
	for _, b := range []string{"03", "04", "7f", "80", "bf", "c0", "01", "02", "01c0", "02c0"} {
		x, _ := hex.DecodeString(b)
		f.Add(x)
	}
	// One transaction for each rule of item 2, and well-formed ones.
	for _, c := range item2Cases {
		f.Add(hexBytes(c.raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) == 0 {
			return // shape refuses an empty rawTransaction before decodeTx
		}
		id := crypto.Keccak256Hash(raw)
		if got := TxID("0x" + hex.EncodeToString(raw)); got != strings.ToLower(id.Hex()) {
			t.Fatalf("TxID %q, keccak256 %s", got, id.Hex())
		}
		tx, sender, why := decodeTx(raw)
		refFrom, refErr := refSender(raw)
		switch why {
		case "":
			if refErr != nil || refFrom != sender {
				t.Fatalf("sender %s; refSender reads %s (%v)", sender.Hex(), refFrom.Hex(), refErr)
			}
		case ReasonMalformed:
			if tx != nil {
				t.Fatalf("a transaction returned with %s", why)
			}
			if refErr == nil && (raw[0] >= 0xc0 || raw[0] == types.AccessListTxType || raw[0] == types.DynamicFeeTxType) {
				t.Fatalf("refused as malformed; refSender reads sender %s", refFrom.Hex())
			}
			return
		case ReasonUnsupportedTxType:
			if tx != nil || raw[0] >= 0x80 || raw[0] == types.AccessListTxType || raw[0] == types.DynamicFeeTxType {
				t.Fatalf("type byte %#x refused as unsupported", raw[0])
			}
			return
		default:
			t.Fatalf("reason %q", why)
		}
		if typ := tx.Type(); typ > types.DynamicFeeTxType {
			t.Fatalf("type %d accepted", typ)
		}
		if tx.Hash() != id {
			t.Fatalf("the chain's id %s is not keccak256 of the raw bytes, %s", tx.Hash().Hex(), id.Hex())
		}
		again, err := tx.MarshalBinary()
		if err != nil || !bytes.Equal(again, raw) {
			t.Fatalf("the transaction re-encodes as %x, not %x (%v)", again, raw, err)
		}
		if signed := signedChainID(tx); signed == nil && (tx.Type() != types.LegacyTxType || tx.Protected()) {
			t.Fatalf("no signed chain id for a type %d transaction", tx.Type())
		}
	})
}

// FuzzParseHeader holds parseHeader to item 6 of Anchor §10.4 on any
// bytes: it never panics; a header it reads has a number and time within
// JSON's safe integers; and every header go-ethereum's own decoder reads,
// with a number and time within them, it reads too, with the same
// transactions root, number and time.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzParseHeader fuzzes.
func FuzzParseHeader(f *testing.F) {
	_, pubs := readEVMVectors(f)
	for _, p := range pubs {
		f.Add(hexBytes(p["blockHeader"]))
	}
	h := &types.Header{Difficulty: big.NewInt(0), Number: big.NewInt(7), Time: 1790876430, BaseFee: big.NewInt(7)}
	if b, err := rlp.EncodeToBytes(h); err == nil {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		got, ok := parseHeader(b)
		if ok && (got.number > 1<<53-1 || got.time > 1<<53-1) {
			t.Fatalf("number %d or time %d beyond 2^53 - 1", got.number, got.time)
		}
		var g types.Header
		if err := rlp.DecodeBytes(b, &g); err != nil || g.Number == nil || !g.Number.IsUint64() ||
			g.Number.Uint64() > 1<<53-1 || g.Time > 1<<53-1 {
			return
		}
		if !ok {
			t.Fatalf("go-ethereum reads header %d, parseHeader refuses it", g.Number)
		}
		if got.txRoot != g.TxHash || got.number != g.Number.Uint64() || got.time != g.Time {
			t.Fatalf("parseHeader reads %x %d %d, go-ethereum %x %d %d", got.txRoot, got.number, got.time, g.TxHash, g.Number, g.Time)
		}
	})
}

// FuzzWalkProof holds walkProof to go-ethereum's transactions trie: for a
// trie of 1 to 400 keys rlp(i) with values of 1 to 128 bytes, the fuzzer's
// choice, go-ethereum's proof of any key in it walks to that key's value,
// and the proof of the first key it lacks does not walk. A proof with its
// last node removed, with a node repeated at its end, or with one bit of
// one node changed, does not walk.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzWalkProof fuzzes.
func FuzzWalkProof(f *testing.F) {
	// The target reads size as one less than the number of keys, so these
	// are tries of exactly 1, 2, 16, 17, 129 and 300 keys; the last seed of
	// each asks for key n, the first one the trie lacks.
	for _, n := range []uint16{1, 2, 16, 17, 129, 300} {
		for _, vlen := range []uint8{0, 2, 30, 31, 32, 127} {
			f.Add(n-1, vlen, []byte{byte(n), vlen}, uint16(n/2))
		}
		f.Add(n-1, uint8(31), []byte{byte(n)}, n)
	}
	f.Fuzz(func(t *testing.T, size uint16, vlen uint8, salt []byte, index uint16) {
		n := int(size)%400 + 1
		value := func(i int) []byte {
			v := make([]byte, int(vlen)%128+1)
			for j := range v {
				v[j] = byte(i) ^ byte(j)
				if len(salt) > 0 {
					v[j] ^= salt[(i+j)%len(salt)]
				}
			}
			return v
		}
		tr := trie.NewEmpty(nil)
		for i := 0; i < n; i++ {
			k, _ := rlp.EncodeToBytes(uint64(i))
			if err := tr.Update(k, value(i)); err != nil {
				t.Fatal(err)
			}
		}
		root := tr.Hash()
		i := int(index) % (n + 1)
		k, _ := rlp.EncodeToBytes(uint64(i))
		var p orderedProof
		if err := tr.Prove(k, &p); err != nil {
			t.Fatal(err)
		}
		got, err := walkProof(root, uint64(i), p)
		switch {
		case err != nil && strings.HasPrefix(err.Error(), "trie proof walk:"):
			t.Fatalf("n=%d key %d: walkProof recovered from a panic: %v", n, i, err)
		case i == n && err == nil:
			t.Fatalf("n=%d: key %d is not in the trie, and the walk returned %x", n, i, got)
		case i < n && (err != nil || !bytes.Equal(got, value(i))):
			t.Fatalf("n=%d key %d: %x, %v", n, i, got, err)
		}
		if len(p) > 1 {
			if _, err := walkProof(root, uint64(i), p[:len(p)-1]); err == nil {
				t.Fatalf("n=%d key %d: a proof without its last node walks", n, i)
			}
		}
		if _, err := walkProof(root, uint64(i), append(append(orderedProof{}, p...), p[len(p)-1])); err == nil {
			t.Fatalf("n=%d key %d: a proof with a node repeated at its end walks", n, i)
		}
		// One bit changed in one node: that node no longer hashes to what
		// the root or its parent names.
		tampered := append(orderedProof{}, p...)
		at := int(index) % len(p)
		node := append([]byte{}, p[at]...)
		bit := int(vlen) + len(salt)
		node[bit/8%len(node)] ^= 1 << (bit % 8)
		tampered[at] = node
		if _, err := walkProof(root, uint64(i), tampered); err == nil {
			t.Fatalf("n=%d key %d: a proof with node %d changed walks", n, i, at)
		}
	})
}

// FuzzWalkNode runs walkProof over a proof whose first node is any bytes,
// its hash taken as the root, so every node passes the first check and the
// rest of the walk reads what the fuzzer wrote, embedded nodes included. It
// never panics (walkProof recovers from a panic, and that error is a failure
// here), and a value it returns is the node's own.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzWalkNode fuzzes.
func FuzzWalkNode(f *testing.F) {
	_, pubs := readEVMVectors(f)
	for _, p := range pubs {
		proof, _ := p["txProof"].([]any)
		idx, _ := p["txIndex"].(float64)
		for i, node := range proof {
			f.Add(hexBytes(node), uint64(idx), i == len(proof)-1)
		}
	}
	// A leaf whose path is empty: an even leaf flag and no nibble.
	f.Add([]byte{0xc2, 0x20, 0x01}, uint64(0), true)
	f.Fuzz(func(t *testing.T, node []byte, index uint64, last bool) {
		nodes := [][]byte{node}
		if !last {
			nodes = append(nodes, node)
		}
		val, err := walkProof(crypto.Keccak256Hash(node), index, nodes)
		if err != nil {
			if strings.HasPrefix(err.Error(), "trie proof walk:") {
				t.Fatalf("walkProof recovered from a panic: %v", err)
			}
			return
		}
		if len(val) == 0 || !bytes.Contains(node, val) {
			t.Fatalf("the walk returned %x, which the node does not hold", val)
		}
	})
}

// FuzzParseStaticSource runs the header-source file reader on any bytes. A
// source it reads has a positive chain id and a declared finality, and the
// report can state it: Describe serializes.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzParseStaticSource fuzzes.
func FuzzParseStaticSource(f *testing.F) {
	for _, s := range []string{
		`{"chainId":31337,"finality":"finalized","finalizedBlockNumber":6,"blocks":[{"number":1,"hash":"0x2163f675e7e2ea6b419cab81b4bcd18e5b46c26667df8ab09c139468cde04230","timestamp":1790876430}]}`,
		`{"chainId":1,"finality":{"confirmations":12,"acceptNonFinal":true},"finalizedBlockNumber":0,"blocks":[]}`,
		`{"chainId":1,"finality":{"confirmations":64},"finalizedBlockNumber":0,"blocks":[]}`,
	} {
		f.Add([]byte(s))
	}
	cases, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "bundle-b1", "*", "inputs.json"))
	for _, c := range cases {
		b, err := os.ReadFile(c)
		if err != nil {
			f.Fatal(err)
		}
		var in struct {
			HeaderSources map[string]json.RawMessage `json:"headerSources"`
		}
		if json.Unmarshal(b, &in) == nil {
			for _, k := range slices.Sorted(maps.Keys(in.HeaderSources)) {
				f.Add([]byte(in.HeaderSources[k]))
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		src, err := ParseStaticSource(data)
		if err != nil {
			if src != nil {
				t.Fatalf("a source returned with %v", err)
			}
			return
		}
		if src.Chain == nil || src.Chain.Sign() <= 0 || !src.Mode.Declared {
			t.Fatalf("chain %v, finality %+v", src.Chain, src.Mode)
		}
		if _, err := canonical.Serialize(report.Obj("source", src.Describe(), "finality", src.Mode.JSON())); err != nil {
			t.Fatalf("the source cannot be stated: %v", err)
		}
	})
}

// FuzzVerify runs §10.4 over any publication entry and any manifest, against
// the header source of evm-anchor-vectors.json, which answers for the
// vectors' block and transaction. The vectors' own publication verifies
// true before fuzzing starts. Verify recovers from a panic as the
// reason evm_verifier_error, which is a failure here. Every check is one of
// the four outcomes, under its own id, and the publication level follows
// the checks (Anchor §10.1): false exactly when a check is checked-wrong,
// true exactly when both are checked-correct.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzVerify fuzzes.
func FuzzVerify(f *testing.F) {
	v, pubs := readEVMVectors(f)
	manifest := func(bounds map[string]any) []byte {
		var e map[string]any
		_ = json.Unmarshal(v.ManifestEnt, &e)
		for k, b := range bounds {
			e[k] = b
		}
		b, _ := json.Marshal(map[string]any{"publishers": map[string]any{v.AnchorOrigin: []any{e}}})
		return b
	}
	for _, p := range pubs {
		full, _ := json.Marshal(p)
		bare := map[string]any{}
		for k, x := range p {
			switch k {
			case "blockHeader", "txIndex", "txProof":
			default:
				bare[k] = x
			}
		}
		noHeader, _ := json.Marshal(bare)
		f.Add(full, manifest(nil))
		f.Add(noHeader, manifest(nil))
		for _, vb := range v.ValidityBounds {
			f.Add(full, manifest(vb.Bounds))
		}
	}
	// The vectors' transaction replaced by one that item 2 refuses, for each
	// rule.
	for _, c := range item2Cases {
		if c.sender != "" {
			continue
		}
		refused := map[string]any{}
		for k, x := range pubs[0] {
			refused[k] = x
		}
		delete(refused, "transactionId")
		refused["rawTransaction"] = "0x" + c.raw
		b, _ := json.Marshal(refused)
		f.Add(b, manifest(nil))
	}
	P := hexBytes(v.P)
	src := &StaticSource{Chain: new(big.Int).SetUint64(v.HeaderSource.ChainID), Mode: Finality{Declared: true, Finalized: true},
		Finalized: v.HeaderSource.Finalized, Blocks: map[uint64]Block{}, Txs: map[common.Hash]TxLookup{}}
	for _, b := range v.HeaderSource.Blocks {
		src.Blocks[b.Number] = Block{Hash: common.HexToHash(b.Hash), Time: b.Timestamp}
	}
	for _, x := range v.HeaderSource.Transactions {
		bh, bn, from := common.HexToHash(x.BlockHash), x.BlockNumber, common.HexToAddress(x.From)
		src.Txs[common.HexToHash(x.TransactionID)] = TxLookup{BlockHash: &bh, BlockNumber: &bn, Sender: &from}
	}
	verify := func(entry, manifest []byte) (Result, bool) {
		e, err := jsonv.Parse(entry)
		if err != nil {
			return Result{}, false
		}
		m, _ := jsonv.Parse(manifest)
		return Verify(Input{Index: 3, Entry: e, P: P, AnchorOrigin: v.AnchorOrigin, Manifest: m,
			Sources: Sources{ByChain: map[string]HeaderSource{"eip155:31337": src}}, Deadline: time.Now().Add(10 * time.Second)}), true
	}
	// The vectors' publication is true: a target whose seeds verify nothing
	// would not notice a check that refuses every publication.
	full, _ := json.Marshal(pubs[0])
	if r, _ := verify(full, manifest(nil)); r.Valid == nil || !*r.Valid {
		f.Fatalf("the vectors' publication is not true: %+v", r)
	}
	f.Fuzz(func(t *testing.T, entry, manifest []byte) {
		r, ok := verify(entry, manifest)
		if !ok {
			return
		}
		if r.Tx.Reason == ReasonVerifierError {
			t.Fatalf("Verify recovered from a panic")
		}
		wrong, correct := 0, 0
		for _, c := range []struct {
			check report.Check
			id    string
		}{{r.Tx, "anchor.evm.tx[3]"}, {r.Canonical, "anchor.evm.canonical[3]"}} {
			if c.check.ID != c.id {
				t.Fatalf("check id %q, want %q", c.check.ID, c.id)
			}
			switch c.check.Outcome {
			case report.Wrong:
				wrong++
			case report.Correct:
				correct++
			case report.NotChecked, report.Abstain:
			default:
				t.Fatalf("%s: outcome %q", c.id, c.check.Outcome)
			}
		}
		switch {
		case r.Valid == nil:
			if wrong > 0 || correct == 2 || r.Reason == "" {
				t.Fatalf("null with %d wrong, %d correct, reason %q", wrong, correct, r.Reason)
			}
		case *r.Valid:
			if correct != 2 || r.Reason != "" {
				t.Fatalf("true with %d correct, reason %q", correct, r.Reason)
			}
		default:
			if wrong == 0 || r.Reason == "" {
				t.Fatalf("false with no check wrong, reason %q", r.Reason)
			}
		}
	})
}
