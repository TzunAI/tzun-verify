// SPDX-License-Identifier: BSD-3-Clause-Clear

package evm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
)

const origin = "test.example/0123456789abcdef0123456789abcdef/anchors"

var testP = func() []byte { s := sha256.Sum256([]byte("anchor checkpoint")); return s[:] }()

// txOpts describes the publication transaction a fixture signs.
type txOpts struct {
	txType    byte // 0 legacy, 1, 2
	chainID   int64
	unprotect bool // pre-EIP-155 legacy
	data      []byte
}

// fixture is one publication mined in a synthetic block: the raw
// transaction, the block header and the transactions-trie proof.
type fixture struct {
	key       *ecdsa.PrivateKey
	sender    common.Address
	chainID   *big.Int
	raw       []byte
	txID      common.Hash
	header    []byte
	blockHash common.Hash
	blockNum  uint64
	blockTime uint64
	index     uint64
	proof     [][]byte
	// proofs holds the trie proof of every transaction in the block, and
	// raws their encodings.
	proofs map[uint64][][]byte
	raws   map[uint64][]byte
}

func signTx(t *testing.T, key *ecdsa.PrivateKey, o txOpts, nonce uint64) *types.Transaction {
	t.Helper()
	cid := big.NewInt(o.chainID)
	to := crypto.PubkeyToAddress(key.PublicKey)
	var inner types.TxData
	switch o.txType {
	case 0:
		inner = &types.LegacyTx{Nonce: nonce, GasPrice: big.NewInt(1e9), Gas: 30000, To: &to, Data: o.data}
	case 1:
		inner = &types.AccessListTx{ChainID: cid, Nonce: nonce, GasPrice: big.NewInt(1e9), Gas: 30000, To: &to, Data: o.data}
	default:
		inner = &types.DynamicFeeTx{ChainID: cid, Nonce: nonce, GasTipCap: big.NewInt(1e9), GasFeeCap: big.NewInt(3e9), Gas: 30000, To: &to, Data: o.data}
	}
	var signer types.Signer = types.NewLondonSigner(cid)
	if o.txType == 0 && o.unprotect {
		signer = types.HomesteadSigner{}
	}
	tx, err := types.SignNewTx(key, signer, inner)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func newFixture(t *testing.T, o txOpts) *fixture {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := crypto.GenerateKey()
	if o.data == nil {
		o.data = testP
	}
	if o.chainID == 0 {
		o.chainID = 11155111
	}
	f := &fixture{key: key, sender: crypto.PubkeyToAddress(key.PublicKey), chainID: big.NewInt(o.chainID),
		blockNum: 7123456, blockTime: 1790000000, index: 2}
	// A block of four transactions; the publication is at index 2.
	var txs []*types.Transaction
	for i := 0; i < 4; i++ {
		if uint64(i) == f.index {
			txs = append(txs, signTx(t, key, o, 0))
		} else {
			txs = append(txs, signTx(t, other, txOpts{txType: 2, chainID: o.chainID, data: []byte{byte(i)}}, uint64(i)))
		}
	}
	tr := trie.NewEmpty(nil)
	for i, tx := range txs {
		k, _ := rlp.EncodeToBytes(uint64(i))
		v, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.Update(k, v); err != nil {
			t.Fatal(err)
		}
	}
	root := tr.Hash()
	f.proofs, f.raws = map[uint64][][]byte{}, map[uint64][]byte{}
	for i := range txs {
		var path orderedProof
		k, _ := rlp.EncodeToBytes(uint64(i))
		if err := tr.Prove(k, &path); err != nil {
			t.Fatal(err)
		}
		f.proofs[uint64(i)] = path
		f.raws[uint64(i)], _ = txs[i].MarshalBinary()
	}
	f.proof = f.proofs[f.index]
	h := &types.Header{
		ParentHash: common.HexToHash("0x01"), UncleHash: types.EmptyUncleHash, Root: common.HexToHash("0x02"),
		TxHash: root, ReceiptHash: types.EmptyReceiptsHash, Difficulty: big.NewInt(0),
		Number: new(big.Int).SetUint64(f.blockNum), GasLimit: 30_000_000, GasUsed: 100_000,
		Time: f.blockTime, BaseFee: big.NewInt(1e9),
	}
	f.header, err = rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	f.blockHash = crypto.Keccak256Hash(f.header)
	f.raw, _ = txs[f.index].MarshalBinary()
	f.txID = crypto.Keccak256Hash(f.raw)
	return f
}

func hx(b []byte) string { return "0x" + fmt.Sprintf("%x", b) }

// orderedProof receives a trie proof's nodes in the order go-ethereum
// writes them, root first, which is the order txProof carries them in.
type orderedProof [][]byte

func (p *orderedProof) Put(_, value []byte) error {
	*p = append(*p, append([]byte{}, value...))
	return nil
}

func (p *orderedProof) Delete([]byte) error { return nil }

// entry renders the joined publication; drop names members to leave out.
func (f *fixture) entry(drop ...string) *jsonv.Value {
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d] = true
	}
	o := report.Obj()
	add := func(k string, v *jsonv.Value) {
		if !skip[k] {
			o.O = append(o.O, jsonv.Member{Key: k, Value: v})
		}
	}
	add("kind", report.S(Kind))
	add("chain", report.S("eip155:"+f.chainID.String()))
	add("transactionId", report.S(strings.ToLower(f.txID.Hex())))
	add("blockNumber", report.N(f.blockNum))
	add("blockHash", report.S(strings.ToLower(f.blockHash.Hex())))
	add("publisher", report.S(strings.ToLower(f.sender.Hex())))
	add("rawTransaction", report.S(hx(f.raw)))
	add("blockHeader", report.S(hx(f.header)))
	add("txIndex", report.N(f.index))
	proof := report.Arr()
	for _, n := range f.proof {
		proof.A = append(proof.A, report.S(hx(n)))
	}
	add("txProof", proof)
	return o
}

func set(o *jsonv.Value, k string, v *jsonv.Value) *jsonv.Value {
	c := &jsonv.Value{Kind: jsonv.Object, O: append([]jsonv.Member{}, o.O...)}
	for i := range c.O {
		if c.O[i].Key == k {
			c.O[i].Value = v
			return c
		}
	}
	c.O = append(c.O, jsonv.Member{Key: k, Value: v})
	return c
}

// manifestFor lists the fixture's sender for origin, with extra entry
// members (validFrom, validUntil, namespace overrides).
func (f *fixture) manifest(chain string, extra ...any) *jsonv.Value {
	if chain == "" {
		chain = "eip155:" + f.chainID.String()
	}
	e := report.Obj("address", report.S(strings.ToLower(f.sender.Hex())), "chain", report.S(chain), "namespace", report.S("test"))
	for i := 0; i+1 < len(extra); i += 2 {
		e = set(e, extra[i].(string), extra[i+1].(*jsonv.Value))
	}
	return report.Obj("publishers", report.Obj(origin, report.Arr(e)))
}

func (f *fixture) source() *StaticSource {
	return &StaticSource{
		Chain: f.chainID, Mode: Finality{Declared: true, Finalized: true}, Finalized: f.blockNum + 10,
		Blocks: map[uint64]Block{f.blockNum: {Hash: f.blockHash, Time: f.blockTime}},
	}
}

func run(entry, manifest *jsonv.Value, src HeaderSource) Result {
	in := Input{Index: 0, Entry: entry, P: testP, AnchorOrigin: origin, Manifest: manifest,
		Deadline: time.Now().Add(2 * time.Second)}
	if src != nil {
		in.Sources = Sources{Any: src}
	}
	return Verify(in)
}

type want struct {
	valid     string // "true", "false", "null"
	reason    string // publication-level reason
	tx        report.Outcome
	txReason  string
	can       report.Outcome
	canReason string
}

func check(t *testing.T, name string, r Result, w want) {
	t.Helper()
	valid := "null"
	if r.Valid != nil {
		valid = fmt.Sprint(*r.Valid)
	}
	if valid != w.valid || r.Reason != w.reason {
		t.Errorf("%s: publication %s %q, want %s %q", name, valid, r.Reason, w.valid, w.reason)
	}
	if w.tx != "" && (r.Tx.Outcome != w.tx || r.Tx.Reason != w.txReason) {
		t.Errorf("%s: tx %s %q, want %s %q", name, r.Tx.Outcome, r.Tx.Reason, w.tx, w.txReason)
	}
	if w.can != "" && (r.Canonical.Outcome != w.can || r.Canonical.Reason != w.canReason) {
		t.Errorf("%s: canonical %s %q, want %s %q", name, r.Canonical.Outcome, r.Canonical.Reason, w.can, w.canReason)
	}
}

var ok = want{valid: "true", tx: report.Correct, can: report.Correct}

func TestPublicationTrue(t *testing.T) {
	for _, typ := range []byte{0, 1, 2} {
		f := newFixture(t, txOpts{txType: typ})
		r := run(f.entry(), f.manifest(""), f.source())
		check(t, fmt.Sprintf("type %d, trie proof", typ), r, ok)
		if r.Inclusion != "tx_proof" || r.Network != "testnet" || r.Chain != "eip155:11155111" ||
			r.Namespace == nil || *r.Namespace != "test" || r.BlockTime != f.blockTime {
			t.Errorf("type %d: facts %+v", typ, r)
		}
		if v, _ := r.Tx.Fact("sender"); v == nil || v.S != strings.ToLower(f.sender.Hex()) {
			t.Errorf("type %d: sender fact", typ)
		}
		if v, _ := r.Tx.Fact("txType"); v == nil || v.N != float64(typ) {
			t.Errorf("type %d: txType fact", typ)
		}
	}
}

func TestPlacedByHeaderSource(t *testing.T) {
	f := newFixture(t, txOpts{txType: 2})
	src := f.source()
	num := f.blockNum
	src.Txs = map[common.Hash]TxLookup{f.txID: {BlockHash: &f.blockHash, BlockNumber: &num, Sender: &f.sender}}
	r := run(f.entry("blockHeader", "txIndex", "txProof"), f.manifest(""), src)
	check(t, "lookup places it", r, ok)
	if r.Inclusion != "header_source" {
		t.Errorf("inclusion %q", r.Inclusion)
	}
	// Nothing places it: no lookup, no proof.
	r = run(f.entry("blockHeader", "txIndex", "txProof"), f.manifest(""), f.source())
	check(t, "nothing places it", r, want{valid: "null", reason: ReasonNotChecked, tx: report.Correct, can: report.NotChecked, canReason: ReasonNoTxProof})
	// A trie proof carried without a header is not walked.
	r = run(f.entry("blockHeader"), f.manifest(""), f.source())
	check(t, "proof without header", r, want{valid: "null", reason: ReasonNotChecked, can: report.NotChecked, canReason: ReasonNoHeader})
	// A bundle entry without transactionId.
	r = run(f.entry("transactionId"), f.manifest(""), f.source())
	check(t, "no transactionId", r, ok)
}

func TestOfflineFailures(t *testing.T) {
	f := newFixture(t, txOpts{txType: 2})
	fail := func(reason string) want {
		return want{valid: "false", reason: reason, tx: report.Wrong, txReason: reason}
	}

	other := newFixture(t, txOpts{txType: 2, data: []byte("not P")})
	check(t, "calldata", run(other.entry(), other.manifest(""), other.source()), fail(ReasonCalldataMismatch))

	stranger := f.manifest("")
	stranger = report.Obj("publishers", report.Obj(origin, report.Arr(report.Obj(
		"address", report.S("0x"+strings.Repeat("ab", 20)), "chain", report.S("eip155:11155111"), "namespace", report.S("test")))))
	check(t, "stranger", run(f.entry(), stranger, f.source()), fail(ReasonSenderMismatch))

	check(t, "manifest chain", run(f.entry(), f.manifest("eip155:1"), f.source()), fail(ReasonChainMismatch))

	wrongChain := newFixture(t, txOpts{txType: 2, chainID: 5})
	check(t, "signed chain", run(wrongChain.entry(), wrongChain.manifest("eip155:11155111"), wrongChain.source()), fail(ReasonChainMismatch))

	pre155 := newFixture(t, txOpts{txType: 0, unprotect: true})
	check(t, "pre-EIP-155", run(pre155.entry(), pre155.manifest("eip155:11155111"), pre155.source()), fail(ReasonChainMismatch))

	tampered := f.entry()
	nodes := append([]byte{}, f.proof[len(f.proof)-1]...)
	nodes[len(nodes)-1] ^= 1
	proof := report.Arr()
	for _, n := range f.proof[:len(f.proof)-1] {
		proof.A = append(proof.A, report.S(hx(n)))
	}
	proof.A = append(proof.A, report.S(hx(nodes)))
	check(t, "tampered trie node", run(set(tampered, "txProof", proof), f.manifest(""), f.source()), fail(ReasonTxProofInvalid))

	check(t, "wrong index", run(set(f.entry(), "txIndex", report.N(1)), f.manifest(""), f.source()), fail(ReasonTxProofInvalid))
	// A valid proof of another transaction in the same block.
	otherProof := report.Arr()
	for _, n := range f.proofs[1] {
		otherProof.A = append(otherProof.A, report.S(hx(n)))
	}
	check(t, "another transaction's proof", run(set(set(f.entry(), "txIndex", report.N(1)), "txProof", otherProof), f.manifest(""), f.source()),
		fail(ReasonTxProofInvalid))

	// txProof is a path, root first, every node used once (§10.4 item 6):
	// the same nodes out of order, repeated, beside a foreign node, or with
	// junk at either end are not a walk from transactionsRoot.
	asArr := func(nodes ...[]byte) *jsonv.Value {
		a := report.Arr()
		for _, n := range nodes {
			a.A = append(a.A, report.S(hx(n)))
		}
		return a
	}
	if len(f.proof) < 2 {
		t.Fatalf("the fixture's proof has %d nodes; the order cases need two or more", len(f.proof))
	}
	reversed := make([][]byte, len(f.proof))
	for i, n := range f.proof {
		reversed[len(f.proof)-1-i] = n
	}
	foreign := f.proofs[1][len(f.proofs[1])-1]
	junk := []byte{0xc2, 0x80, 0x80}
	for _, c := range []struct {
		name  string
		nodes [][]byte
	}{
		{"proof nodes reordered", reversed},
		{"a proof node repeated", append(append([][]byte{}, f.proof...), f.proof[len(f.proof)-1])},
		{"the root node repeated first", append([][]byte{f.proof[0]}, f.proof...)},
		{"a foreign node appended", append(append([][]byte{}, f.proof...), foreign)},
		{"a foreign node first", append([][]byte{foreign}, f.proof...)},
		{"junk appended", append(append([][]byte{}, f.proof...), junk)},
		{"junk first", append([][]byte{junk}, f.proof...)},
		{"the last node left out", f.proof[:len(f.proof)-1]},
	} {
		check(t, c.name, run(set(f.entry(), "txProof", asArr(c.nodes...)), f.manifest(""), f.source()), fail(ReasonTxProofInvalid))
	}
	// A leaf holding the raw transaction at the whole key, alone: a walk
	// that did not start at transactionsRoot would accept it.
	k, _ := rlp.EncodeToBytes(f.index)
	path := append([]byte{0x20}, k...)
	lone, _ := rlp.EncodeToBytes([][]byte{path, f.raw})
	check(t, "a leaf alone, not under transactionsRoot", run(set(f.entry(), "txProof", asArr(lone)), f.manifest(""), f.source()), fail(ReasonTxProofInvalid))
	check(t, "the proof in order", run(set(f.entry(), "txProof", asArr(f.proof...)), f.manifest(""), f.source()),
		want{valid: "true", tx: report.Correct, can: report.Correct})

	badHeader := append([]byte{}, f.header...)
	badHeader[len(badHeader)-1] ^= 1
	check(t, "header hash", run(set(f.entry(), "blockHeader", report.S(hx(badHeader))), f.manifest(""), f.source()), fail(ReasonTxProofInvalid))
	check(t, "header number", run(set(f.entry(), "blockNumber", report.N(f.blockNum+1)), f.manifest(""), f.source()), fail(ReasonTxProofInvalid))

	check(t, "transactionId", run(set(f.entry(), "transactionId", report.S("0x"+strings.Repeat("11", 32))), f.manifest(""), f.source()), fail(ReasonTxProofInvalid))

	blob := append([]byte{0x03}, f.raw[1:]...)
	check(t, "type 3", run(set(f.entry("transactionId"), "rawTransaction", report.S(hx(blob))), f.manifest(""), f.source()),
		want{valid: "null", reason: ReasonUnsupportedTxType, tx: report.Abstain, txReason: ReasonUnsupportedTxType})
	strRLP := append([]byte{0x85}, f.raw[1:]...)
	check(t, "0x80..0xbf", run(set(f.entry("transactionId"), "rawTransaction", report.S(hx(strRLP))), f.manifest(""), f.source()), fail(ReasonMalformed))
	garbage := append([]byte{0x02}, 0xff, 0x00)
	check(t, "unparseable", run(set(f.entry("transactionId"), "rawTransaction", report.S(hx(garbage))), f.manifest(""), f.source()), fail(ReasonMalformed))
}

func TestShape(t *testing.T) {
	f := newFixture(t, txOpts{txType: 2})
	nc := func(reason string) want {
		return want{valid: "null", reason: ReasonNotChecked, tx: report.NotChecked, txReason: reason}
	}
	fail := want{valid: "false", reason: ReasonMalformed, tx: report.Wrong, txReason: ReasonMalformed}
	check(t, "no raw", run(f.entry("rawTransaction"), f.manifest(""), f.source()), nc(ReasonNoRaw))
	check(t, "null raw", run(set(f.entry(), "rawTransaction", report.Null()), f.manifest(""), f.source()), nc(ReasonNoRaw))
	check(t, "odd hex", run(set(f.entry(), "rawTransaction", report.S("0x123")), f.manifest(""), f.source()), fail)
	check(t, "no 0x", run(set(f.entry(), "rawTransaction", report.S(fmt.Sprintf("%x", f.raw))), f.manifest(""), f.source()), fail)
	check(t, "index without proof", run(f.entry("txProof"), f.manifest(""), f.source()), fail)
	check(t, "empty proof", run(set(f.entry(), "txProof", report.Arr()), f.manifest(""), f.source()), fail)
	check(t, "fractional block number", run(set(f.entry(), "blockNumber", &jsonv.Value{Kind: jsonv.Number, N: 1.5}), f.manifest(""), f.source()), fail)
	check(t, "short block hash", run(set(f.entry(), "blockHash", report.S("0x12")), f.manifest(""), f.source()), fail)

	r := Verify(Input{Entry: f.entry(), P: testP[:31], AnchorOrigin: origin, Manifest: f.manifest(""), Deadline: time.Now().Add(time.Second)})
	check(t, "short P", r, nc(ReasonNoP))
	r = Verify(Input{Entry: report.Arr(), P: testP, Deadline: time.Now().Add(time.Second)})
	check(t, "not an object", r, fail)
	r = Verify(Input{Entry: set(f.entry(), "kind", report.S("evm-calldata/2")), P: testP, Deadline: time.Now().Add(time.Second)})
	check(t, "other kind", r, want{valid: "null", reason: ReasonUnsupportedKind, tx: report.Abstain, txReason: ReasonUnsupportedKind})
}

func TestManifestReadings(t *testing.T) {
	f := newFixture(t, txOpts{txType: 2})
	nc := func(reason string) want {
		return want{valid: "null", reason: ReasonNotChecked, tx: report.NotChecked, txReason: reason}
	}
	sender := strings.ToLower(f.sender.Hex())
	cases := []struct {
		name string
		m    *jsonv.Value
		w    want
	}{
		{"absent manifest", nil, nc(ReasonNoExpectation)},
		{"not an object", report.Arr(), nc(ReasonNoExpectation)},
		{"absent publishers", report.Obj(), nc(ReasonNoExpectation)},
		{"origin with no key", report.Obj("publishers", report.Obj("other/x/anchors", report.Arr())), nc(ReasonNoExpectation)},
		{"all entries outside eip155", report.Obj("publishers", report.Obj(origin, report.Arr(report.Obj("chain", report.S("bip122:000000000019d6689c085ae165831e93"))))), nc(ReasonNoExpectation)},
		{"value not an array", report.Obj("publishers", report.Obj(origin, report.Obj())), nc(ReasonManifestUnreadable)},
		{"element not an object", report.Obj("publishers", report.Obj(origin, report.Arr(report.S("x")))), nc(ReasonManifestUnreadable)},
		{"chain not a string", report.Obj("publishers", report.Obj(origin, report.Arr(report.Obj("chain", report.N(1))))), nc(ReasonManifestUnreadable)},
		{"bad address", report.Obj("publishers", report.Obj(origin, report.Arr(report.Obj("address", report.S("0x12"), "chain", report.S("eip155:11155111"), "namespace", report.S("test"))))), nc(ReasonManifestUnreadable)},
		{"leading zero chain", report.Obj("publishers", report.Obj(origin, report.Arr(report.Obj("address", report.S(sender), "chain", report.S("eip155:011155111"), "namespace", report.S("test"))))), nc(ReasonManifestUnreadable)},
		{"bad namespace", report.Obj("publishers", report.Obj(origin, report.Arr(report.Obj("address", report.S(sender), "chain", report.S("eip155:11155111"), "namespace", report.S("prod"))))), nc(ReasonManifestUnreadable)},
	}
	for _, bad := range []string{"2026-01-01t00:00:00Z", "2026-01-01T00:00:00z", "2026-01-01T00:00:60Z", "2026-09-31T00:00:00Z", "2026-01-01T24:00:00Z", "2026-01-01T00:00:00+24:00", "2026-01-01 00:00:00Z"} {
		cases = append(cases, struct {
			name string
			m    *jsonv.Value
			w    want
		}{"validFrom " + bad, f.manifest("", "validFrom", report.S(bad)), nc(ReasonManifestUnreadable)})
	}
	for _, c := range cases {
		check(t, c.name, run(f.entry(), c.m, f.source()), c.w)
	}
	// An address in another case still matches; unknown members are ignored.
	upper := report.Obj("publishers", report.Obj(origin, report.Arr(report.Obj("address", report.S(f.sender.Hex()), "chain", report.S("eip155:11155111"), "namespace", report.S("test"), "note", report.S("x")))))
	check(t, "checksummed address", run(f.entry(), upper, f.source()), ok)
}

func TestValidityWindow(t *testing.T) {
	f := newFixture(t, txOpts{txType: 2})
	iso := func(sec int64, frac string) *jsonv.Value {
		return report.S(time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05") + frac + "Z")
	}
	bt := int64(f.blockTime)
	senderFail := want{valid: "false", reason: ReasonSenderMismatch, tx: report.Wrong, txReason: ReasonSenderMismatch}
	// With a header, the window is decided offline, at the header's time,
	// and the node is never asked.
	headerFail := senderFail
	headerFail.can, headerFail.canReason = report.NotChecked, "blocked_by:anchor.evm.tx[0]"
	check(t, "validFrom .0005 after the block second", run(f.entry(), f.manifest("", "validFrom", iso(bt, ".0005")), f.source()), headerFail)
	check(t, "outside the window at the header's time, offline", run(f.entry(), f.manifest("", "validUntil", iso(bt-1, "")), nil), headerFail)
	check(t, "validFrom .0005 before the block second", run(f.entry(), f.manifest("", "validFrom", iso(bt-1, ".0005")), f.source()), ok)
	check(t, "validUntil exactly the block time", run(f.entry(), f.manifest("", "validUntil", iso(bt, "")), f.source()), ok)
	check(t, "validUntil with a fraction", run(f.entry(), f.manifest("", "validUntil", iso(bt, ".999")), f.source()), ok)
	check(t, "validUntil a second before", run(f.entry(), f.manifest("", "validUntil", iso(bt-1, ".999")), f.source()), senderFail)
	offset := report.S(time.Unix(bt, 0).In(time.FixedZone("", -5*3600)).Format("2006-01-02T15:04:05-07:00"))
	check(t, "validFrom with an offset", run(f.entry(), f.manifest("", "validFrom", offset), f.source()), ok)

	// Without a header, a bounded window waits for the confirmed block time.
	noHeader := f.entry("blockHeader", "txIndex", "txProof")
	pending := run(noHeader, f.manifest("", "validUntil", iso(bt-1, "")), nil)
	check(t, "bounded window, no header, no source", pending, want{valid: "null", reason: ReasonNotChecked,
		tx: report.NotChecked, txReason: ReasonNoHeader, can: report.NotChecked, canReason: ReasonNoSource})
	src := f.source()
	num := f.blockNum
	src.Txs = map[common.Hash]TxLookup{f.txID: {BlockHash: &f.blockHash, BlockNumber: &num, Sender: &f.sender}}
	check(t, "bounded window decided at the confirmed time", run(noHeader, f.manifest("", "validUntil", iso(bt-1, "")), src),
		want{valid: "false", reason: ReasonSenderMismatch, tx: report.Wrong, txReason: ReasonSenderMismatch, can: report.Correct})
	check(t, "bounded window holds at the confirmed time", run(noHeader, f.manifest("", "validUntil", iso(bt, "")), src), ok)
}

// slowSource never answers before its context ends.
type slowSource struct{ StaticSource }

func (s *slowSource) ChainID(ctx context.Context) (*big.Int, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestHeaderSourceStates(t *testing.T) {
	f := newFixture(t, txOpts{txType: 2})
	nc := func(reason string) want {
		return want{valid: "null", reason: ReasonNotChecked, tx: report.Correct, can: report.NotChecked, canReason: reason}
	}
	check(t, "no source", run(f.entry(), f.manifest(""), nil), nc(ReasonNoSource))

	notFinal := f.source()
	notFinal.Finalized = f.blockNum - 1
	r := run(f.entry(), f.manifest(""), notFinal)
	check(t, "not final", r, nc(ReasonNotFinalized))
	if v, _ := r.Canonical.Fact("finality"); v == nil || v.S != "finalized" {
		t.Errorf("not final: the finality fact is reported once the chain matched")
	}

	other := f.source()
	other.Chain = big.NewInt(1)
	r = run(f.entry(), f.manifest(""), other)
	check(t, "source chain", r, nc(ReasonSourceChain))
	if _, ok := r.Canonical.Fact("finality"); ok {
		t.Errorf("source chain mismatch: no finality fact before the chain matched")
	}

	reorg := f.source()
	reorg.Blocks[f.blockNum] = Block{Hash: common.HexToHash("0xdead"), Time: f.blockTime}
	check(t, "another canonical block", run(f.entry(), f.manifest(""), reorg),
		want{valid: "false", reason: ReasonNotFoundOnChain, tx: report.Correct, can: report.Wrong, canReason: ReasonNotFoundOnChain})

	empty := f.source()
	delete(empty.Blocks, f.blockNum)
	check(t, "no block at a final height", run(f.entry(), f.manifest(""), empty), nc(ReasonInconsistent))

	timeDiffers := f.source()
	timeDiffers.Blocks[f.blockNum] = Block{Hash: f.blockHash, Time: f.blockTime + 1}
	check(t, "timestamp differs from the header", run(f.entry(), f.manifest(""), timeDiffers), nc(ReasonInconsistent))

	broken := f.source()
	broken.Err = errors.New("connection refused")
	check(t, "source fails", run(f.entry(), f.manifest(""), broken), nc(ReasonUnavailable))

	slow := &slowSource{StaticSource: *f.source()}
	in := Input{Entry: f.entry(), P: testP, AnchorOrigin: origin, Manifest: f.manifest(""), Sources: Sources{Any: slow},
		Deadline: time.Now().Add(50 * time.Millisecond)}
	check(t, "timeout", Verify(in), nc(ReasonTimeout))

	num := f.blockNum
	otherBlock := common.HexToHash("0xbeef")
	otherNum := f.blockNum + 1
	stranger := common.HexToAddress("0x" + strings.Repeat("cd", 20))
	noProof := f.entry("blockHeader", "txIndex", "txProof")

	s := f.source()
	s.Txs = map[common.Hash]TxLookup{f.txID: {BlockHash: &f.blockHash, BlockNumber: &num, Sender: &stranger}}
	check(t, "lookup names another sender", run(noProof, f.manifest(""), s), nc(ReasonInconsistent))
	check(t, "lookup names another sender, with a trie proof", run(f.entry(), f.manifest(""), s), nc(ReasonInconsistent))

	s = f.source()
	s.Txs = map[common.Hash]TxLookup{f.txID: {BlockHash: &otherBlock, BlockNumber: &otherNum, Sender: &f.sender}}
	check(t, "lookup names a block the source does not call canonical", run(noProof, f.manifest(""), s), nc(ReasonInconsistent))
	s.Blocks[otherNum] = Block{Hash: otherBlock, Time: f.blockTime + 12}
	check(t, "lookup names another canonical block", run(noProof, f.manifest(""), s),
		want{valid: "false", reason: ReasonNotFoundOnChain, tx: report.Correct, can: report.Wrong, canReason: ReasonNotFoundOnChain})
	check(t, "lookup names another block, with a trie proof", run(f.entry(), f.manifest(""), s), nc(ReasonInconsistent))

	s = f.source()
	s.Txs = map[common.Hash]TxLookup{f.txID: {BlockHash: nil, Sender: &f.sender}}
	check(t, "pending lookup", run(noProof, f.manifest(""), s), nc(ReasonInconsistent))

	s = f.source()
	s.Txs = map[common.Hash]TxLookup{}
	check(t, "empty lookup with a trie proof", run(f.entry(), f.manifest(""), s), ok)
	check(t, "empty lookup without one", run(noProof, f.manifest(""), s), nc(ReasonNoTxProof))
}

func TestRecoverIsVerifierError(t *testing.T) {
	f := newFixture(t, txOpts{txType: 2})
	r := Verify(Input{Entry: f.entry(), P: testP, AnchorOrigin: origin, Manifest: f.manifest(""),
		Sources: Sources{Any: &panicSource{}}, Deadline: time.Now().Add(time.Second)})
	check(t, "panic", r, want{valid: "null", reason: ReasonNotChecked, tx: report.NotChecked, txReason: ReasonVerifierError})
}

type panicSource struct{ StaticSource }

func (*panicSource) ChainID(context.Context) (*big.Int, error) { panic("boom") }

// reheader rebuilds the fixture's header from its RLP items, changed by
// edit, and rehashes it: the entry and the header source then name the new
// hash, as they would for a genuine header of that shape.
func (f *fixture) reheader(t *testing.T, edit func([]rlp.RawValue) []rlp.RawValue) *fixture {
	t.Helper()
	var items []rlp.RawValue
	if err := rlp.DecodeBytes(f.header, &items); err != nil {
		t.Fatal(err)
	}
	b, err := rlp.EncodeToBytes(edit(items))
	if err != nil {
		t.Fatal(err)
	}
	g := *f
	g.header = b
	g.blockHash = crypto.Keccak256Hash(b)
	return &g
}

func rawOf(t *testing.T, v any) rlp.RawValue {
	t.Helper()
	b, err := rlp.EncodeToBytes(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHeaderMoreFieldsThanGoEthereumKnows(t *testing.T) {
	// A later fork appends fields. The header is read as a generic list, so
	// fields past the known layout, of any shape, never make a genuine
	// header read as tampered: only items 4, 8 and 11 are read
	// (Anchor §10.4 item 6, Yellow Paper §4.3), and keccak256 over
	// the whole header binds the rest.
	f := newFixture(t, txOpts{txType: 2})
	hash32 := rawOf(t, common.HexToHash("0xabcdef"))
	for n, extra := range map[string][]rlp.RawValue{
		"one hash":             {hash32},
		"two hashes":           {hash32, hash32},
		"hash then a 32-byte":  {hash32, rawOf(t, make([]byte, 32))},
		"a list and a string":  {rawOf(t, []uint64{1, 2, 3}), rawOf(t, "x")},
		"ten more":             {hash32, hash32, hash32, hash32, hash32, hash32, hash32, hash32, hash32, hash32},
		"a uint past 64 bits":  {rawOf(t, new(big.Int).Lsh(big.NewInt(1), 100))},
		"an empty string item": {rawOf(t, []byte{})},
	} {
		g := f.reheader(t, func(items []rlp.RawValue) []rlp.RawValue { return append(items, extra...) })
		check(t, n, run(g.entry(), g.manifest(""), g.source()), ok)
	}
}

func TestHeaderShape(t *testing.T) {
	f := newFixture(t, txOpts{txType: 2})
	fail := func(reason string) want {
		return want{valid: "false", reason: reason, tx: report.Wrong, txReason: reason}
	}
	bad := map[string]func([]rlp.RawValue) []rlp.RawValue{
		"fourteen fields": func(items []rlp.RawValue) []rlp.RawValue { return items[:14] },
		"root of 31 bytes": func(items []rlp.RawValue) []rlp.RawValue {
			items[4] = rawOf(t, make([]byte, 31))
			return items
		},
		"root a list": func(items []rlp.RawValue) []rlp.RawValue {
			items[4] = rawOf(t, []uint64{1})
			return items
		},
		"number with a leading zero byte": func(items []rlp.RawValue) []rlp.RawValue {
			n := new(big.Int).SetUint64(f.blockNum).Bytes()
			items[8] = rawOf(t, append([]byte{0}, n...))
			return items
		},
		"time above 2^53 - 1": func(items []rlp.RawValue) []rlp.RawValue {
			items[11] = rawOf(t, uint64(1)<<53)
			return items
		},
		"another number": func(items []rlp.RawValue) []rlp.RawValue {
			items[8] = rawOf(t, f.blockNum+1)
			return items
		},
	}
	for n, edit := range bad {
		g := f.reheader(t, edit)
		check(t, n, run(g.entry(), g.manifest(""), g.source()), fail(ReasonTxProofInvalid))
	}
	// A root that is not 32 bytes fails even when no trie proof is walked
	// from it.
	g31 := f.reheader(t, bad["root of 31 bytes"])
	check(t, "root of 31 bytes, no trie proof", run(g31.entry("txIndex", "txProof"), g31.manifest(""), g31.source()), fail(ReasonTxProofInvalid))

	// Trailing bytes after the list are not a header.
	g := *f
	g.header = append(append([]byte{}, f.header...), 0x80)
	g.blockHash = crypto.Keccak256Hash(g.header)
	check(t, "trailing byte", run(g.entry(), g.manifest(""), g.source()), fail(ReasonTxProofInvalid))
}

// nested is the RLP of lists nested the given number of deep, the
// innermost empty.
func nested(t *testing.T, lists int) rlp.RawValue {
	var v any = []any{}
	for i := 1; i < lists; i++ {
		v = []any{v}
	}
	return rawOf(t, v)
}

// TestRLPDepth: a header or a trie node may hold lists 64 deep, its own
// list at depth 1, and no deeper, in items that no rule otherwise reads
// (Anchor §10.4 item 6).
func TestRLPDepth(t *testing.T) {
	f := newFixture(t, txOpts{txType: 2})
	fail := want{valid: "false", reason: ReasonTxProofInvalid, tx: report.Wrong, txReason: ReasonTxProofInvalid}
	appended := func(extra rlp.RawValue) *fixture {
		return f.reheader(t, func(items []rlp.RawValue) []rlp.RawValue { return append(items, extra) })
	}
	g := appended(nested(t, 63))
	check(t, "header, lists 64 deep", run(g.entry(), g.manifest(""), g.source()), ok)
	g = appended(nested(t, 64))
	check(t, "header, lists 65 deep", run(g.entry(), g.manifest(""), g.source()), fail)
	// A list whose content is not RLP items: a string header claims three
	// bytes and two follow.
	g = appended(rlp.RawValue{0xc3, 0x83, 0x01, 0x02})
	check(t, "header, a list that is not RLP", run(g.entry(), g.manifest(""), g.source()), fail)

	// The root node of the transactions trie is a branch; the walk follows
	// one child and reads none of the others. Nesting lists in an unused
	// child, and pointing the header at the changed root, leaves a proof
	// that walks: 64 deep verifies, 65 does not.
	var items []rlp.RawValue
	if err := rlp.DecodeBytes(f.proof[0], &items); err != nil || len(items) != 17 {
		t.Fatalf("the root node is not a branch: %d items, %v", len(items), err)
	}
	key, _ := rlp.EncodeToBytes(f.index)
	unused := 15
	if int(key[0]>>4) == unused {
		unused = 14
	}
	for lists, w := range map[int]want{63: {valid: "true", tx: report.Correct, can: report.Correct}, 64: fail} {
		changed := append([]rlp.RawValue{}, items...)
		changed[unused] = nested(t, lists)
		node := rawOf(t, changed)
		root := crypto.Keccak256(node)
		h := f.reheader(t, func(hi []rlp.RawValue) []rlp.RawValue {
			hi[4] = rawOf(t, root)
			return hi
		})
		proof := report.Arr(report.S(hx(node)))
		for _, n := range f.proof[1:] {
			proof.A = append(proof.A, report.S(hx(n)))
		}
		check(t, fmt.Sprintf("trie node, lists %d deep", lists+1), run(set(h.entry(), "txProof", proof), h.manifest(""), h.source()), w)
	}
}

func TestSignedChainIDFactIsAString(t *testing.T) {
	f := newFixture(t, txOpts{txType: 2, chainID: 31337})
	r := run(f.entry(), f.manifest(""), f.source())
	if v, _ := r.Tx.Fact("signedChainId"); v == nil || v.Kind != jsonv.String || v.S != "31337" {
		t.Errorf("signedChainId %+v", v)
	}
	g := newFixture(t, txOpts{txType: 0, unprotect: true})
	r = run(g.entry(), g.manifest(""), g.source())
	if v, _ := r.Tx.Fact("signedChainId"); v == nil || v.Kind != jsonv.Null {
		t.Errorf("unprotected signedChainId %+v", v)
	}
}

// item2Signer is the address of the key of the fuzz seeds (seedTxs), which
// signed every transaction of item2Cases whose signature is a real one.
const item2Signer = "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"

// item2Cases are raw transactions of types 0, 1 and 2 for item 2 of Anchor
// §10.4, each carrying 32 zero bytes of calldata but the two fuzzing found,
// which carry none. rule is the rule of item 2 the transaction breaks, by
// the name the transaction cases of evm-anchor-vectors.json give it, or ""
// when item 2 reads it; sender is the sender decodeTx recovers, or "" when
// it refuses the transaction as malformed_publication.
var item2Cases = []struct {
	name   string
	raw    string
	rule   string
	sender string
}{
	// Well formed: the rules hold and the signer's key is recovered.
	{"legacy, v 27, no chain id", "f88301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a000000000000000000000000000000000000000000000000000000000000000001ba0df0ffd2c28d257380d45c591f6a58fb3cdbf6e0acd40f857d0456c61a3b8f13fa006f153cf7c84d158ca1dfdf5246000509a6428b4df5180d4e3359a641109b61b", "", item2Signer},
	{"legacy, v 37, chain id 1", "f88303843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000025a07bc272e39d9c660450e3aafc266c7b4db971be5a1b6a30b8f530d928401fa6b8a0401761f4b1085eade70225aaf59204bd4d1813b3877035f2970173e7ccc0b3b8", "", item2Signer},
	{"legacy, v 38, chain id 1", "f88302843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000026a0e058b908a6408da0c0cd50839ec05319397ee6f062bd1146c7f3de98a5355b55a0640e704a3e0c9e21fb7ee77bd9c32b638ead56c8a06cf8d454efba9471393d39", "", item2Signer},
	{"type 1, chain id 1", "01f8850103843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a03868b3202a079a6293cb28f308c8f3be08d6684623c7956d9e4f25ddcb112ed6a004bb09daaf1e5b81a54844421e972e027f9b44871ee12084a72c82f37de6a4e9", "", item2Signer},
	{"type 2, chain id 1", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "", item2Signer},
	{"type 2, an access list entry", "02f8c30104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000f838f7942c7536e3605d9c16a7a3d7b1898e529396a65c23e1a0000000000000000000000000000000000000000000000000000000000000000101a0287a69555cd5c48dd0868d8191f9b23dffdb5eff59f5587464a467251017d170a008ee76eadcbee035eaf54c15ebecb85801da3d481298bd4810157b5be7545dab", "", item2Signer},
	{"type 2, maxPriorityFeePerGas equal to maxFeePerGas", "02f88a010584773594008477359400827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0bb5780705593ca9d1d81ca6a7a40575f2feb1eda0b37403109515dce95a71654a06c889afcf844954f50930dffeaf17de193007c9edc00f56fdf5357fa047a27c8", "", item2Signer},
	// r and s at the bottom of their ranges; the key recovered is no one's.
	{"type 2, r 1, s 1", "02f84a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c0800101", "", "0x9979ab8c5e067b3bb4a80379697855fc093e1af4"},
	// Chain id: a type 1 or type 2 transaction signs chain id 1 or more. The
	// two signed by the key recover it; the two fuzzing found carry r 5, no
	// point's x.
	{"type 2, chain id 0", "02f88a8001843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0e5cf9ac30913204c2304ff26b31395221488ec07bfddadc72a07ac6b9e9b52dba01376360669d45b1f752fbcaacb63f3d7c6d28c5a96e229c122cbb9f1c93eadfb", "chain-id", ""},
	{"type 1, chain id 0", "01f8858001843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a0b4a0f86712ea3127f47395eccbaf84d994ca860e103725ef7867643017ab0df5a02783e3ec2631c43ed64b706c34225348f8422029be3afe82147f5fa254359aa4", "chain-id", ""},
	{"type 2, chain id 0, found by fuzzing", chainZeroType2, "chain-id", ""},
	{"type 1, chain id 0, found by fuzzing", chainZeroType1, "chain-id", ""},
	// Legacy v: a legacy v is 27, 28, or chainId*2+35 or +36 with chain id 1
	// or more. v 35 and 36 sign chain id 0, and go-ethereum's EIP-155 signer
	// recovers the key.
	{"legacy, v 35, chain id 0", "f88302843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000023a0b8518f02496753340c353fe934213da62cfad76f72def1248886eeab8fe5527ea036a06a7585f073e930f672ed460e76b15bf2c891dafb49de43c6e9a1597569f0", "legacy-v", ""},
	{"legacy, v 36, chain id 0", "f88301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000024a0b2e5d376fe825bbc624b1e2c9927f613e4ce978d71e3e6acd46fdb1fd4455838a06c73364b5730a5b82a576a374a1b6aa12d379f08c240b7afb4ffdc4bd926567b", "legacy-v", ""},
	{"legacy, v 0", "f88301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000080a0df0ffd2c28d257380d45c591f6a58fb3cdbf6e0acd40f857d0456c61a3b8f13fa006f153cf7c84d158ca1dfdf5246000509a6428b4df5180d4e3359a641109b61b", "legacy-v", ""},
	{"legacy, v 34", "f88301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000022a0df0ffd2c28d257380d45c591f6a58fb3cdbf6e0acd40f857d0456c61a3b8f13fa006f153cf7c84d158ca1dfdf5246000509a6428b4df5180d4e3359a641109b61b", "legacy-v", ""},
	// Signature values: a type 1 or type 2 yParity is 0 or 1. r and s are
	// those of yParity 0 or 1, so a reader that took yParity modulo 2, 4 or
	// 256 would recover the key.
	{"type 1, yParity 2", "01f8850103843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c002a03868b3202a079a6293cb28f308c8f3be08d6684623c7956d9e4f25ddcb112ed6a004bb09daaf1e5b81a54844421e972e027f9b44871ee12084a72c82f37de6a4e9", "signature-values", ""},
	{"type 2, yParity 3", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c003a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "signature-values", ""},
	{"type 2, yParity 5", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c005a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "signature-values", ""},
	{"type 2, yParity 257", "02f88c0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c0820101a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "signature-values", ""},
	// Fees: a type 2 maxPriorityFeePerGas is at most its maxFeePerGas.
	// go-ethereum recovers the key.
	{"type 2, maxPriorityFeePerGas above maxFeePerGas", "02f88a010184b2d05e00843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a0602567b7b0456172e8fe09d6fefa537475335fe851d322db7fb72abd590fea11a05a105d78986c71dcc919a5eea7f30661ddbb6a05a2560e8e1440acaa3740974f", "fees", ""},
	// Signature values: s is at most (n-1)/2 (EIP-2). Each high s is the
	// twin, n - s with the parity flipped, of a low s by the key, so its
	// signature recovers the key.
	{"legacy, v 28, high s", "f88301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a000000000000000000000000000000000000000000000000000000000000000001ca0df0ffd2c28d257380d45c591f6a58fb3cdbf6e0acd40f857d0456c61a3b8f13fa0f90eac30837b2ea735e2020adb9fffae204ab431cff71f66dc9cc428bf2c8b26", "signature-values", ""},
	{"legacy, v 37, chain id 1, high s", "f88302843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000025a0e058b908a6408da0c0cd50839ec05319397ee6f062bd1146c7f3de98a5355b55a09bf18fb5c1f361de04811884263cd49b2c01861e0edba7676ae2a3f85efd0408", "signature-values", ""},
	{"type 1, high s", "01f8850103843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a03868b3202a079a6293cb28f308c8f3be08d6684623c7956d9e4f25ddcb112ed6a0fb44f62550e1a47e5ab7bbbde168d1fc3b13985f90677fb718a5db99524f9c58", "signature-values", ""},
	{"type 2, high s", "02f88a0101843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a0e9766cb77e6f64b55517c8e43082bbed6e27e025ef12e24e3690ffb98d5bf861a0d6f674e3f862bcf4a1efad4c3c0225c56ae560befc402afeccbfe09dd688fcf9", "signature-values", ""},
	{"type 2, s (n-1)/2 + 1", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa07fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1", "signature-values", ""},
	// Signature values: r is in [1, n-1], s in [1, (n-1)/2].
	{"type 2, s n", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa0fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "signature-values", ""},
	{"type 2, s 0", "02f86a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5f80", "signature-values", ""},
	{"type 2, r 0", "02f86a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c00180a02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "signature-values", ""},
	{"type 2, r n", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141a02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "signature-values", ""},
	{"legacy, s 0", "f86301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a000000000000000000000000000000000000000000000000000000000000000001ba0df0ffd2c28d257380d45c591f6a58fb3cdbf6e0acd40f857d0456c61a3b8f13f80", "signature-values", ""},
	{"legacy, r 0", "f86301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a000000000000000000000000000000000000000000000000000000000000000001b80a006f153cf7c84d158ca1dfdf5246000509a6428b4df5180d4e3359a641109b61b", "signature-values", ""},
	{"legacy, r n", "f88301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a000000000000000000000000000000000000000000000000000000000000000001ba0fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141a006f153cf7c84d158ca1dfdf5246000509a6428b4df5180d4e3359a641109b61b", "signature-values", ""},
	// Encoding: rawTransaction is the canonical RLP of its fields. Each of
	// these holds the values of a transaction the key signed over their
	// canonical encoding, written another way, so a reader that took the
	// values and not the bytes would recover the key.
	{"type 2, nonce 4 written 0x8104", "02f88b018104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "encoding", ""},
	{"type 2, yParity 1 written 0x8101", "02f88b0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c08101a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "encoding", ""},
	{"type 2, nonce 4 written 0x820004", "02f88c01820004843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "encoding", ""},
	{"type 2, chain id 1 written 0x820001", "02f88c82000104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "encoding", ""},
	{"type 2, gasLimit 30000 written 0x83007530", "02f88b0104843b9aca0084b2d05e0083007530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "encoding", ""},
	{"legacy, gasPrice written with a leading zero byte", "f8840285003b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000026a0e058b908a6408da0c0cd50839ec05319397ee6f062bd1146c7f3de98a5355b55a0640e704a3e0c9e21fb7ee77bd9c32b638ead56c8a06cf8d454efba9471393d39", "encoding", ""},
	{"type 2, r with a leading zero byte", "02f88b0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a100c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "encoding", ""},
	{"type 2, value 0 written 0x00", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2300a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "encoding", ""},
	{"type 2, yParity 0 written 0x00", "02f88a0107843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c000a02f403a2eeaf93a414074bf8d4cd82a42bdd3d4c0525e79ace2f3cdf4729e8b74a03bf2e1312b4b61b9853172c61933c4d05c00b5cb4b7133e154cd35149eb51bb5", "encoding", ""},
	{"type 2, calldata's length in the long form", "02f88b0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380b8200000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "encoding", ""},
	{"type 1, to's length in the long form", "01f8860103843b9aca00827530b8142c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a03868b3202a079a6293cb28f308c8f3be08d6684623c7956d9e4f25ddcb112ed6a004bb09daaf1e5b81a54844421e972e027f9b44871ee12084a72c82f37de6a4e9", "encoding", ""},
	{"type 2, the empty access list written 0xf800", "02f88b0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000f80001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "encoding", ""},
	{"type 2, the list's length written with a leading zero byte", "02f9008a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "encoding", ""},
	{"type 2, a storage key's length in the long form", "02f8c50104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000f83af838942c7536e3605d9c16a7a3d7b1898e529396a65c23e2b820000000000000000000000000000000000000000000000000000000000000000101a0287a69555cd5c48dd0868d8191f9b23dffdb5eff59f5587464a467251017d170a008ee76eadcbee035eaf54c15ebecb85801da3d481298bd4810157b5be7545dab", "encoding", ""},
	{"type 2, a byte after the list", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd06134200", "encoding", ""},
	{"legacy, a byte after the list", "f88302843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000026a0e058b908a6408da0c0cd50839ec05319397ee6f062bd1146c7f3de98a5355b55a0640e704a3e0c9e21fb7ee77bd9c32b638ead56c8a06cf8d454efba9471393d3900", "encoding", ""},
	{"type 2, a string where the list belongs", "02b88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", "encoding", ""},
	// Field sizes: the nonce and gasLimit are at most 2^64 - 1; the chain id,
	// value, gasPrice and the fees at most 2^256 - 1; a legacy v at most
	// 2 * (2^256 - 1) + 36, the v of chain id 2^256 - 1. Each is read at its
	// bound and refused above it.
	{"type 2, nonce 2^53", "02f891018720000000000000843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a00fba4b7d57fcc7265d3bdb3483eb0bf997769684d31d22faee58695a4347af77a00609aca63f24dac0dbe3ca34ea42b17e121b14fc3693c860c06ba6dd51259f35", "", item2Signer},
	{"type 2, nonce 2^64 - 1", "02f8910188ffffffffffffffff843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0af37a8bf87d673d6f9eb3a97595a7f1ab00c4a20824bb355ca24e283dc2825539f4d22e10f6bb0cc9c124f250fdf8acbf8ab37ac8a730be92f7edeb81cc956ea", "", item2Signer},
	{"type 2, nonce 2^64", "02f8930189010000000000000000843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a0fbe80009e44bf2eb83454b46e6d1fe457836f8c231dbd18564972284393d82b8a00a49d1ecc8f48592f11d12a7e1213318ba5a614f4d94149269abf24e882af6bb", "field-sizes", ""},
	{"legacy, nonce 2^64 - 1", "f88b88ffffffffffffffff843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000026a073b308f0fead9ac711d1865dd5a3141d186c75d3edf8373cee3f5aefbfa948f3a06a55174cf0ae0bb80e790dd6535dceda29d9d39f4dd1109bd36b4e3dafef7fa4", "", item2Signer},
	{"legacy, nonce 2^64", "f88c89010000000000000000843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000026a061971a79e7b49e61bf32348444b4cb9ed63830481c3a35b97fef7828c971b889a04e0d48e76186839f903ee2c21023fd603fdfd5f8eadfaf5fe3af2e3f73255c18", "field-sizes", ""},
	{"type 2, gasLimit 2^64 - 1", "02f8900104843b9aca0084b2d05e0088ffffffffffffffff942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a0d39697e454fac9da21b8dbfaf736683e624721ad0af583408331091919596e84a05a0aaaea10ace6ac759beeb8ae36e222005bf08ce4b45e5c70c94d99ee03788a", "", item2Signer},
	{"type 2, gasLimit 2^64", "02f8910104843b9aca0084b2d05e0089010000000000000000942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a06621167f7edfe42f10e3ca49c0e420c4705e4e51a50a1f9a9566eab32f78a0aea04a354e17fef4bce00bd375a36b26f3d62f081c071bd2e8b8fda05887e6f45fc7", "field-sizes", ""},
	{"type 1, gasLimit 2^64", "01f88c0103843b9aca0089010000000000000000942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a03352877f31ed81e17848d4275b6d830d6ba1f0eae525b99d1fbb6e0dfc3c699ba03ddef38c4d821f8a781aa680fde9b932dad20e2826bffb87213bd6811b5556a1", "field-sizes", ""},
	{"type 2, chain id 2^256 - 1", "02f8aaa0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff04843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a001f55ce6108a592dd135b6c2524417e5556a14478f8086691ad8229ff7b473e9a00a2f35ba1280ded666f56003c2aebaf0515713af0ba5e422a4507776ab5db4fd", "", item2Signer},
	{"type 2, chain id 2^256", "02f8aba101000000000000000000000000000000000000000000000000000000000000000004843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a07d1fb1abfe1913e719965d2b8e9225b1c19266e5b457692e7790aa75be58fbdda03dfdd48d286b0386712b1bc1c0c1b6bd4f4d6f590e918fac170ff00bca57f4c6", "field-sizes", ""},
	{"type 2, value 2^256 - 1", "02f8aa0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c23a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa00000000000000000000000000000000000000000000000000000000000000000c080a0aa38758964d76a15ae73dd88429471f092b3aa5d695a3f1e1cd16ef9839bc42ea016faf239432e8f466b7b89ae9a15421137d782d713aa92f9dcd544ac3211a34f", "", item2Signer},
	{"type 2, value 2^256", "02f8ab0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c23a1010000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000c001a08911ae89f4c04d0235df6649cc901b3668bbebfc958717bb6b7780240acf492ca01a2f49bacb2c3595135fb1d399cac2a9f6cae2e5bd33581a1cdc9d2e369dd87f", "field-sizes", ""},
	{"legacy, value 2^256", "f8a402843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c23a1010000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000025a04253d26bdd9037067cd4ef7034938f91796c69d63e01112e093a2771e4409a02a05bf66c9e91871d154a6bbc71ca3f6fbcc6be61236ead6a175866d11c92b8659e", "field-sizes", ""},
	{"type 1, gasPrice 2^256 - 1", "01f8a10103a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0e2a777b23fb22a76a9b9add77637c0766d83d520ae19f6621b0f48861e030441a0445c4694128ccdb9b793b1049c36c1fe5d13999b04471e71e7f5f9c3619d5772", "", item2Signer},
	{"type 1, gasPrice 2^256", "01f8a20103a1010000000000000000000000000000000000000000000000000000000000000000827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c1e79ac6f4b97c48a2cc11bcd7728bde0584189d5baf7c9b945bdf4ae2d344fda077c0fc84e064b6a882349f1f049ffa67b78845ddbab9c6f4aee6836c7c7f4dd9", "field-sizes", ""},
	{"legacy, gasPrice 2^256 - 1", "f89f02a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000025a0354ceed0e7d0af60be136d6664e17d952c47245796578195ff29021332fdc285a0544a4279d9286294cd67a76dc6ba54f254cbf3e631ab935b98cc28a7cec21e19", "", item2Signer},
	{"legacy, gasPrice 2^256", "f8a002a1010000000000000000000000000000000000000000000000000000000000000000827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000025a0b88eee9cfecb6c4614941b768783cd315e68dc5a520fb0cdb91251eac01b5ce7a01f45a77dd20a49399ccac765578d271b08cb76cfd10a681c1177df46a59992c9", "field-sizes", ""},
	{"type 2, maxPriorityFeePerGas and maxFeePerGas 2^256 - 1", "02f8c20104a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a01eb03a0eb3611ab1f761287dd02a06aa11c9893572c9e4cd11049c3fc1d75f64a0034756cf7c0c01b75ac0f72a5bed11bd55d74fc83053cec4e73a71f7fa013d57", "", item2Signer},
	{"type 2, maxFeePerGas 2^256", "02f8a70104843b9aca00a1010000000000000000000000000000000000000000000000000000000000000000827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a089e0068b807913b29d9b7e7d80f0d90349d057a045ace325290434a9c060ba02a013fbc9df3064a0408b0abc01bf220ab641a7410cf4b0dea37a126218a40f601b", "field-sizes", ""},
	{"type 2, maxPriorityFeePerGas and maxFeePerGas 2^256", "02f8c40104a1010000000000000000000000000000000000000000000000000000000000000000a1010000000000000000000000000000000000000000000000000000000000000000827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a0b3c569dd9f79a9944e837204cdd57c40928256f2e77ab3be1afe30ac8bfc4e75a00e2809f74e04559e817efcc7cba1c90ded6abc28b77765f061c8f03a1dcf19d8", "field-sizes", ""},
	{"legacy, v 2^257 + 34, chain id 2^256 - 1", "f8a402843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000a1020000000000000000000000000000000000000000000000000000000000000022a0655a74dc35e2235d23cc39c1993be44f4cbc2c80f1c08be46f4b9fa7b1b905ada011ccd47e389c102e98d1cdac3e58d16c5e5c3c66a04ec40fb7f4c54000c35c2b", "", item2Signer},
	{"legacy, v 2^257 + 35, chain id 2^256", "f8a403843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000a1020000000000000000000000000000000000000000000000000000000000000023a0ca54bb7a5b98a45274851be2ff8d48a93a4e9b029186c99177ee2624f854b54ba001ad5b7c77f5294e6096737cee171dadf2ede8db250be7eb4fe37af1727bbf56", "field-sizes", ""},
	// Recovery: the other rules hold and no public key is recovered; r 5 and
	// r n-1 are no point's x coordinate.
	{"legacy, v 27, r 5", "f84301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a000000000000000000000000000000000000000000000000000000000000000001b0507", "recovery", ""},
	{"type 2, r 5", "02f84a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c0800507", "recovery", ""},
	{"type 2, r n-1, s (n-1)/2", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140a07fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", "recovery", ""},
}

// item2RulesOfTxRulesOK names the rules of item 2 that txRulesOK holds a
// decoded transaction to.
var item2RulesOfTxRulesOK = map[string]bool{"chain-id": true, "legacy-v": true, "signature-values": true, "fees": true}

// TestItem2Rules holds each check of item 2 to item2Cases on its own, and
// decodeTx to all of them. txEncoding, fieldSizesOK and txRulesOK are
// checked on their own because go-ethereum refuses many of the transactions
// they refuse too (every one the encoding rule refuses, a nonce or gasLimit
// above 2^64 - 1, r or s out of range, a high s, a yParity above 1, a
// typed transaction that signs chain id 0), so decodeTx's outcome alone
// would not show that the rule is stated here.
func TestItem2Rules(t *testing.T) {
	for _, c := range item2Cases {
		raw, err := hex.DecodeString(c.raw)
		if err != nil {
			t.Fatal(err)
		}
		if (c.rule == "") != (c.sender != "") {
			t.Fatalf("%s: rule %q beside sender %q", c.name, c.rule, c.sender)
		}
		ints, encoded := txEncoding(raw)
		if encoded != (c.rule != "encoding") {
			t.Errorf("%s: txEncoding %v", c.name, encoded)
		}
		if encoded {
			if got := fieldSizesOK(ints); got != (c.rule != "field-sizes") {
				t.Errorf("%s: fieldSizesOK %v", c.name, got)
			}
		}
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(raw); err == nil {
			if got := txRulesOK(tx); got == item2RulesOfTxRulesOK[c.rule] {
				t.Errorf("%s: txRulesOK %v", c.name, got)
			}
		} else if c.rule != "encoding" && c.rule != "field-sizes" {
			t.Fatalf("%s: go-ethereum does not decode it: %v", c.name, err)
		}
		got, from, why := decodeTx(raw)
		switch {
		case c.sender == "" && (got != nil || why != ReasonMalformed):
			t.Errorf("%s: decodeTx gives a transaction %v, sender %s, reason %q; want %s", c.name, got != nil, from.Hex(), why, ReasonMalformed)
		case c.sender != "" && (got == nil || why != "" || strings.ToLower(from.Hex()) != c.sender):
			t.Errorf("%s: decodeTx gives sender %s, reason %q; want %s", c.name, from.Hex(), why, c.sender)
		}
	}
}

// TestItem2Verify runs Verify over item2Cases: a transaction decodeTx
// refuses makes the publication false, malformed_publication,
// anchor.evm.canonical is blocked by anchor.evm.tx, and anchor.evm.tx
// reports none of the transaction's facts, since it has not decoded; one
// it reads a sender from reports that sender and goes on to item 4, where
// its zero calldata is not P.
func TestItem2Verify(t *testing.T) {
	f := newFixture(t, txOpts{txType: 2})
	for _, c := range item2Cases {
		w := want{valid: "false", reason: ReasonMalformed, tx: report.Wrong, txReason: ReasonMalformed,
			can: report.NotChecked, canReason: "blocked_by:anchor.evm.tx[0]"}
		if c.sender != "" {
			w.reason, w.txReason = ReasonCalldataMismatch, ReasonCalldataMismatch
		}
		r := run(set(f.entry("transactionId"), "rawTransaction", report.S("0x"+c.raw)), f.manifest(""), f.source())
		check(t, c.name, r, w)
		sender, _ := r.Tx.Fact("sender")
		switch {
		case c.sender == "" && len(r.Tx.Facts) != 0:
			t.Errorf("%s: a transaction item 2 refuses reports %d facts", c.name, len(r.Tx.Facts))
		case c.sender != "" && (sender == nil || sender.S != c.sender):
			t.Errorf("%s: sender fact %v, want %s", c.name, sender, c.sender)
		}
	}
}

// TestRLPHead holds rlpHead to the canonical form of an RLP header and to
// the end of its input. An item it reads is followed by one more byte,
// which it returns as the rest.
func TestRLPHead(t *testing.T) {
	long := func(head string, n int) string { return head + strings.Repeat("00", n) }
	for _, c := range []struct {
		name, in string
		list, ok bool
		content  int // the content's length, when ok
	}{
		{"nothing", "", false, false, 0},
		{"a byte below 0x80", "05", false, true, 1},
		{"the empty string", "80", false, true, 0},
		{"a byte 0x80 as a string of one", "8180", false, true, 1},
		{"a byte below 0x80 as a string of one", "8105", false, false, 0},
		{"0x00 as a string of one", "8100", false, false, 0},
		{"a string of 55, short form", long("b7", 55), false, true, 55},
		{"a string of 55, long form", long("b837", 55), false, false, 0},
		{"a string of 56, long form", long("b838", 56), false, true, 56},
		{"a string of 56, length with a leading zero byte", long("b90038", 56), false, false, 0},
		{"a string of 256, two-byte length", long("b90100", 256), false, true, 256},
		{"the empty list", "c0", true, true, 0},
		{"the empty list, long form", "f800", true, false, 0},
		{"a list of 55, long form", long("f837", 55), true, false, 0},
		{"a list of 56, long form", long("f838", 56), true, true, 56},
		{"a list of 56, length with a leading zero byte", long("f90038", 56), true, false, 0},
		{"a list holding one byte below 0x80", "c105", true, true, 1},
		{"a string longer than its input", "8201", false, false, 0},
		{"a list longer than its input", long("f838", 55), true, false, 0},
		{"a length's bytes cut short", "b901", false, false, 0},
		{"a length of 2^64 - 1", "bfffffffffffffffff", false, false, 0},
	} {
		b, err := hex.DecodeString(c.in)
		if err != nil {
			t.Fatal(err)
		}
		if c.ok {
			b = append(b, 0xaa)
		}
		list, content, rest, ok := rlpHead(b)
		if ok != c.ok || ok && (list != c.list || len(content) != c.content || !bytes.Equal(rest, []byte{0xaa})) {
			t.Errorf("%s: list %v, content %d, rest %x, ok %v", c.name, list, len(content), rest, ok)
		}
	}
}

// TestFieldSizes holds fieldSizesOK to each bound of the field sizes rule,
// one field at a time: a field at its bound is read and one above it is
// refused. The bound on maxPriorityFeePerGas is tested here alone, since
// within a transaction the fees rule refuses a tip above a cap that is
// itself in bounds.
func TestFieldSizes(t *testing.T) {
	pow2 := func(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }
	add := func(x *big.Int, d int64) *big.Int { return new(big.Int).Add(x, big.NewInt(d)) }
	u64, u256 := add(pow2(64), -1), add(pow2(256), -1)
	for _, c := range []struct {
		field string
		most  *big.Int
	}{
		{"nonce", u64}, {"gasLimit", u64}, {"chainId", u256}, {"value", u256}, {"gasPrice", u256},
		{"maxPriorityFeePerGas", u256}, {"maxFeePerGas", u256}, {"v", add(pow2(257), 34)},
	} {
		if !fieldSizesOK(map[string]*big.Int{c.field: c.most}) {
			t.Errorf("%s %v refused", c.field, c.most)
		}
		if fieldSizesOK(map[string]*big.Int{c.field: add(c.most, 1)}) {
			t.Errorf("%s %v read", c.field, add(c.most, 1))
		}
	}
	// yParity, r and s are the signature values rule's.
	for _, field := range []string{"yParity", "r", "s"} {
		if !fieldSizesOK(map[string]*big.Int{field: pow2(300)}) {
			t.Errorf("%s bounded by the field sizes rule", field)
		}
	}
}

// TestTxEncodingShape: canonical RLP that is not a list of the type's
// fields is no transaction of the type. txEncoding refuses it, as
// go-ethereum's decoder does.
func TestTxEncodingShape(t *testing.T) {
	to, key := make([]byte, 20), make([]byte, 32)
	type2 := func(edit func([]any) []any) []byte {
		f := []any{uint64(1), uint64(4), uint64(1e9), uint64(3e9), uint64(30000), to, uint64(0), []byte{}, []any{},
			uint64(0), uint64(1), uint64(1)}
		b, err := rlp.EncodeToBytes(edit(f))
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte{types.DynamicFeeTxType}, b...)
	}
	for _, c := range []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"the twelve fields", type2(func(f []any) []any { return f }), true},
		{"eleven fields", type2(func(f []any) []any { return f[:11] }), false},
		{"thirteen fields", type2(func(f []any) []any { return append(f, uint64(0)) }), false},
		{"a list for the nonce", type2(func(f []any) []any { f[1] = []any{}; return f }), false},
		{"an access list four deep", type2(func(f []any) []any { f[8] = []any{[]any{to, []any{key}}}; return f }), true},
		{"an access list five deep", type2(func(f []any) []any { f[8] = []any{[]any{to, []any{[]any{key}}}}; return f }), false},
	} {
		if _, ok := txEncoding(c.raw); ok != c.ok {
			t.Errorf("%s: txEncoding %v", c.name, ok)
		}
		if err := new(types.Transaction).UnmarshalBinary(c.raw); (err == nil) != c.ok {
			t.Errorf("%s: go-ethereum's decoder: %v", c.name, err)
		}
	}
}

// TestSecp256k1Order holds the order txRulesOK states to the curve's.
func TestSecp256k1Order(t *testing.T) {
	n := crypto.S256().Params().N
	if secp256k1N.Cmp(n) != 0 || secp256k1HalfN.Cmp(new(big.Int).Rsh(n, 1)) != 0 {
		t.Errorf("n %x, n/2 %x; the curve's n is %x", secp256k1N, secp256k1HalfN, n)
	}
}
