// SPDX-License-Identifier: BSD-3-Clause-Clear

package evm

import (
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
// which carry none. rules is whether txRulesOK holds; sender is the sender
// decodeTx recovers, or "" when it refuses the transaction as
// malformed_publication.
var item2Cases = []struct {
	name   string
	raw    string
	rules  bool
	sender string
}{
	// Well formed: the rules hold and the signer's key is recovered.
	{"legacy, v 27, no chain id", "f88301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a000000000000000000000000000000000000000000000000000000000000000001ba0df0ffd2c28d257380d45c591f6a58fb3cdbf6e0acd40f857d0456c61a3b8f13fa006f153cf7c84d158ca1dfdf5246000509a6428b4df5180d4e3359a641109b61b", true, item2Signer},
	{"legacy, v 38, chain id 1", "f88302843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000026a0e058b908a6408da0c0cd50839ec05319397ee6f062bd1146c7f3de98a5355b55a0640e704a3e0c9e21fb7ee77bd9c32b638ead56c8a06cf8d454efba9471393d39", true, item2Signer},
	{"type 1, chain id 1", "01f8850103843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a03868b3202a079a6293cb28f308c8f3be08d6684623c7956d9e4f25ddcb112ed6a004bb09daaf1e5b81a54844421e972e027f9b44871ee12084a72c82f37de6a4e9", true, item2Signer},
	{"type 2, chain id 1", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", true, item2Signer},
	{"type 2, maxPriorityFeePerGas equal to maxFeePerGas", "02f88a010584773594008477359400827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0bb5780705593ca9d1d81ca6a7a40575f2feb1eda0b37403109515dce95a71654a06c889afcf844954f50930dffeaf17de193007c9edc00f56fdf5357fa047a27c8", true, item2Signer},
	// r and s at the bottom of their ranges; the key recovered is no one's.
	{"type 2, r 1, s 1", "02f84a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c0800101", true, "0x9979ab8c5e067b3bb4a80379697855fc093e1af4"},
	// A type 1 or type 2 transaction signs chain id 1 or more. The two signed
	// by the key recover it; the two fuzzing found carry r 5, no point's x.
	{"type 2, chain id 0", "02f88a8001843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0e5cf9ac30913204c2304ff26b31395221488ec07bfddadc72a07ac6b9e9b52dba01376360669d45b1f752fbcaacb63f3d7c6d28c5a96e229c122cbb9f1c93eadfb", false, ""},
	{"type 1, chain id 0", "01f8858001843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a0b4a0f86712ea3127f47395eccbaf84d994ca860e103725ef7867643017ab0df5a02783e3ec2631c43ed64b706c34225348f8422029be3afe82147f5fa254359aa4", false, ""},
	{"type 2, chain id 0, found by fuzzing", chainZeroType2, false, ""},
	{"type 1, chain id 0, found by fuzzing", chainZeroType1, false, ""},
	// A legacy v is 27, 28, or chainId*2+35 or +36 with chain id 1 or more. v 35
	// and 36 sign chain id 0, and go-ethereum's EIP-155 signer recovers the key.
	{"legacy, v 35, chain id 0", "f88302843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000023a0b8518f02496753340c353fe934213da62cfad76f72def1248886eeab8fe5527ea036a06a7585f073e930f672ed460e76b15bf2c891dafb49de43c6e9a1597569f0", false, ""},
	{"legacy, v 36, chain id 0", "f88301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000024a0b2e5d376fe825bbc624b1e2c9927f613e4ce978d71e3e6acd46fdb1fd4455838a06c73364b5730a5b82a576a374a1b6aa12d379f08c240b7afb4ffdc4bd926567b", false, ""},
	{"legacy, v 0", "f88301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000080a0df0ffd2c28d257380d45c591f6a58fb3cdbf6e0acd40f857d0456c61a3b8f13fa006f153cf7c84d158ca1dfdf5246000509a6428b4df5180d4e3359a641109b61b", false, ""},
	{"legacy, v 34", "f88301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000022a0df0ffd2c28d257380d45c591f6a58fb3cdbf6e0acd40f857d0456c61a3b8f13fa006f153cf7c84d158ca1dfdf5246000509a6428b4df5180d4e3359a641109b61b", false, ""},
	// A type 1 or type 2 yParity is 0 or 1. r and s are those of yParity 0 or
	// 1, so a reader that took yParity modulo 2, 4 or 256 would recover the key.
	{"type 1, yParity 2", "01f8850103843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c002a03868b3202a079a6293cb28f308c8f3be08d6684623c7956d9e4f25ddcb112ed6a004bb09daaf1e5b81a54844421e972e027f9b44871ee12084a72c82f37de6a4e9", false, ""},
	{"type 2, yParity 3", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c003a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", false, ""},
	{"type 2, yParity 5", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c005a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", false, ""},
	{"type 2, yParity 257", "02f88c0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c0820101a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", false, ""},
	// A type 2 maxPriorityFeePerGas is at most its maxFeePerGas.
	// go-ethereum recovers the key.
	{"type 2, maxPriorityFeePerGas above maxFeePerGas", "02f88a010184b2d05e00843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a0602567b7b0456172e8fe09d6fefa537475335fe851d322db7fb72abd590fea11a05a105d78986c71dcc919a5eea7f30661ddbb6a05a2560e8e1440acaa3740974f", false, ""},
	// s is at most n/2 (EIP-2). Each high s is the twin, n - s with the parity
	// flipped, of a low s by the key, so its signature recovers the key.
	{"legacy, v 28, high s", "f88301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a000000000000000000000000000000000000000000000000000000000000000001ca0df0ffd2c28d257380d45c591f6a58fb3cdbf6e0acd40f857d0456c61a3b8f13fa0f90eac30837b2ea735e2020adb9fffae204ab431cff71f66dc9cc428bf2c8b26", false, ""},
	{"legacy, v 37, chain id 1, high s", "f88302843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a0000000000000000000000000000000000000000000000000000000000000000025a0e058b908a6408da0c0cd50839ec05319397ee6f062bd1146c7f3de98a5355b55a09bf18fb5c1f361de04811884263cd49b2c01861e0edba7676ae2a3f85efd0408", false, ""},
	{"type 1, high s", "01f8850103843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a03868b3202a079a6293cb28f308c8f3be08d6684623c7956d9e4f25ddcb112ed6a0fb44f62550e1a47e5ab7bbbde168d1fc3b13985f90677fb718a5db99524f9c58", false, ""},
	{"type 2, high s", "02f88a0101843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a0e9766cb77e6f64b55517c8e43082bbed6e27e025ef12e24e3690ffb98d5bf861a0d6f674e3f862bcf4a1efad4c3c0225c56ae560befc402afeccbfe09dd688fcf9", false, ""},
	{"type 2, s n/2 + 1", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c080a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa07fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1", false, ""},
	// r is in [1, n-1], s in [1, n/2].
	{"type 2, s n", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5fa0fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", false, ""},
	{"type 2, s 0", "02f86a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0c29b6dad31844f327d25632f3cc757bc5a80f1eb7dae204e5dc38379c43d7b5f80", false, ""},
	{"type 2, r 0", "02f86a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c00180a02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", false, ""},
	{"type 2, r n", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141a02ae7dd41ec3690ac724b807135f4e53047776f4d25315a0c5936eaa6bd061342", false, ""},
	{"legacy, s 0", "f86301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a000000000000000000000000000000000000000000000000000000000000000001ba0df0ffd2c28d257380d45c591f6a58fb3cdbf6e0acd40f857d0456c61a3b8f13f80", false, ""},
	{"legacy, r 0", "f86301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a000000000000000000000000000000000000000000000000000000000000000001b80a006f153cf7c84d158ca1dfdf5246000509a6428b4df5180d4e3359a641109b61b", false, ""},
	{"legacy, r n", "f88301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a000000000000000000000000000000000000000000000000000000000000000001ba0fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141a006f153cf7c84d158ca1dfdf5246000509a6428b4df5180d4e3359a641109b61b", false, ""},
	// The rules hold and no public key is recovered: r 5 and r n-1 are no
	// point's x coordinate.
	{"legacy, v 27, r 5", "f84301843b9aca00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a000000000000000000000000000000000000000000000000000000000000000001b0507", true, ""},
	{"type 2, r 5", "02f84a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c0800507", true, ""},
	{"type 2, r n-1, s n/2", "02f88a0104843b9aca0084b2d05e00827530942c7536e3605d9c16a7a3d7b1898e529396a65c2380a00000000000000000000000000000000000000000000000000000000000000000c001a0fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140a07fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", true, ""},
}

// TestItem2Rules holds txRulesOK and decodeTx to item2Cases. txRulesOK is
// checked on its own because go-ethereum refuses some of the transactions
// it refuses too (r or s out of range, a high s, a yParity above 1, a
// typed transaction that signs chain id 0), so decodeTx's outcome alone
// would not show that the rule is stated here.
func TestItem2Rules(t *testing.T) {
	for _, c := range item2Cases {
		raw, err := hex.DecodeString(c.raw)
		if err != nil {
			t.Fatal(err)
		}
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(raw); err != nil {
			t.Fatalf("%s: go-ethereum does not decode it: %v", c.name, err)
		}
		if got := txRulesOK(tx); got != c.rules {
			t.Errorf("%s: txRulesOK %v, want %v", c.name, got, c.rules)
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
// refuses makes the publication false, malformed_publication, and
// anchor.evm.canonical is blocked by anchor.evm.tx; one it reads a sender
// from goes on to item 4, where its zero calldata is not P.
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
	}
}

// TestSecp256k1Order holds the order txRulesOK states to the curve's.
func TestSecp256k1Order(t *testing.T) {
	n := crypto.S256().Params().N
	if secp256k1N.Cmp(n) != 0 || secp256k1HalfN.Cmp(new(big.Int).Rsh(n, 1)) != 0 {
		t.Errorf("n %x, n/2 %x; the curve's n is %x", secp256k1N, secp256k1HalfN, n)
	}
}
