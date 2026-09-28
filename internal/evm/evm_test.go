package evm

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
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
