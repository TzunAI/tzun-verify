// Package evm verifies an evm-calldata/1 publication (Anchor §7.2,
// §10.4) with go-ethereum: the raw transaction's type, signature and sender,
// its calldata against P, its signed chain id against the publisher
// manifest, the block header and the transactions-trie proof the bundle
// carries, and the auditor's own header source for canonicality and
// finality. A bare §n in this package's comments is a section of Anchor;
// the Yellow Paper's sections are named as such.
package evm

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/manifest"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// Kind is the publication kind this package verifies.
const Kind = "evm-calldata/1"

// Reasons of §10.1 used here.
const (
	ReasonMalformed          = "malformed_publication"
	ReasonUnsupportedKind    = "unsupported_publication_kind"
	ReasonUnsupportedTxType  = "unsupported_evm_tx_type"
	ReasonTxProofInvalid     = "evm_tx_proof_invalid"
	ReasonCalldataMismatch   = "evm_calldata_mismatch"
	ReasonSenderMismatch     = "evm_sender_mismatch"
	ReasonChainMismatch      = "evm_chain_mismatch"
	ReasonNotFoundOnChain    = "anchor_not_found_on_chain"
	ReasonNoP                = "input_not_supplied:p"
	ReasonNoRaw              = "not_in_bundle:raw_transaction"
	ReasonNoTxProof          = "not_in_bundle:tx_proof"
	ReasonNoHeader           = "not_in_bundle:block_header"
	ReasonManifestUnreadable = "input_not_supplied:publisher_manifest"
	ReasonNoExpectation      = "no_expectation:publisher"
	ReasonNoSource           = "input_not_supplied:evm_header_source"
	ReasonNotFinalized       = "evm_block_not_finalized"
	ReasonUnavailable        = "evm_header_source_unavailable"
	ReasonSourceChain        = "evm_header_source_chain_mismatch"
	ReasonInconsistent       = "evm_header_source_inconsistent"
	ReasonTimeout            = "evm_header_source_timeout"
	ReasonVerifierError      = "evm_verifier_error"
	ReasonNotChecked         = "publication_not_checked"
)

// Input is one joined publication and what its verification needs.
type Input struct {
	// Index is the publication's index in the artifact's publications.
	Index int
	// Entry is the publication entry, joined with the bundle's heavy
	// material (rawTransaction, blockHeader, txIndex, txProof).
	Entry *jsonv.Value
	// P is the published value, 32 bytes.
	P            []byte
	AnchorOrigin string
	Manifest     *jsonv.Value
	Sources      Sources
	// Deadline bounds every header-source call of this verification.
	Deadline time.Time
}

// Result is the verification of one publication.
type Result struct {
	Tx        report.Check
	Canonical report.Check
	// Valid is the publication-level outcome: true, false or nil (null),
	// with Reason when it is not true.
	Valid  *bool
	Reason string
	// Facts for the anchor fields when Valid is true.
	Chain     string
	Namespace *string
	Network   string
	BlockTime uint64
	Inclusion string
	Finality  Finality
}

// TxID returns keccak256 of a raw transaction written as 0x hex, lowercase,
// or "" when raw is not 0x hex.
func TxID(raw string) string {
	b, ok := decodeHex0x(raw)
	if !ok || len(b) == 0 {
		return ""
	}
	return "0x" + hex.EncodeToString(crypto.Keccak256(b))
}

func decodeHex0x(s string) ([]byte, bool) {
	if !strings.HasPrefix(s, "0x") || len(s)%2 != 0 {
		return nil, false
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, false
	}
	return b, true
}

type parsed struct {
	raw        []byte
	txID       *common.Hash // the entry's transactionId, when present
	blockHash  common.Hash
	blockNum   uint64
	header     []byte // nil when absent
	hasTxProof bool
	txIndex    uint64
	txProof    [][]byte
}

// readHash32 reads 0x and 64 hex.
func readHash32(v *jsonv.Value) (common.Hash, bool) {
	s, ok := v.Str()
	if !ok || len(s) != 66 {
		return common.Hash{}, false
	}
	b, ok := decodeHex0x(s)
	if !ok || len(b) != 32 {
		return common.Hash{}, false
	}
	return common.BytesToHash(b), true
}

func readHexBytes(v *jsonv.Value) ([]byte, bool) {
	s, ok := v.Str()
	if !ok {
		return nil, false
	}
	b, ok := decodeHex0x(s)
	if !ok || len(b) == 0 {
		return nil, false
	}
	return b, true
}

// member returns an optional member, treating null as absent.
func member(o *jsonv.Value, k string) (*jsonv.Value, bool) {
	v, ok := o.Get(k)
	if !ok || v.Kind == jsonv.Null {
		return nil, false
	}
	return v, true
}

// shape is item 1 after the raw-transaction presence check.
func shape(e *jsonv.Value) (*parsed, bool) {
	p := &parsed{}
	rv, _ := member(e, "rawTransaction")
	raw, ok := readHexBytes(rv)
	if !ok {
		return nil, false
	}
	p.raw = raw
	if v, present := member(e, "transactionId"); present {
		h, ok := readHash32(v)
		if !ok {
			return nil, false
		}
		p.txID = &h
	}
	bh, present := member(e, "blockHash")
	if !present {
		return nil, false
	}
	if p.blockHash, ok = readHash32(bh); !ok {
		return nil, false
	}
	bn, present := member(e, "blockNumber")
	if !present {
		return nil, false
	}
	if p.blockNum, ok = bn.Uint53(); !ok {
		return nil, false
	}
	if v, present := member(e, "blockHeader"); present {
		if p.header, ok = readHexBytes(v); !ok {
			return nil, false
		}
	}
	iv, hasIndex := member(e, "txIndex")
	pv, hasProof := member(e, "txProof")
	switch {
	case !hasIndex && !hasProof:
	case hasIndex && hasProof:
		if p.txIndex, ok = iv.Uint53(); !ok {
			return nil, false
		}
		if pv.Kind != jsonv.Array || len(pv.A) == 0 {
			return nil, false
		}
		for _, n := range pv.A {
			b, ok := readHexBytes(n)
			if !ok {
				return nil, false
			}
			p.txProof = append(p.txProof, b)
		}
		p.hasTxProof = true
	default:
		return nil, false
	}
	return p, true
}

// decodeTx is item 2: the EIP-2718 type, then parse and sender recovery.
func decodeTx(raw []byte) (*types.Transaction, common.Address, string) {
	switch b := raw[0]; {
	case b >= 0xc0, b == 0x01, b == 0x02:
	case b >= 0x80 && b <= 0xbf:
		return nil, common.Address{}, ReasonMalformed
	default:
		return nil, common.Address{}, ReasonUnsupportedTxType
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(raw); err != nil {
		return nil, common.Address{}, ReasonMalformed
	}
	var signer types.Signer
	switch {
	case tx.Type() != types.LegacyTxType:
		signer = types.NewLondonSigner(tx.ChainId())
	case tx.Protected():
		signer = types.NewEIP155Signer(tx.ChainId())
	default:
		signer = types.HomesteadSigner{}
	}
	from, err := types.Sender(signer, tx)
	if err != nil {
		return nil, common.Address{}, ReasonMalformed
	}
	return tx, from, ""
}

// signedChainID is the chain id the signature covers; nil for a
// pre-EIP-155 legacy transaction, which signs none.
func signedChainID(tx *types.Transaction) *big.Int {
	if tx.Type() == types.LegacyTxType && !tx.Protected() {
		return nil
	}
	return tx.ChainId()
}

// chainIDFact renders the signed chain id as the report states it: a
// decimal string, so every chain id reads the same whatever its size, and
// null for a transaction that signs none.
func chainIDFact(id *big.Int) *jsonv.Value {
	if id == nil {
		return report.Null()
	}
	return report.S(id.String())
}

// blockHeader is what a verifier reads from a block header: its
// transactions root, number and time.
type blockHeader struct {
	txRoot common.Hash
	number uint64
	time   uint64
}

// maxRLPDepth is how deep a list may sit in a block header or a trie
// node, the outermost list counting as depth 1 (Anchor §10.4
// item 6).
const maxRLPDepth = 64

// rlpDepthOK reports whether b is one RLP item with nothing after it, in
// which every list splits into RLP items and no list lies deeper than
// maxRLPDepth. It walks items that no rule reads as well, so that the
// verdict on a header or a node never depends on how far a decoder
// recurses.
func rlpDepthOK(b []byte) bool {
	kind, content, rest, err := rlp.Split(b)
	if err != nil || len(rest) != 0 {
		return false
	}
	return kind != rlp.List || listDepthOK(content, 1)
}

// listDepthOK checks the items of a list at the given depth.
func listDepthOK(content []byte, depth int) bool {
	if depth > maxRLPDepth {
		return false
	}
	for len(content) > 0 {
		kind, val, rest, err := rlp.Split(content)
		if err != nil {
			return false
		}
		if kind == rlp.List && !listDepthOK(val, depth+1) {
			return false
		}
		content = rest
	}
	return true
}

// headerFields is the least number of fields a header has: the fifteen of
// the pre-London layout. Later forks append fields, and a header may carry
// more than this verifier's go-ethereum knows of.
const headerFields = 15

// parseHeader reads the three header fields Anchor §10.4 item 6
// needs, by their positions in the Ethereum header (Yellow Paper §4.3):
// transactionsRoot (item 4), a 32-byte string; number (item 8) and
// timestamp (item 11), canonical RLP integers (no leading zero byte) within
// JSON's safe integers, since the number is compared with the entry's
// blockNumber. The header must be one RLP list of at least the fifteen
// items every fork has had, within the depth limit of rlpDepthOK. Later
// forks only append fields, so the other items are read for that limit
// alone: keccak256 over the raw bytes, compared with blockHash, already
// binds every field. Decoding into go-ethereum's types.Header instead would
// refuse a genuine header of a fork newer than the linked go-ethereum.
func parseHeader(b []byte) (*blockHeader, bool) {
	if !rlpDepthOK(b) {
		return nil, false
	}
	content, rest, err := rlp.SplitList(b)
	if err != nil || len(rest) != 0 {
		return nil, false
	}
	type item struct {
		kind rlp.Kind
		val  []byte
	}
	var items []item
	for len(content) > 0 {
		kind, val, r, err := rlp.Split(content)
		if err != nil {
			return nil, false
		}
		items = append(items, item{kind, val})
		content = r
	}
	if len(items) < headerFields {
		return nil, false
	}
	safeInt := func(it item) (uint64, bool) {
		if it.kind == rlp.List || len(it.val) > 7 || (len(it.val) > 0 && it.val[0] == 0) {
			return 0, false
		}
		var n uint64
		for _, c := range it.val {
			n = n<<8 | uint64(c)
		}
		return n, n <= 1<<53-1
	}
	root := items[4]
	if root.kind != rlp.String || len(root.val) != 32 {
		return nil, false
	}
	number, ok1 := safeInt(items[8])
	time, ok2 := safeInt(items[11])
	if !ok1 || !ok2 {
		return nil, false
	}
	return &blockHeader{txRoot: common.BytesToHash(root.val), number: number, time: time}, true
}

// SourceErrReason names a failed header-source call: the deadline shared
// by every call of one verification passed, or the source failed.
func SourceErrReason(ctx context.Context, err error) string { return sourceErrReason(ctx, err) }

func sourceErrReason(ctx context.Context, err error) string {
	if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		return ReasonTimeout
	}
	return ReasonUnavailable
}

// ISOTime renders a Unix time as JavaScript's Date.toISOString does.
func ISOTime(sec uint64) string {
	return time.Unix(int64(sec), 0).UTC().Format("2006-01-02T15:04:05.000Z")
}

// Verify runs §10.4 items 1 to 15 over one publication.
func Verify(in Input) (res Result) {
	txID := fmt.Sprintf("anchor.evm.tx[%d]", in.Index)
	canID := fmt.Sprintf("anchor.evm.canonical[%d]", in.Index)
	res.Tx = report.Check{ID: txID}
	res.Canonical = report.Check{ID: canID}
	defer func() {
		if r := recover(); r != nil {
			res.Tx = report.Check{ID: txID, Outcome: report.NotChecked, Reason: ReasonVerifierError}
			res.Canonical = report.BlockedBy(canID, txID)
			res.Valid, res.Reason = nil, ReasonNotChecked
		}
	}()
	verify(&in, &res)
	res.Valid, res.Reason = publicationOutcome(&res.Tx, &res.Canonical)
	return res
}

// publicationOutcome is the publication level of §10.1.
func publicationOutcome(checks ...*report.Check) (*bool, string) {
	for _, c := range checks {
		if c.Outcome == report.Wrong {
			f := false
			return &f, c.Reason
		}
	}
	for _, c := range checks {
		if c.Outcome == report.Abstain {
			return nil, c.Reason
		}
	}
	for _, c := range checks {
		if c.Outcome != report.Correct {
			return nil, ReasonNotChecked
		}
	}
	t := true
	return &t, ""
}

func (r *Result) txFail(reason string) {
	r.Tx.Outcome, r.Tx.Reason = report.Wrong, reason
	r.Canonical = report.BlockedBy(r.Canonical.ID, r.Tx.ID)
}

func (r *Result) txNotChecked(reason string) {
	r.Tx.Outcome, r.Tx.Reason = report.NotChecked, reason
	r.Canonical = report.BlockedBy(r.Canonical.ID, r.Tx.ID)
}

func verify(in *Input, r *Result) {
	e := in.Entry
	// Item 1, the two dispatch rules for a direct call.
	if e == nil || e.Kind != jsonv.Object {
		r.txFail(ReasonMalformed)
		return
	}
	if k, ok := e.Get("kind"); !ok || k.Kind != jsonv.String || k.Lone || k.S != Kind {
		r.Tx.Outcome, r.Tx.Reason = report.Abstain, ReasonUnsupportedKind
		r.Canonical = report.BlockedBy(r.Canonical.ID, r.Tx.ID)
		return
	}
	if len(in.P) != 32 {
		r.txNotChecked(ReasonNoP)
		return
	}
	if _, present := member(e, "rawTransaction"); !present {
		r.txNotChecked(ReasonNoRaw)
		return
	}
	p, ok := shape(e)
	if !ok {
		r.txFail(ReasonMalformed)
		return
	}

	// Item 2.
	tx, sender, why := decodeTx(p.raw)
	switch why {
	case ReasonUnsupportedTxType:
		r.Tx.Outcome, r.Tx.Reason = report.Abstain, why
		r.Canonical = report.BlockedBy(r.Canonical.ID, r.Tx.ID)
		return
	case ReasonMalformed:
		r.txFail(why)
		return
	}
	computedID := crypto.Keccak256Hash(p.raw)
	signed := signedChainID(tx)
	senderHex := strings.ToLower(sender.Hex())
	r.Tx.SetFact("transactionId", report.S(strings.ToLower(computedID.Hex())))
	r.Tx.SetFact("txType", report.N(uint64(tx.Type())))
	r.Tx.SetFact("sender", report.S(senderHex))
	r.Tx.SetFact("signedChainId", chainIDFact(signed))

	// Item 3.
	if p.txID != nil && *p.txID != computedID {
		r.txFail(ReasonTxProofInvalid)
		return
	}
	// Item 4.
	if !bytes.Equal(tx.Data(), in.P) {
		r.txFail(ReasonCalldataMismatch)
		return
	}
	// Item 5.
	look := manifest.ForOrigin(in.Manifest, in.AnchorOrigin)
	switch look.State {
	case manifest.Unreadable:
		r.txNotChecked(ReasonManifestUnreadable)
		return
	case manifest.NoEntries:
		r.txNotChecked(ReasonNoExpectation)
		return
	}
	var bySender, matching []manifest.Entry
	for _, en := range look.Entries {
		if en.Address == senderHex {
			bySender = append(bySender, en)
		}
	}
	if len(bySender) == 0 {
		r.txFail(ReasonSenderMismatch)
		return
	}
	for _, en := range bySender {
		if signed != nil && en.ChainID.Cmp(signed) == 0 {
			matching = append(matching, en)
		}
	}
	if len(matching) == 0 {
		r.txFail(ReasonChainMismatch)
		return
	}

	// Item 6.
	trieVerified := false
	var header *blockHeader
	if p.header != nil {
		h, ok := parseHeader(p.header)
		if !ok || crypto.Keccak256Hash(p.header) != p.blockHash || h.number != p.blockNum {
			r.txFail(ReasonTxProofInvalid)
			return
		}
		header = h
		if p.hasTxProof {
			val, err := walkProof(h.txRoot, p.txIndex, p.txProof)
			if err != nil || !bytes.Equal(val, p.raw) {
				r.txFail(ReasonTxProofInvalid)
				return
			}
			trieVerified = true
		}
		if !anyValid(matching, int64(h.time)) {
			r.txFail(ReasonSenderMismatch)
			return
		}
		r.Tx.Outcome = report.Correct
	} else {
		bounded := false
		for _, en := range matching {
			if en.Bounded() {
				bounded = true
			}
		}
		if bounded {
			r.Tx.Outcome, r.Tx.Reason = report.NotChecked, ReasonNoHeader
		} else {
			r.Tx.Outcome = report.Correct
		}
	}

	// Items 7 to 14: anchor.evm.canonical.
	chain := matching[0].Chain
	src := in.Sources.For(chain)
	if src == nil {
		r.Canonical.Outcome, r.Canonical.Reason = report.NotChecked, ReasonNoSource
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), in.Deadline)
	defer cancel()
	notChecked := func(reason string) {
		r.Canonical.Outcome, r.Canonical.Reason = report.NotChecked, reason
	}
	srcChain, err := src.ChainID(ctx)
	if err != nil || srcChain == nil {
		notChecked(sourceErrReason(ctx, orUnusable(err)))
		return
	}
	if srcChain.Cmp(signed) != 0 {
		notChecked(ReasonSourceChain)
		return
	}
	fin := src.Finality()
	r.Finality = fin
	if fin.Declared {
		r.Canonical.SetFact("finality", fin.JSON())
	}
	finalized, err := src.FinalizedHeight(ctx)
	if err != nil {
		notChecked(sourceErrReason(ctx, err))
		return
	}
	if p.blockNum > finalized {
		notChecked(ReasonNotFinalized)
		return
	}
	blk, err := src.BlockAt(ctx, p.blockNum)
	if err != nil {
		notChecked(sourceErrReason(ctx, err))
		return
	}
	if blk == nil {
		notChecked(ReasonInconsistent)
		return
	}
	if blk.Hash != p.blockHash {
		r.Canonical.Outcome, r.Canonical.Reason = report.Wrong, ReasonNotFoundOnChain
		return
	}
	if header != nil && blk.Time != header.time {
		notChecked(ReasonInconsistent)
		return
	}

	// Item 12: inclusion.
	inclusion := ""
	if trieVerified {
		inclusion = "tx_proof"
	}
	lk, lerr := src.LookupTx(ctx, computedID)
	switch {
	case errors.Is(lerr, ErrNoLookup) || (lerr == nil && lk == nil):
		// No lookup, or nothing found: never a statement.
	case lerr != nil:
		if !trieVerified {
			notChecked(sourceErrReason(ctx, lerr))
			return
		}
	case lk.BlockHash == nil || lk.Sender == nil:
		notChecked(ReasonInconsistent)
		return
	case *lk.BlockHash != p.blockHash:
		if trieVerified || lk.BlockNumber == nil {
			notChecked(ReasonInconsistent)
			return
		}
		named, err := src.BlockAt(ctx, *lk.BlockNumber)
		if err != nil {
			notChecked(sourceErrReason(ctx, err))
			return
		}
		if named != nil && named.Hash == *lk.BlockHash {
			r.Canonical.Outcome, r.Canonical.Reason = report.Wrong, ReasonNotFoundOnChain
			return
		}
		notChecked(ReasonInconsistent)
		return
	case *lk.Sender != sender:
		notChecked(ReasonInconsistent)
		return
	default:
		if !trieVerified {
			inclusion = "header_source"
		}
	}
	if inclusion == "" {
		if p.hasTxProof && header == nil {
			notChecked(ReasonNoHeader)
		} else {
			notChecked(ReasonNoTxProof)
		}
		return
	}

	// Item 13: the window at the confirmed block time, reported on the tx
	// check.
	var valid []manifest.Entry
	for _, en := range matching {
		if en.ValidAt(int64(blk.Time)) {
			valid = append(valid, en)
		}
	}
	if len(valid) == 0 {
		r.Tx.Outcome, r.Tx.Reason = report.Wrong, ReasonSenderMismatch
	} else if r.Tx.Outcome == report.NotChecked {
		r.Tx.Outcome, r.Tx.Reason = report.Correct, ""
	}

	// Item 14.
	r.Canonical.Outcome = report.Correct
	r.Chain = chain
	r.Network = manifest.Network(chain)
	r.BlockTime = blk.Time
	r.Inclusion = inclusion
	if len(valid) > 0 {
		ns, agree := valid[0].Namespace, true
		for _, en := range valid[1:] {
			if en.Namespace != ns {
				agree = false
			}
		}
		if agree {
			r.Namespace = &ns
		}
	}
	network := report.Null()
	if r.Network != "" {
		network = report.S(r.Network)
	}
	r.Canonical.SetFact("chain", report.S(chain))
	r.Canonical.SetFact("namespace", report.SOrNull(r.Namespace))
	r.Canonical.SetFact("network", network)
	r.Canonical.SetFact("blockTime", report.S(ISOTime(blk.Time)))
	r.Canonical.SetFact("inclusion", report.S(inclusion))
}

func orUnusable(err error) error {
	if err == nil {
		return errors.New("header source gave no chain id")
	}
	return err
}

func anyValid(entries []manifest.Entry, t int64) bool {
	for _, e := range entries {
		if e.ValidAt(t) {
			return true
		}
	}
	return false
}
