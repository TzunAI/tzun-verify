package evm

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// MinFinalConfirmations is the least confirmation depth that counts as
// finality on Ethereum: two epochs, the least distance at which the
// finalized block can trail the head (Anchor §10.4).
const MinFinalConfirmations = 64

// Finality is what a header source counts as final.
type Finality struct {
	// Declared is false for a source that states no mode.
	Declared bool
	// Finalized is true for the chain's own finalized tag.
	Finalized bool
	// Confirmations is the depth, when Finalized is false.
	Confirmations uint64
	// AcceptNonFinal is set when the auditor accepted a depth below
	// MinFinalConfirmations.
	AcceptNonFinal bool
}

// JSON renders the mode as the report states it: "finalized", or
// {"confirmations": n} with "acceptNonFinal": true when it was set.
func (f Finality) JSON() *jsonv.Value {
	if !f.Declared {
		return report.Null()
	}
	if f.Finalized {
		return report.S("finalized")
	}
	if f.AcceptNonFinal {
		return report.Obj("acceptNonFinal", report.B(true), "confirmations", report.N(f.Confirmations))
	}
	return report.Obj("confirmations", report.N(f.Confirmations))
}

// Block is a canonical block as a header source reports it.
type Block struct {
	Hash common.Hash
	Time uint64
}

// TxLookup is a header source's answer about a transaction. A nil pointer
// member means the source did not report it.
type TxLookup struct {
	BlockHash   *common.Hash
	BlockNumber *uint64
	Sender      *common.Address
}

// ErrNoLookup is returned by a header source that does not look
// transactions up.
var ErrNoLookup = errors.New("evm: this header source does not look transactions up")

// HeaderSource is the auditor's own view of one EVM chain (§10.4). The
// verifier trusts it for canonicality and finality, and for nothing else.
type HeaderSource interface {
	// ChainID is the chain id the source serves.
	ChainID(ctx context.Context) (*big.Int, error)
	// Finality is the source's declared finality mode.
	Finality() Finality
	// FinalizedHeight is the height of the newest block it considers final.
	FinalizedHeight(ctx context.Context) (uint64, error)
	// BlockAt returns the canonical block at a height, or nil for none.
	BlockAt(ctx context.Context, n uint64) (*Block, error)
	// LookupTx looks a transaction up by id: nil for not found, ErrNoLookup
	// when the source does not look transactions up.
	LookupTx(ctx context.Context, id common.Hash) (*TxLookup, error)
	// Describe names the source for the report's inputs, without secrets.
	Describe() *jsonv.Value
}

// Sources holds the auditor's header sources: ByChain, keyed by CAIP-2
// chain, and Any, a source for whichever chain a publication's manifest
// entry names (its own chain id is then checked against the transaction's).
type Sources struct {
	ByChain map[string]HeaderSource
	Any     HeaderSource
}

// For returns the source for a CAIP-2 chain.
func (s Sources) For(chain string) HeaderSource {
	if src, ok := s.ByChain[chain]; ok {
		return src
	}
	return s.Any
}

// Empty reports whether no source is configured.
func (s Sources) Empty() bool { return len(s.ByChain) == 0 && s.Any == nil }

// StaticSource is a header source that answers from fixed data, the way the
// end-to-end vectors state a source's answers. It looks no transaction up
// unless Txs is set.
type StaticSource struct {
	Chain     *big.Int
	Mode      Finality
	Finalized uint64
	Blocks    map[uint64]Block
	Txs       map[common.Hash]TxLookup
	// Err, when set, is returned by every call.
	Err error
}

// ChainID implements HeaderSource.
func (s *StaticSource) ChainID(context.Context) (*big.Int, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	return s.Chain, nil
}

// Finality implements HeaderSource.
func (s *StaticSource) Finality() Finality { return s.Mode }

// FinalizedHeight implements HeaderSource.
func (s *StaticSource) FinalizedHeight(context.Context) (uint64, error) {
	if s.Err != nil {
		return 0, s.Err
	}
	return s.Finalized, nil
}

// BlockAt implements HeaderSource.
func (s *StaticSource) BlockAt(_ context.Context, n uint64) (*Block, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	b, ok := s.Blocks[n]
	if !ok {
		return nil, nil
	}
	return &b, nil
}

// LookupTx implements HeaderSource.
func (s *StaticSource) LookupTx(_ context.Context, id common.Hash) (*TxLookup, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	if s.Txs == nil {
		return nil, ErrNoLookup
	}
	t, ok := s.Txs[id]
	if !ok {
		return nil, nil
	}
	return &t, nil
}

// Describe implements HeaderSource.
func (s *StaticSource) Describe() *jsonv.Value {
	id := report.Null()
	if s.Chain != nil {
		id = report.S("eip155:" + s.Chain.String())
	}
	return report.Obj("chain", id, "finality", s.Mode.JSON(), "kind", report.S("static"))
}

// ParseStaticSource reads a header source from a file the auditor wrote:
//
//	{ "chainId": 31337,
//	  "finality": "finalized" | { "confirmations": n, "acceptNonFinal": true },
//	  "finalizedBlockNumber": 13,
//	  "blocks": [ { "number": 1, "hash": "0x…", "timestamp": 1790444377 } ] }
//
// It is taken at its word, as any header source is: finalizedBlockNumber is
// the newest block it calls final, and blocks are the canonical blocks it
// knows. It has no block at any other height and looks no transaction up. A
// member it does not know is refused, so a misspelling never changes what
// the source says.
func ParseStaticSource(data []byte) (*StaticSource, error) {
	v, err := jsonv.Parse(data)
	if err != nil {
		return nil, err
	}
	if v.Kind != jsonv.Object {
		return nil, errors.New("not a JSON object")
	}
	for _, k := range v.Keys() {
		switch k {
		case "chainId", "finality", "finalizedBlockNumber", "blocks":
		default:
			return nil, fmt.Errorf("unknown member %q", k)
		}
	}
	src := &StaticSource{Blocks: map[uint64]Block{}}
	cid, _ := v.Get("chainId")
	n, ok := cid.Uint53()
	if !ok || n == 0 {
		return nil, errors.New("chainId must be a positive integer")
	}
	src.Chain = new(big.Int).SetUint64(n)
	fin, _ := v.Get("finality")
	switch {
	case fin != nil && fin.Kind == jsonv.String && fin.S == "finalized":
		src.Mode = Finality{Declared: true, Finalized: true}
	case fin != nil && fin.Kind == jsonv.Object:
		c, _ := fin.Get("confirmations")
		depth, ok := c.Uint53()
		accept := false
		if a, present := fin.Get("acceptNonFinal"); present {
			if a.Kind != jsonv.Bool {
				return nil, errors.New("finality.acceptNonFinal must be a boolean")
			}
			accept = a.B
		}
		if !ok || depth == 0 || len(fin.O) > 2 || (len(fin.O) == 2 && !fin.Has("acceptNonFinal")) {
			return nil, errors.New(`finality must be "finalized" or {"confirmations": n}`)
		}
		if depth < MinFinalConfirmations && !accept {
			return nil, fmt.Errorf("%d confirmations is not finality on Ethereum (at least %d); set acceptNonFinal to use it anyway", depth, MinFinalConfirmations)
		}
		src.Mode = Finality{Declared: true, Confirmations: depth, AcceptNonFinal: accept && depth < MinFinalConfirmations}
	default:
		return nil, errors.New(`finality must be "finalized" or {"confirmations": n}`)
	}
	fb, _ := v.Get("finalizedBlockNumber")
	if src.Finalized, ok = fb.Uint53(); !ok {
		return nil, errors.New("finalizedBlockNumber must be a block number")
	}
	blocks, _ := v.Get("blocks")
	if blocks == nil || blocks.Kind != jsonv.Array {
		return nil, errors.New("blocks must be an array")
	}
	for i, b := range blocks.A {
		num, _ := b.Get("number")
		hash, _ := b.Get("hash")
		ts, _ := b.Get("timestamp")
		bn, ok1 := num.Uint53()
		t, ok2 := ts.Uint53()
		h, ok3 := hash.Str()
		hb, ok4 := decodeHex0x(h)
		if b.Kind != jsonv.Object || len(b.O) != 3 || !ok1 || !ok2 || !ok3 || !ok4 || len(hb) != 32 {
			return nil, fmt.Errorf("blocks[%d] must be {number, hash, timestamp}", i)
		}
		if _, dup := src.Blocks[bn]; dup {
			return nil, fmt.Errorf("blocks[%d]: a second block at height %d", i, bn)
		}
		src.Blocks[bn] = Block{Hash: common.BytesToHash(hb), Time: t}
	}
	return src, nil
}
