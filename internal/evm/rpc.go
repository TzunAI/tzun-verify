package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// RPCSource is a header source backed by an Ethereum JSON-RPC endpoint the
// auditor chooses. It asks the node for its chain id, its finalized block
// (or its head, in confirmation-depth mode), the canonical block at a height
// and, optionally, a transaction by hash.
type RPCSource struct {
	URL    string
	Mode   Finality
	Client *http.Client
	// NoLookup disables transaction lookups.
	NoLookup bool

	mu      sync.Mutex
	chainID *big.Int
	nextID  int
}

// NewRPCSource returns a source for url. confirmations 0 selects the
// chain's finalized tag; a depth below MinFinalConfirmations is refused
// unless acceptNonFinal is set.
func NewRPCSource(rawURL string, confirmations uint64, acceptNonFinal bool) (*RPCSource, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("evm-rpc: %q is not an http(s) URL", rawURL)
	}
	mode := Finality{Declared: true, Finalized: true}
	if confirmations > 0 {
		if confirmations < MinFinalConfirmations && !acceptNonFinal {
			return nil, fmt.Errorf("evm-rpc: %d confirmations is not finality on Ethereum (at least %d); pass --accept-non-final to use it anyway", confirmations, MinFinalConfirmations)
		}
		mode = Finality{Declared: true, Confirmations: confirmations, AcceptNonFinal: acceptNonFinal && confirmations < MinFinalConfirmations}
	}
	return &RPCSource{URL: rawURL, Mode: mode, Client: &http.Client{}}, nil
}

// Describe implements HeaderSource. It reports the endpoint's scheme and
// host only: a path or query can carry an API key.
func (s *RPCSource) Describe() *jsonv.Value {
	host := ""
	if u, err := url.Parse(s.URL); err == nil {
		host = u.Scheme + "://" + u.Host
	}
	return report.Obj("finality", s.Mode.JSON(), "kind", report.S("json-rpc"), "endpoint", report.S(host))
}

// Finality implements HeaderSource.
func (s *RPCSource) Finality() Finality { return s.Mode }

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

func (s *RPCSource) call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	s.mu.Lock()
	s.nextID++
	id := s.nextID
	s.mu.Unlock()
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("evm-rpc: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var r rpcResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("evm-rpc: unreadable response: %w", err)
	}
	if r.Error != nil {
		return nil, fmt.Errorf("evm-rpc: %s: %d %s", method, r.Error.Code, r.Error.Message)
	}
	return r.Result, nil
}

func parseQuantity(raw json.RawMessage) (*big.Int, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("evm-rpc: quantity is not a string")
	}
	if !strings.HasPrefix(s, "0x") || len(s) < 3 || len(s) > 66 {
		return nil, fmt.Errorf("evm-rpc: bad quantity %q", s)
	}
	n, ok := new(big.Int).SetString(s[2:], 16)
	if !ok {
		return nil, fmt.Errorf("evm-rpc: bad quantity %q", s)
	}
	return n, nil
}

func parseUint(raw json.RawMessage) (uint64, error) {
	n, err := parseQuantity(raw)
	if err != nil {
		return 0, err
	}
	if !n.IsUint64() {
		return 0, errors.New("evm-rpc: quantity out of range")
	}
	return n.Uint64(), nil
}

func parseHash(raw json.RawMessage) (*common.Hash, error) {
	var s *string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, errors.New("evm-rpc: hash is not a string")
	}
	if s == nil {
		return nil, nil
	}
	if len(*s) != 66 || !strings.HasPrefix(*s, "0x") {
		return nil, fmt.Errorf("evm-rpc: bad hash %q", *s)
	}
	for _, c := range (*s)[2:] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return nil, fmt.Errorf("evm-rpc: bad hash %q", *s)
		}
	}
	h := common.HexToHash(*s)
	return &h, nil
}

// ChainID implements HeaderSource.
func (s *RPCSource) ChainID(ctx context.Context) (*big.Int, error) {
	s.mu.Lock()
	cached := s.chainID
	s.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
	raw, err := s.call(ctx, "eth_chainId")
	if err != nil {
		return nil, err
	}
	id, err := parseQuantity(raw)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.chainID = id
	s.mu.Unlock()
	return id, nil
}

type rpcBlock struct {
	Number    json.RawMessage `json:"number"`
	Hash      json.RawMessage `json:"hash"`
	Timestamp json.RawMessage `json:"timestamp"`
}

func (s *RPCSource) block(ctx context.Context, tag string) (*rpcBlock, error) {
	raw, err := s.call(ctx, "eth_getBlockByNumber", tag, false)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var b rpcBlock
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("evm-rpc: unreadable block: %w", err)
	}
	return &b, nil
}

// FinalizedHeight implements HeaderSource.
func (s *RPCSource) FinalizedHeight(ctx context.Context) (uint64, error) {
	tag := "finalized"
	if !s.Mode.Finalized {
		tag = "latest"
	}
	b, err := s.block(ctx, tag)
	if err != nil {
		return 0, err
	}
	if b == nil {
		return 0, fmt.Errorf("evm-rpc: no %s block", tag)
	}
	n, err := parseUint(b.Number)
	if err != nil {
		return 0, err
	}
	if s.Mode.Finalized {
		return n, nil
	}
	if n < s.Mode.Confirmations {
		return 0, nil
	}
	return n - s.Mode.Confirmations, nil
}

// BlockAt implements HeaderSource.
func (s *RPCSource) BlockAt(ctx context.Context, n uint64) (*Block, error) {
	b, err := s.block(ctx, "0x"+strconv.FormatUint(n, 16))
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, nil
	}
	num, err := parseUint(b.Number)
	if err != nil {
		return nil, err
	}
	if num != n {
		return nil, fmt.Errorf("evm-rpc: asked for block %d, got %d", n, num)
	}
	h, err := parseHash(b.Hash)
	if err != nil || h == nil {
		return nil, errors.New("evm-rpc: block without a hash")
	}
	t, err := parseUint(b.Timestamp)
	if err != nil {
		return nil, err
	}
	return &Block{Hash: *h, Time: t}, nil
}

// LookupTx implements HeaderSource.
func (s *RPCSource) LookupTx(ctx context.Context, id common.Hash) (*TxLookup, error) {
	if s.NoLookup {
		return nil, ErrNoLookup
	}
	raw, err := s.call(ctx, "eth_getTransactionByHash", id.Hex())
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var t struct {
		BlockHash   json.RawMessage `json:"blockHash"`
		BlockNumber json.RawMessage `json:"blockNumber"`
		From        *string         `json:"from"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("evm-rpc: unreadable transaction: %w", err)
	}
	out := &TxLookup{}
	if len(t.BlockHash) > 0 {
		h, err := parseHash(t.BlockHash)
		if err != nil {
			return nil, err
		}
		out.BlockHash = h
	}
	if len(t.BlockNumber) > 0 && string(t.BlockNumber) != "null" {
		n, err := parseUint(t.BlockNumber)
		if err != nil {
			return nil, err
		}
		out.BlockNumber = &n
	}
	if t.From != nil {
		if !common.IsHexAddress(*t.From) {
			return nil, fmt.Errorf("evm-rpc: bad sender %q", *t.From)
		}
		a := common.HexToAddress(*t.From)
		out.Sender = &a
	}
	return out, nil
}
