// SPDX-License-Identifier: BSD-3-Clause-Clear

package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
	"github.com/TzunAI/tzun-verify/internal/testpki"
	"github.com/TzunAI/tzun-verify/publishers"
)

func loadE2E(t *testing.T) *jsonv.Value {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "anchor-e2e-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsonv.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func g(v *jsonv.Value, path ...string) *jsonv.Value {
	for _, p := range path {
		v, _ = v.Get(p)
	}
	return v
}

func with(o *jsonv.Value, k string, v *jsonv.Value) *jsonv.Value {
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

func without(o *jsonv.Value, k string) *jsonv.Value {
	c := &jsonv.Value{Kind: jsonv.Object}
	for _, m := range o.O {
		if m.Key != k {
			c.O = append(c.O, m)
		}
	}
	return c
}

func sizeOf(body string) uint64 {
	n, _ := strconv.ParseUint(strings.Split(body, "\n")[1], 10, 64)
	return n
}

func hexPath(p [][]byte) *jsonv.Value {
	a := report.Arr()
	for _, h := range p {
		a.A = append(a.A, report.S(hex.EncodeToString(h)))
	}
	return a
}

// bundleFor builds a b1 record bundle, laid out as Bundle states,
// for record i of the end-to-end vectors: the envelope; the record's own
// checkpoints and, when its log grew in the second epoch, the newest ones,
// with the subject's anchor into them stated on the newer evidence-log
// checkpoint (logPath, anchorLeafIndex, anchorSize, anchorPath) and one
// consistency proof per level.
func bundleFor(t *testing.T, d *jsonv.Value, i int) *jsonv.Value {
	t.Helper()
	records := g(d, "records").A
	rec := records[i]
	env := g(rec, "envelope")
	anc := g(env, "nonRepudiation", "anchor")
	epochs := g(d, "epochs").A
	logBody := g(anc, "logCheckpoint").S
	logOrigin := strings.SplitN(logBody, "\n", 2)[0]
	anchorOrigin := g(d, "anchorOrigin").S
	epoch, _ := g(rec, "epoch").Uint53()

	anchorCps := []*jsonv.Value{report.Obj("body", g(epochs[epoch], "anchorCheckpoint"), "signatures", report.Arr(),
		"publications", report.Arr(g(epochs[epoch], "publication")))}
	anchorCons := report.Arr()
	logCps := []*jsonv.Value{report.Obj("body", report.S(logBody), "signatures", report.Arr())}
	logCons := report.Arr()
	if epoch == 0 {
		for _, m := range g(epochs[1], "members").A {
			prev := g(m, "previousLogCheckpoint")
			if prev.Kind != jsonv.String || prev.S != logBody {
				continue
			}
			newer := g(m, "logCheckpoint").S
			// The subject's path in the newer log, from every leaf of the log.
			tree := testonly.New(rfc6962.DefaultHasher)
			seq, _ := g(env, "payload", "sequenceNumber").Uint53()
			for n := uint64(1); n <= sizeOf(newer); n++ {
				for _, r := range records {
					if g(r, "chainId").S == g(rec, "chainId").S {
						if s, _ := g(r, "envelope", "payload", "sequenceNumber").Uint53(); s == n {
							leaf, _ := hex.DecodeString(g(r, "envelope", "integrity", "canonicalDigest").S)
							tree.AppendData(leaf)
						}
					}
				}
			}
			logPath, err := tree.InclusionProof(seq-1, sizeOf(newer))
			if err != nil {
				t.Fatal(err)
			}
			// The newer body's path in the second anchor checkpoint, taken
			// from a record of the second epoch in the same log.
			var anchorPath *jsonv.Value
			for _, r2 := range records {
				a2 := g(r2, "envelope", "nonRepudiation", "anchor")
				if g(a2, "logCheckpoint").S == newer {
					anchorPath = g(a2, "anchorPath")
				}
			}
			if anchorPath == nil {
				t.Fatalf("no anchor path for %s", newer)
			}
			anchorBody := g(epochs[1], "anchorCheckpoint").S
			logCps = append(logCps, report.Obj("body", report.S(newer), "signatures", report.Arr(),
				"logPath", hexPath(logPath), "anchorLeafIndex", g(m, "anchorLeafIndex"),
				"anchorSize", report.N(sizeOf(anchorBody)), "anchorPath", anchorPath))
			logCons.A = append(logCons.A, report.Obj("fromSize", report.N(sizeOf(logBody)), "toSize", report.N(sizeOf(newer)),
				"path", g(m, "consistencyProof")))
			anchorCps = append(anchorCps, report.Obj("body", report.S(anchorBody), "signatures", report.Arr(),
				"publications", report.Arr(g(epochs[1], "publication"))))
			anchorCons.A = append(anchorCons.A, report.Obj("fromSize", g(epochs[1], "previousAnchorSize"),
				"toSize", report.N(sizeOf(anchorBody)), "path", g(epochs[1], "anchorConsistencyProof")))
		}
	}
	return report.Obj(
		"bundleVersion", report.S("b1"),
		"profile", report.S("record"),
		"subject", report.Obj("evidenceId", g(env, "payload", "evidenceId"), "canonicalDigest", g(env, "integrity", "canonicalDigest")),
		"envelope", env,
		"chain", report.Obj("chainId", g(rec, "chainId"), "predecessor", predecessorOf(records, rec)),
		"custody", report.Obj("entries", report.Arr()),
		"credentials", report.Null(),
		"relatedRecords", report.Null(),
		"anchoring", report.Obj(
			anchorOrigin, report.Obj("checkpoints", report.Arr(anchorCps...), "consistency", anchorCons),
			logOrigin, report.Obj("checkpoints", report.Arr(logCps...), "consistency", logCons),
		),
		"anchorPending", report.Null(),
		"policy", report.Null(),
		"extensions", report.Obj("witness/1", report.Null()),
		"exporter", report.Obj("exportedAt", report.S("2026-09-26T01:00:00.000Z")),
	)
}

// predecessorOf is chain.predecessor: the chain's record numbered one
// below rec, or null when rec is the chain's first.
func predecessorOf(records []*jsonv.Value, rec *jsonv.Value) *jsonv.Value {
	seq, _ := g(rec, "envelope", "payload", "sequenceNumber").Uint53()
	for _, r := range records {
		s, _ := g(r, "envelope", "payload", "sequenceNumber").Uint53()
		if g(r, "chainId").S == g(rec, "chainId").S && s+1 == seq {
			return report.Obj("sequenceNumber", report.N(s), "canonicalDigest", g(r, "envelope", "integrity", "canonicalDigest"))
		}
	}
	return report.Null()
}

func write(t *testing.T, dir, name string, v *jsonv.Value) string {
	t.Helper()
	b, err := canonical.Serialize(v)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeNode answers the JSON-RPC calls a header source makes, from the
// end-to-end vectors' header source; override replaces the hash of a block.
func fakeNode(t *testing.T, d *jsonv.Value, override map[uint64]string) *httptest.Server {
	hs := g(d, "headerSource")
	chainID, _ := g(hs, "chainId").Uint53()
	final, _ := g(hs, "finalizedBlockNumber").Uint53()
	blocks := map[uint64][2]string{}
	for _, ep := range g(d, "epochs").A {
		cb := g(ep, "canonicalBlock")
		n, _ := g(cb, "number").Uint53()
		ts, _ := g(cb, "timestamp").Uint53()
		h := g(cb, "hash").S
		if o, ok := override[n]; ok {
			h = o
		}
		blocks[n] = [2]string{h, fmt.Sprintf("0x%x", ts)}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var result any
		switch req.Method {
		case "eth_chainId":
			result = fmt.Sprintf("0x%x", chainID)
		case "eth_getBlockByNumber":
			var tag string
			_ = json.Unmarshal(req.Params[0], &tag)
			n := final
			if tag != "finalized" && tag != "latest" {
				n, _ = strconv.ParseUint(strings.TrimPrefix(tag, "0x"), 16, 64)
			}
			if b, ok := blocks[n]; ok {
				result = map[string]string{"number": fmt.Sprintf("0x%x", n), "hash": b[0], "timestamp": b[1]}
			} else if tag == "finalized" {
				result = map[string]string{"number": fmt.Sprintf("0x%x", n), "hash": "0x" + strings.Repeat("00", 32), "timestamp": "0x0"}
			}
		case "eth_getTransactionByHash":
			result = nil
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
}

// headerFile writes the vectors' header source as an --evm-header-file.
func headerFile(t *testing.T, d *jsonv.Value, dir string) string {
	hs := g(d, "headerSource")
	blocks := report.Arr()
	for _, ep := range g(d, "epochs").A {
		cb := g(ep, "canonicalBlock")
		blocks.A = append(blocks.A, report.Obj("number", g(cb, "number"), "hash", g(cb, "hash"), "timestamp", g(cb, "timestamp")))
	}
	return write(t, dir, "headers.json", report.Obj("chainId", g(hs, "chainId"), "finality", g(hs, "finality"),
		"finalizedBlockNumber", g(hs, "finalizedBlockNumber"), "blocks", blocks))
}

type outcome struct {
	exit   int
	report *jsonv.Value
	text   string
}

func verify(t *testing.T, args ...string) outcome {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(append([]string{"--json"}, args...), &out, &errb)
	o := outcome{exit: code}
	if out.Len() > 0 {
		v, err := jsonv.Parse(out.Bytes())
		if err != nil {
			t.Fatalf("report is not JSON: %v\n%s", err, out.String())
		}
		o.report = v
	}
	var tb bytes.Buffer
	Run(args, &tb, &errb)
	o.text = tb.String()
	return o
}

func (o outcome) check(t *testing.T, id string) (string, string) {
	t.Helper()
	if o.report == nil {
		t.Fatalf("no report")
	}
	for _, c := range g(o.report, "checks").A {
		if g(c, "id").S == id {
			reason := ""
			if r, ok := c.Get("reason"); ok {
				reason = r.S
			}
			return g(c, "outcome").S, reason
		}
	}
	return "", ""
}

// row returns a report's row with the given id, an empty object for none.
func row(t *testing.T, o outcome, id string) *jsonv.Value {
	t.Helper()
	if o.report == nil {
		t.Fatalf("no report")
	}
	for _, c := range g(o.report, "checks").A {
		if g(c, "id").S == id {
			return c
		}
	}
	return &jsonv.Value{Kind: jsonv.Object}
}

func expect(t *testing.T, o outcome, id, outcome, reason string) {
	t.Helper()
	got, why := o.check(t, id)
	if got != outcome || why != reason {
		t.Errorf("%s: %s %q, want %s %q", id, got, why, outcome, reason)
	}
}

func mustJSON(v *jsonv.Value) string {
	b, _ := canonical.Serialize(v)
	return string(b)
}

func TestEndToEnd(t *testing.T) {
	d := loadE2E(t)
	dir := t.TempDir()
	manifest := write(t, dir, "publishers.json", g(d, "manifest"))
	node := fakeNode(t, d, nil)
	defer node.Close()
	b := write(t, dir, "alpha1.json", bundleFor(t, d, 0))
	anchorsID := "anchor.consistency[" + g(d, "anchorOrigin").S + "]"

	offline := verify(t, "--publishers", manifest, b)
	if offline.exit != 4 {
		t.Errorf("offline: exit %d, want 4", offline.exit)
	}
	expect(t, offline, "record.digest", "checked-correct", "")
	expect(t, offline, "record.chainLink", "checked-correct", "")
	expect(t, offline, "custody.ledger", "not-checked", "not_applicable")
	expect(t, offline, "ts.record.token", "not-checked", "absent")
	expect(t, offline, "signoff.key", "not-checked", "absent")
	expect(t, offline, "anchor.evm.tx[0]", "checked-correct", "")
	expect(t, offline, "anchor.evm.canonical[0]", "not-checked", "input_not_supplied:evm_header_source")
	expect(t, offline, "anchor", "not-checked", "publication_not_checked")
	expect(t, offline, "anchor.newer", "not-checked", "publication_not_checked")
	expect(t, offline, anchorsID, "not-checked", "blocked_by:anchor")
	if !strings.Contains(offline.text, "NOT CHECKED") || !strings.Contains(offline.text, "exit 4") {
		t.Errorf("text report:\n%s", offline.text)
	}
	// The report names what it was given: the manifest by the SHA-256 of
	// its bytes (written here in canonical form), no roots, no header
	// source.
	in := g(offline.report, "inputs")
	mb, _ := canonical.Serialize(g(d, "manifest"))
	if g(in, "publisherManifest").S != canonical.Digest(mb) || len(g(in, "trustAnchors").A) != 0 || len(g(in, "evmHeaderSources").A) != 0 {
		t.Errorf("inputs: %s", mustJSON(in))
	}

	allowed := verify(t, "--publishers", manifest, "--allow-unchecked", b)
	if allowed.exit != 0 || !strings.Contains(allowed.text, "NOT CHECKED") {
		t.Errorf("--allow-unchecked: exit %d; the NOT CHECKED lines are still printed:\n%s", allowed.exit, allowed.text)
	}

	online := verify(t, "--publishers", manifest, "--evm-rpc", node.URL, b)
	if online.exit != 0 {
		t.Errorf("online: exit %d, want 0\n%s", online.exit, online.text)
	}
	expect(t, online, "anchor", "checked-correct", "")
	expect(t, online, "anchor.evm.canonical[0]", "checked-correct", "")
	expect(t, online, "anchor.newer", "checked-correct", "")
	// One consistency proof per level: the evidence log and the anchor log.
	expect(t, online, anchorsID, "checked-correct", "")
	logOrigin := strings.SplitN(g(bundleFor(t, d, 0), "envelope", "nonRepudiation", "anchor", "logCheckpoint").S, "\n", 2)[0]
	expect(t, online, "anchor.consistency["+logOrigin+"]", "checked-correct", "")
	sum := g(online.report, "summary")
	if g(sum, "anchorNamespace").S != "test" || !g(sum, "anchorOriginAuthenticated").B || g(sum, "existedBy", "source").S != "evm-calldata" ||
		g(sum, "existedBy", "check").S != "anchor" {
		t.Errorf("summary: %s", mustJSON(sum))
	}
	if src := g(online.report, "inputs", "evmHeaderSources").A; len(src) != 1 || g(src[0], "chain").Kind != jsonv.Null || g(src[0], "finality").S != "finalized" {
		t.Errorf("inputs: %s", mustJSON(g(online.report, "inputs")))
	}
	if !strings.Contains(online.text, "publisher authenticated") {
		t.Errorf("text:\n%s", online.text)
	}

	// The same header source from a file the auditor wrote.
	file := verify(t, "--publishers", manifest, "--evm-header-file", "eip155:31337="+headerFile(t, d, dir), b)
	if file.exit != 0 {
		t.Errorf("header file: exit %d\n%s", file.exit, file.text)
	}
	if src := g(file.report, "inputs", "evmHeaderSources").A; len(src) != 1 || g(src[0], "chain").S != "eip155:31337" {
		t.Errorf("inputs: %s", mustJSON(g(file.report, "inputs")))
	}

	chainPrefixed := verify(t, "--publishers", manifest, "--evm-rpc", "eip155:31337="+node.URL, b)
	if chainPrefixed.exit != 0 {
		t.Errorf("chain-prefixed source: exit %d", chainPrefixed.exit)
	}
	wrongChain := verify(t, "--publishers", manifest, "--evm-rpc", "eip155:1="+node.URL, b)
	expect(t, wrongChain, "anchor.evm.canonical[0]", "not-checked", "input_not_supplied:evm_header_source")

	pinned := verify(t, "--evm-rpc", node.URL, b)
	if pinned.exit != 4 {
		t.Errorf("pinned manifest: exit %d", pinned.exit)
	}
	expect(t, pinned, "anchor.evm.tx[0]", "not-checked", "no_expectation:publisher")
	if g(pinned.report, "inputs", "publisherManifest").S != publishers.SHA256() {
		t.Errorf("pinned manifest digest: %s", mustJSON(g(pinned.report, "inputs")))
	}
	none := verify(t, "--no-publishers", "--evm-rpc", node.URL, b)
	expect(t, none, "anchor.evm.tx[0]", "not-checked", "no_expectation:publisher")
	if g(none.report, "inputs", "publisherManifest").Kind != jsonv.Null {
		t.Errorf("--no-publishers: %s", mustJSON(g(none.report, "inputs")))
	}

	required := verify(t, "--publishers", manifest, "--allow-unchecked", "--require", "anchor.evm.canonical[*]", b)
	if required.exit != 3 {
		t.Errorf("--require unmet: exit %d, want 3", required.exit)
	}
	requiredOK := verify(t, "--publishers", manifest, "--evm-rpc", node.URL, "--require", "anchor,anchor.evm.canonical[*]", b)
	if requiredOK.exit != 0 {
		t.Errorf("--require met: exit %d", requiredOK.exit)
	}

	reorg := fakeNode(t, d, map[uint64]string{1: "0x" + strings.Repeat("ab", 32)})
	defer reorg.Close()
	lost := verify(t, "--publishers", manifest, "--evm-rpc", reorg.URL, b)
	if lost.exit != 1 {
		t.Errorf("another canonical block: exit %d, want 1", lost.exit)
	}
	expect(t, lost, "anchor.evm.canonical[0]", "checked-wrong", "anchor_not_found_on_chain")

	// Every record of the vectors verifies end to end.
	for i := range g(d, "records").A {
		p := write(t, dir, fmt.Sprintf("r%d.json", i), bundleFor(t, d, i))
		if o := verify(t, "--publishers", manifest, "--evm-rpc", node.URL, p); o.exit != 0 {
			t.Errorf("record %d: exit %d\n%s", i, o.exit, o.text)
		}
	}
}

func TestTamperAndForgery(t *testing.T) {
	d := loadE2E(t)
	dir := t.TempDir()
	manifest := write(t, dir, "publishers.json", g(d, "manifest"))
	node := fakeNode(t, d, nil)
	defer node.Close()
	base := bundleFor(t, d, 1)
	env := g(base, "envelope")
	payload := g(env, "payload")
	anchorsID := "anchor.consistency[" + g(d, "anchorOrigin").S + "]"

	// An insider changes the decision and does not re-seal the digest. The
	// failure is reported once: the subject still names the stored digest,
	// and every check that takes the digest as input is blocked by it.
	tampered := with(base, "envelope", with(env, "payload", with(payload, "action", report.S("rejected"))))
	o := verify(t, "--publishers", manifest, "--evm-rpc", node.URL, write(t, dir, "t1.json", tampered))
	if o.exit != 1 {
		t.Errorf("unsealed tamper: exit %d", o.exit)
	}
	expect(t, o, "record.digest", "checked-wrong", "digest_mismatch")
	expect(t, o, "subject", "checked-correct", "")
	expect(t, o, "anchor", "not-checked", "blocked_by:record.digest")
	expect(t, o, "anchor.inclusion", "not-checked", "blocked_by:record.digest")
	expect(t, o, "anchor.newer", "not-checked", "blocked_by:record.digest")
	expect(t, o, anchorsID, "not-checked", "blocked_by:anchor")
	if n := g(o.report, "summary", "outcomes", "checked-wrong"); n.N != 1 {
		t.Errorf("one failure, reported once: %s", mustJSON(g(o.report, "summary")))
	}

	// Re-sealed: the digest matches its payload, and is not the anchored leaf.
	newPayload := with(payload, "action", report.S("rejected"))
	digest, err := canonical.RecordDigest(newPayload)
	if err != nil {
		t.Fatal(err)
	}
	resealedEnv := with(with(env, "payload", newPayload), "integrity", with(g(env, "integrity"), "canonicalDigest", report.S(digest)))
	resealed := with(with(base, "envelope", resealedEnv), "subject",
		report.Obj("evidenceId", g(payload, "evidenceId"), "canonicalDigest", report.S(digest)))
	o = verify(t, "--publishers", manifest, "--evm-rpc", node.URL, write(t, dir, "t2.json", resealed))
	if o.exit != 1 {
		t.Errorf("re-sealed tamper: exit %d", o.exit)
	}
	expect(t, o, "record.digest", "checked-correct", "")
	expect(t, o, "record.chainLink", "checked-wrong", "chain_link_mismatch")
	expect(t, o, "anchor.inclusion", "checked-wrong", "merkle_proof_invalid")
	expect(t, o, "anchor.anchorInclusion", "not-checked", "blocked_by:anchor.inclusion")

	// A forged future version tag abstains, and abstaining is not passing.
	anc := g(env, "nonRepudiation", "anchor")
	forged := with(base, "envelope", with(env, "nonRepudiation", report.Obj("anchor", with(anc, "anchorSpec", report.S("tzun-anchor/2")))))
	o = verify(t, "--publishers", manifest, "--evm-rpc", node.URL, write(t, dir, "t3.json", forged))
	if o.exit != 4 {
		t.Errorf("forged future tag: exit %d, want 4", o.exit)
	}
	expect(t, o, "anchor", "abstain", "unsupported_anchor_spec")

	// No trust inputs at all: exit 4.
	o = verify(t, write(t, dir, "t4.json", base))
	if o.exit != 4 {
		t.Errorf("no trust inputs: exit %d", o.exit)
	}

	// An unanchored record: anchor.pending, exit 4, 0 with --allow-unchecked.
	pendingEnv := with(env, "nonRepudiation", report.Obj())
	pending := with(with(with(base, "anchoring", report.Obj()), "envelope", pendingEnv), "anchorPending",
		report.Obj("origin", report.S("x"), "leafIndex", report.N(1), "since", report.S("2026-09-26T00:00:00Z")))
	pp := write(t, dir, "t5.json", pending)
	o = verify(t, pp)
	if o.exit != 4 {
		t.Errorf("unanchored: exit %d", o.exit)
	}
	expect(t, o, "anchor.pending", "not-checked", "not_yet_published")
	expect(t, o, "anchor", "not-checked", "absent")
	expect(t, o, "anchor.spec", "not-checked", "absent")
	if o := verify(t, "--allow-unchecked", pp); o.exit != 0 {
		t.Errorf("unanchored with --allow-unchecked: exit %d", o.exit)
	}
	// A null anchor is an empty slot: absent, as a missing one is.
	nullAnchor := with(pending, "envelope", with(env, "nonRepudiation", report.Obj("anchor", report.Null(), "blockchainAnchor", report.Null())))
	o = verify(t, write(t, dir, "t5b.json", nullAnchor))
	expect(t, o, "anchor", "not-checked", "absent")

	// The record's own timestamp is verified, over the record's digest.
	withTS := with(base, "envelope", with(env, "nonRepudiation", report.Obj("anchor", anc, "rfc3161Token", report.S("AA=="))))
	o = verify(t, "--publishers", manifest, "--evm-rpc", node.URL, write(t, dir, "t6.json", withTS))
	if o.exit != 1 {
		t.Errorf("an unreadable record timestamp: exit %d", o.exit)
	}
	expect(t, o, "ts.record.token", "checked-wrong", "malformed_token")
	expect(t, o, "ts.record.trust", "not-checked", "blocked_by:ts.record.token")

	// The join takes the bundle entry whose raw transaction hashes to the
	// envelope's transactionId, never another publication of the domain.
	epochs := g(d, "epochs").A
	anchorOrigin := g(d, "anchorOrigin").S
	anchoring := g(base, "anchoring")
	var decoyed []jsonv.Member
	for _, m := range anchoring.O {
		if m.Key != anchorOrigin {
			decoyed = append(decoyed, m)
			continue
		}
		var cps []*jsonv.Value
		for _, cp := range g(m.Value, "checkpoints").A {
			// Another transaction, claiming the same block.
			sameBlock := with(g(epochs[1], "publication"), "blockHash", g(g(cp, "publications").A[0], "blockHash"))
			pubs := report.Arr(sameBlock)
			pubs.A = append(pubs.A, g(cp, "publications").A...)
			cps = append(cps, with(cp, "publications", pubs))
		}
		decoyed = append(decoyed, jsonv.Member{Key: m.Key, Value: with(m.Value, "checkpoints", report.Arr(cps...))})
	}
	decoy := with(base, "anchoring", &jsonv.Value{Kind: jsonv.Object, O: decoyed})
	if o := verify(t, "--publishers", manifest, "--evm-rpc", node.URL, write(t, dir, "t8.json", decoy)); o.exit != 0 {
		t.Errorf("a second publication in the bundle: exit %d\n%s", o.exit, o.text)
	}

	// Unknown bundle version, the chain profile, a missing member, and bytes
	// that are not JSON.
	if o := verify(t, write(t, dir, "t7.json", with(base, "bundleVersion", report.S("b2")))); o.exit != 2 {
		t.Errorf("unknown bundle version: exit %d", o.exit)
	}
	o = verify(t, write(t, dir, "t9.json", with(base, "profile", report.S("chain"))))
	if o.exit != 2 {
		t.Errorf("chain profile: exit %d", o.exit)
	}
	expect(t, o, "bundle", "abstain", "unsupported_bundle_profile")
	o = verify(t, write(t, dir, "t10.json", without(base, "custody")))
	if o.exit != 2 {
		t.Errorf("no custody member: exit %d", o.exit)
	}
	expect(t, o, "bundle", "checked-wrong", "malformed_bundle")
	junk := filepath.Join(dir, "junk.json")
	_ = os.WriteFile(junk, []byte("{not json"), 0o600)
	if o := verify(t, junk); o.exit != 2 {
		t.Errorf("not JSON: exit %d", o.exit)
	}
}

// TestNothingPresentPassesSilently: on a bundle that exits 0 online, every
// artifact this build does not verify turns the exit code to 4, each on a
// check of its own (Verification §4.7, §6.6).
func TestNothingPresentPassesSilently(t *testing.T) {
	d := loadE2E(t)
	dir := t.TempDir()
	manifest := write(t, dir, "publishers.json", g(d, "manifest"))
	node := fakeNode(t, d, nil)
	defer node.Close()
	base := bundleFor(t, d, 0)
	env := g(base, "envelope")
	nr := g(env, "nonRepudiation")
	if o := verify(t, "--publishers", manifest, "--evm-rpc", node.URL, write(t, dir, "base.json", base)); o.exit != 0 {
		t.Fatalf("base: exit %d\n%s", o.exit, o.text)
	}
	clientData := base64.RawURLEncoding.EncodeToString([]byte(`{"type":"webauthn.get","challenge":"x","origin":"https://example.test"}`))
	// A batch statement with the members Record §9.4 reads.
	statement := report.Obj("mode", report.S("batch"), "root", report.S(strings.Repeat("cd", 32)), "treeSize", report.N(2))
	// custodyChain entries: the capture's own, which has no entryHash, and a
	// mirror entry, whose entryHash is 64 lowercase hex digits (Record §2.1).
	captureEntry := report.Obj("timestamp", report.S("2026-01-01T00:00:00.000Z"), "actor", report.S("acct:u-1"),
		"action", report.S("decision_captured"), "systemId", report.S("sys-1"))
	mirrorEntry := report.Obj("timestamp", report.S("2026-01-01T00:01:00.000Z"), "actor", report.S("ops@example.com"),
		"action", report.S("reviewed"), "systemId", report.S("sys-1"), "entryHash", report.S(strings.Repeat("ab", 32)),
		"prevEntryHash", report.Null())
	for _, c := range []struct {
		name     string
		bundle   *jsonv.Value
		id       string
		outcome  string
		reason   string
		wantExit int
	}{
		{"a witness cosignature", with(base, "extensions", report.Obj("witness/1", report.Obj("cosignatures", report.Arr(report.S("forged"))))),
			"extension[witness/1]", "abstain", "unsupported_extension", 4},
		{"an unknown extension", with(base, "extensions", report.Obj("witness/1", report.Null(), "x-other/1", report.Obj())),
			"extension[x-other/1]", "abstain", "unsupported_extension", 4},
		{"custody entries", with(base, "custody", report.Obj("entries", report.Arr(report.Obj("id", report.N(1))))),
			"custody.ledger", "abstain", "unsupported_artifact", 4},
		{"a custody slot without entries", with(base, "custody", report.Obj("entries", report.Null())),
			"custody.ledger", "abstain", "unsupported_artifact", 4},
		{"an empty custody slot", with(base, "custody", report.Obj("entries", report.Arr())),
			"custody.ledger", "not-checked", "not_applicable", 0},
		{"a null custody slot", with(base, "custody", report.Null()),
			"custody.ledger", "not-checked", "not_applicable", 0},
		// A mirror entry beside a slot that holds no row names a custody row
		// the bundle leaves out: a finding, which exits 1 (Verification §4.3).
		{"a mirror entry beside an empty custody slot", with(with(base, "custody", report.Obj("entries", report.Arr())),
			"envelope", with(env, "custodyChain", report.Arr(captureEntry, mirrorEntry))),
			"custody.ledger", "checked-wrong", "mirror_entry_unexpected", 1},
		{"a mirror entry beside a null custody slot", with(with(base, "custody", report.Null()),
			"envelope", with(env, "custodyChain", report.Arr(mirrorEntry))),
			"custody.ledger", "checked-wrong", "mirror_entry_unexpected", 1},
		// Beside a slot that holds a row, custody material abstains (rule 2).
		{"a mirror entry beside custody entries", with(with(base, "custody", report.Obj("entries", report.Arr(report.Obj("id", report.N(1))))),
			"envelope", with(env, "custodyChain", report.Arr(captureEntry, mirrorEntry))),
			"custody.ledger", "abstain", "unsupported_artifact", 4},
		// Any other custodyChain element is no mirror entry.
		{"the capture's entry beside an empty custody slot", with(with(base, "custody", report.Obj("entries", report.Arr())),
			"envelope", with(env, "custodyChain", report.Arr(captureEntry))),
			"custody.ledger", "not-checked", "not_applicable", 0},
		{"a custodyChain entry whose entryHash is null", with(with(base, "custody", report.Null()),
			"envelope", with(env, "custodyChain", report.Arr(with(mirrorEntry, "entryHash", report.Null())))),
			"custody.ledger", "not-checked", "not_applicable", 0},
		{"a custodyChain entry whose entryHash is \"x\"", with(with(base, "custody", report.Obj("entries", report.Arr())),
			"envelope", with(env, "custodyChain", report.Arr(with(mirrorEntry, "entryHash", report.S("x"))))),
			"custody.ledger", "not-checked", "not_applicable", 0},
		{"a custodyChain entry whose entryHash is a number", with(with(base, "custody", report.Obj("entries", report.Arr())),
			"envelope", with(env, "custodyChain", report.Arr(with(mirrorEntry, "entryHash", report.N(1))))),
			"custody.ledger", "not-checked", "not_applicable", 0},
		{"a custodyChain entry whose entryHash has an uppercase digit", with(with(base, "custody", report.Null()),
			"envelope", with(env, "custodyChain", report.Arr(with(mirrorEntry, "entryHash", report.S("AB"+strings.Repeat("ab", 31)))))),
			"custody.ledger", "not-checked", "not_applicable", 0},
		{"related records", with(base, "relatedRecords", report.Obj("x", report.Obj("role", report.S("credential-registration")))),
			"relatedRecords", "abstain", "unsupported_slot", 4},
		{"an empty relatedRecords slot is filled", with(base, "relatedRecords", report.Obj()),
			"relatedRecords", "abstain", "unsupported_slot", 4},
		{"credentials", with(base, "credentials", report.Obj("k", report.Obj("coseKey", report.S("x")))),
			"signoff.key", "abstain", "unsupported_signoff", 4},
		{"a policy", with(base, "policy", report.Obj("leaves", report.Arr())),
			"policy", "abstain", "unsupported_slot", 4},
		{"a top-level member a record bundle does not have", with(base, "records", report.Arr()),
			"member[records]", "abstain", "unsupported_member", 4},
		{"a WebAuthn assertion", with(base, "envelope", with(env, "nonRepudiation", with(nr, "webauthnAssertion", report.Obj("clientDataJSON", report.S(clientData))))),
			"signoff.key", "not-checked", "not_in_bundle:credential", 4},
		// An assertion whose clientDataJSON does not parse binds nothing;
		// under a null expectation nothing is owed (Verification §5), and
		// the key is not in the bundle.
		{"an unreadable WebAuthn assertion", with(base, "envelope", with(env, "nonRepudiation", with(nr, "webauthnAssertion", report.Obj()))),
			"signoff.key", "not-checked", "not_in_bundle:credential", 4},
		// A signoff block and an assertion that bind nothing were moved or
		// made up (Verification §5).
		{"a sign-off that binds nothing", with(base, "envelope", with(env, "nonRepudiation",
			with(with(nr, "signoff", report.Obj("statement", statement)), "webauthnAssertion", report.Obj("clientDataJSON", report.S(clientData))))),
			"signoff.expectation", "checked-wrong", "signoff_unbound", 1},
		{"a legacy anchor beside the anchor", with(base, "envelope", with(env, "nonRepudiation", with(nr, "blockchainAnchor", report.Obj()))),
			"nonRepudiation.blockchainAnchor", "abstain", "legacy_blockchain_anchor", 4},
		{"a nonRepudiation member this build does not know", with(base, "envelope", with(env, "nonRepudiation", with(nr, "x-other", report.Obj()))),
			"nonRepudiation.x-other", "abstain", "unsupported_artifact", 4},
		{"an assertion timestamp", with(base, "envelope", with(env, "nonRepudiation", with(nr, "assertionTimestamp", report.Obj()))),
			"ts.assertion.token", "abstain", "unsupported_artifact", 4},
	} {
		o := verify(t, "--publishers", manifest, "--evm-rpc", node.URL, write(t, dir, "c.json", c.bundle))
		if o.exit != c.wantExit {
			t.Errorf("%s: exit %d, want %d\n%s", c.name, o.exit, c.wantExit, o.text)
		}
		got, why := o.check(t, c.id)
		if got != c.outcome || why != c.reason {
			t.Errorf("%s: %s %s %q, want %s %q", c.name, c.id, got, why, c.outcome, c.reason)
		}
	}

	// A third checkpoint for one log is refused: a record bundle carries at
	// most two per level, and never one that nothing authenticates.
	anchoring := g(base, "anchoring")
	var three []jsonv.Member
	for _, m := range anchoring.O {
		cps := g(m.Value, "checkpoints")
		if len(cps.A) == 2 {
			extra := report.Arr(cps.A...)
			extra.A = append(extra.A, cps.A[0])
			m = jsonv.Member{Key: m.Key, Value: with(m.Value, "checkpoints", extra)}
		}
		three = append(three, m)
	}
	o := verify(t, "--publishers", manifest, "--evm-rpc", node.URL, write(t, dir, "three.json", with(base, "anchoring", &jsonv.Value{Kind: jsonv.Object, O: three})))
	if o.exit != 2 {
		t.Errorf("three checkpoints: exit %d", o.exit)
	}
	expect(t, o, "bundle", "checked-wrong", "malformed_bundle")
}

// TestNullReadsAbsent: inside a slot, a member whose value is null reads as
// absent (Bundle §3.2) in the anchoring material too.
func TestNullReadsAbsent(t *testing.T) {
	d := loadE2E(t)
	dir := t.TempDir()
	manifest := write(t, dir, "publishers.json", g(d, "manifest"))
	node := fakeNode(t, d, nil)
	defer node.Close()
	base := bundleFor(t, d, 0)
	env := g(base, "envelope")
	nr := g(env, "nonRepudiation")
	anc := g(nr, "anchor")
	logOrigin := strings.SplitN(g(anc, "logCheckpoint").S, "\n", 2)[0]
	logs := g(base, "anchoring", logOrigin)
	if len(g(logs, "checkpoints").A) != 2 || len(g(logs, "consistency").A) != 1 {
		t.Fatal("the base bundle does not carry a newer evidence-log checkpoint")
	}
	withLog := func(b, l *jsonv.Value) *jsonv.Value {
		return with(b, "anchoring", with(g(b, "anchoring"), logOrigin, l))
	}

	// Null newer members on the record's own checkpoint, and no newer
	// checkpoint: nothing names a target, so there is no anchor.newer row.
	own := g(logs, "checkpoints").A[0]
	nulls := with(with(with(with(own, "logPath", report.Null()), "anchorLeafIndex", report.Null()), "anchorSize", report.Null()), "anchorPath", report.Null())
	noNewer := withLog(base, with(with(logs, "checkpoints", report.Arr(nulls)), "consistency", report.Arr()))
	o := verify(t, "--publishers", manifest, "--evm-rpc", node.URL, write(t, dir, "n1.json", noNewer))
	if id, _ := o.check(t, "anchor.newer"); id != "" {
		t.Errorf("null newer members: an anchor.newer row, %s", id)
	}

	// A null rawTransaction in the envelope's entry gains the bundle's.
	pubs := g(anc, "publications")
	nullRaw := with(pubs.A[0], "rawTransaction", report.Null())
	joined := with(base, "envelope", with(env, "nonRepudiation", with(nr, "anchor", with(anc, "publications", report.Arr(nullRaw)))))
	o = verify(t, "--publishers", manifest, write(t, dir, "n2.json", joined))
	expect(t, o, "anchor.evm.tx[0]", "checked-correct", "")

	// The consistency entry between the two sizes, with its path missing or
	// null, is the proof used, and it is not an array of hashes.
	entry := g(logs, "consistency").A[0]
	for name, e := range map[string]*jsonv.Value{"missing": without(entry, "path"), "null": with(entry, "path", report.Null())} {
		b := withLog(base, with(logs, "consistency", report.Arr(e)))
		o = verify(t, "--publishers", manifest, "--evm-rpc", node.URL, write(t, dir, "n3.json", b))
		expect(t, o, "anchor.consistency["+logOrigin+"]", "checked-wrong", "log_inconsistent_with_anchor")
		if o.exit != 1 {
			t.Errorf("a consistency path %s: exit %d", name, o.exit)
		}
	}
}

// TestUnwritableReport: a report with no canonical form, here because the
// bundle's subject holds a lone surrogate, exits 2 in either output format
// (Verification §6.5).
func TestUnwritableReport(t *testing.T) {
	d := loadE2E(t)
	dir := t.TempDir()
	b, err := canonical.Serialize(bundleFor(t, d, 0))
	if err != nil {
		t.Fatal(err)
	}
	const subject = `"subject":{`
	i := bytes.Index(b, []byte(subject))
	if i < 0 {
		t.Fatal("no subject in the bundle")
	}
	lone := append(append(append([]byte{}, b[:i+len(subject)]...), []byte(`"x":"\ud800",`)...), b[i+len(subject):]...)
	p := filepath.Join(dir, "lone.json")
	if err := os.WriteFile(p, lone, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--json", p}, {p}} {
		var out, errb bytes.Buffer
		if code := Run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2\n%q", args, code, out.String())
		}
	}
}

// TestSignoffExpectationHashed: signoffExpectation is in the v1.0 hashed
// set, and an absent key is hashed as null (Record §4.1, §4.2).
func TestSignoffExpectationHashed(t *testing.T) {
	d := loadE2E(t)
	dir := t.TempDir()
	base := bundleFor(t, d, 0)
	env := g(base, "envelope")
	payload := without(g(env, "payload"), "signoffExpectation")

	// A digest over another set of names, here the hashed set less
	// signoffExpectation, does not recompute under v1.0: a digest mismatch,
	// never another form of record (Record §4.2).
	others := []string{"action", "aiOutput", "aiSystemId", "capturedAt", "contributions", "decider", "evidenceId", "links", "reason", "sequenceNumber"}
	other, err := canonical.DigestOver(payload, others)
	if err != nil {
		t.Fatal(err)
	}
	otherEnv := with(with(env, "payload", payload), "integrity", with(g(env, "integrity"), "canonicalDigest", report.S(other)))
	otherBundle := with(with(base, "envelope", otherEnv), "subject", report.Obj("evidenceId", g(payload, "evidenceId"), "canonicalDigest", report.S(other)))
	o := verify(t, write(t, dir, "other.json", otherBundle))
	if o.exit != 1 {
		t.Errorf("a digest over another set of names: exit %d, want 1", o.exit)
	}
	expect(t, o, "record.digest", "checked-wrong", "digest_mismatch")
	expect(t, o, "anchor", "not-checked", "blocked_by:record.digest")
	if _, ok := row(t, o, "record.digest").Get("facts"); ok {
		t.Error("a digest over a set no earlier draft names carries a fieldSet fact")
	}

	// A record rewritten into an earlier field set, its digest recomputed:
	// still a mismatch, and the fact names the set (Verification §4.3).
	for _, fs := range []struct {
		name   string
		fields []string
	}{{"0.7", canonical.FieldSet07}, {"before-0.7", canonical.FieldSetBefore07}} {
		old := with(with(payload, "humanAction", g(payload, "action")), "humanReason", g(payload, "reason"))
		digest, err := canonical.DigestOver(old, fs.fields)
		if err != nil {
			t.Fatal(err)
		}
		oldEnv := with(with(env, "payload", old), "integrity", with(g(env, "integrity"), "canonicalDigest", report.S(digest)))
		oldBundle := with(with(base, "envelope", oldEnv), "subject", report.Obj("evidenceId", g(payload, "evidenceId"), "canonicalDigest", report.S(digest)))
		o := verify(t, write(t, dir, "fieldset-"+fs.name+".json", oldBundle))
		expect(t, o, "record.digest", "checked-wrong", "digest_mismatch")
		if got := g(row(t, o, "record.digest"), "facts", "fieldSet"); got.S != fs.name {
			t.Errorf("a record of the field set %s: fieldSet %q", fs.name, got.S)
		}
		if o.exit != 1 {
			t.Errorf("a record of the field set %s: exit %d, want 1", fs.name, o.exit)
		}
	}

	// A null key removed from a current record: an absent key hashes as
	// null, so the digest still holds.
	if g(env, "payload", "signoffExpectation").Kind != jsonv.Null {
		t.Fatal("the base record's expectation is not null")
	}
	stripped := with(base, "envelope", with(env, "payload", payload))
	o = verify(t, write(t, dir, "stripped.json", stripped))
	expect(t, o, "record.digest", "checked-correct", "")

	// The key present and changed: a tamper like any other.
	changed := with(base, "envelope", with(env, "payload", with(g(env, "payload"), "signoffExpectation",
		report.Obj("policyDigest", report.S(strings.Repeat("0", 64))))))
	o = verify(t, write(t, dir, "changed.json", changed))
	expect(t, o, "record.digest", "checked-wrong", "digest_mismatch")
}

// TestRecordTimestamp: the record's own RFC 3161 token is verified over the
// record's digest (the steps of Anchor §10.5), and a proven genTime
// earlier than the anchor's block is the existedBy bound.
func TestRecordTimestamp(t *testing.T) {
	d := loadE2E(t)
	dir := t.TempDir()
	manifest := write(t, dir, "publishers.json", g(d, "manifest"))
	node := fakeNode(t, d, nil)
	defer node.Close()
	base := bundleFor(t, d, 0)
	env := g(base, "envelope")
	nr := g(env, "nonRepudiation")
	digest, _ := hex.DecodeString(g(env, "integrity", "canonicalDigest").S)

	root := testpki.Root("Record TSA Root")
	inter := testpki.Intermediate("Record TSA CA", root, true)
	signer := testpki.TSASigner("Record TSA", inter)
	// Before the anchor's block, so the record's timestamp is the earliest
	// proven bound.
	blockTime, _ := g(g(d, "epochs").A[0], "canonicalBlock", "timestamp").Uint53()
	gen := time.Unix(int64(blockTime)-3600, 0).UTC()
	stamped := func(dgst []byte) *jsonv.Value {
		tok := testpki.Token(dgst, signer, []*x509.Certificate{inter.Cert}, gen, true)
		return with(base, "envelope", with(env, "nonRepudiation", with(nr, "rfc3161Token", report.S(tok))))
	}
	roots := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	good := write(t, dir, "ts.json", stamped(digest))

	o := verify(t, "--publishers", manifest, "--evm-rpc", node.URL, "--tsa-roots", roots, good)
	if o.exit != 0 {
		t.Errorf("trusted record timestamp: exit %d\n%s", o.exit, o.text)
	}
	expect(t, o, "ts.record.token", "checked-correct", "")
	expect(t, o, "ts.record.trust", "checked-correct", "")
	sum := g(o.report, "summary", "existedBy")
	if g(sum, "source").S != "record-timestamp" || g(sum, "check").S != "ts.record.trust" || g(sum, "at").S != gen.Format("2006-01-02T15:04:05.000Z") {
		t.Errorf("existedBy: %s", mustJSON(sum))
	}
	if fp := g(o.report, "inputs", "trustAnchors").A; len(fp) != 1 || fp[0].S != canonical.Digest(root.Cert.Raw) {
		t.Errorf("trustAnchors: %s", mustJSON(g(o.report, "inputs")))
	}

	// No root supplied: the token holds, its trust is not checked.
	o = verify(t, "--publishers", manifest, "--evm-rpc", node.URL, good)
	if o.exit != 4 {
		t.Errorf("untrusted record timestamp: exit %d", o.exit)
	}
	expect(t, o, "ts.record.trust", "not-checked", "no_matching_trust_anchor")

	// A token over another digest.
	other := make([]byte, 32)
	o = verify(t, "--publishers", manifest, "--evm-rpc", node.URL, "--tsa-roots", roots, write(t, dir, "ts2.json", stamped(other)))
	if o.exit != 1 {
		t.Errorf("a token over another digest: exit %d", o.exit)
	}
	expect(t, o, "ts.record.token", "checked-wrong", "imprint_mismatch")
	expect(t, o, "ts.record.trust", "not-checked", "blocked_by:ts.record.token")
}

func TestFlags(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"--version"}, &out, &errb); code != 0 || !strings.Contains(out.String(), publishers.SHA256()) {
		t.Errorf("--version: %d %q", code, out.String())
	}
	dir := t.TempDir()
	notJSON := filepath.Join(dir, "p.json")
	_ = os.WriteFile(notJSON, []byte("{publishers"), 0o600)
	badHeaders := filepath.Join(dir, "h.json")
	_ = os.WriteFile(badHeaders, []byte(`{"chainId":1,"finality":"finalized","finalizedBlockNumber":1,"blocks":[],"extra":1}`), 0o600)
	shallow := filepath.Join(dir, "s.json")
	_ = os.WriteFile(shallow, []byte(`{"chainId":1,"finality":{"confirmations":2},"finalizedBlockNumber":1,"blocks":[]}`), 0o600)
	for _, args := range [][]string{
		{}, {"--bogus", "x.json"}, {"--confirmations", "10", "--evm-rpc", "https://example.invalid", "x.json"},
		{"--evm-rpc", "ftp://x", "x.json"}, {"--timeout", "0", "x.json"}, {"a.json", "b.json"},
		// An input the auditor named and the command cannot read is refused,
		// never passed on as absent.
		{"--publishers", notJSON, "x.json"}, {"--publishers", filepath.Join(dir, "missing.json"), "x.json"},
		{"--publishers", notJSON, "--no-publishers", "x.json"},
		{"--evm-header-file", badHeaders, "x.json"}, {"--evm-header-file", shallow, "x.json"},
		{"--evm-header-file", "eip155:0=" + badHeaders, "x.json"},
		{"--evm-rpc", "https://a.invalid", "--evm-header-file", badHeaders, "x.json"},
		// A switch given a value is refused whatever the value says: none
		// of these may switch a check on or off by spelling.
		{"--allow-unchecked=false", "x.json"}, {"--allow-unchecked=true", "x.json"}, {"--allow-unchecked=", "x.json"},
		{"--confirmations", "10", "--accept-non-final=false", "--evm-rpc", "https://example.invalid", "x.json"},
		{"--no-publishers=0", "x.json"}, {"--no-tx-lookup=no", "x.json"}, {"--json=false", "x.json"},
		{"--version=1"}, {"--help=yes"},
		// The scoped allowance needs its reasons.
		{"x.json", "--allow-unchecked-reason"},
	} {
		out.Reset()
		errb.Reset()
		if code := Run(args, &out, &errb); code != report.ExitUsageError {
			t.Errorf("%v: exit %d, want %d", args, code, report.ExitUsageError)
		}
	}
	for _, h := range []string{"--help", "-h"} {
		out.Reset()
		if code := Run([]string{h}, &out, &errb); code != 0 || !strings.Contains(out.String(), "usage:") {
			t.Errorf("%s: %d", h, code)
		}
	}
	if code := Run([]string{"missing.json"}, &out, &errb); code != report.ExitBundle {
		t.Errorf("missing file: %d", code)
	}
}

// TestAllowUncheckedReason: the scoped allowance takes a comma-separated
// list of reasons, repeatable, and leaves the switch --allow-unchecked off.
func TestAllowUncheckedReason(t *testing.T) {
	c, err := parseArgs([]string{"--allow-unchecked-reason=unsupported_link_edge, confirmation_missing", "x.json",
		"--allow-unchecked-reason", "unsupported_member,"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.policy.AllowReasons, " "); got != "unsupported_link_edge confirmation_missing unsupported_member" || c.policy.AllowUnchecked {
		t.Errorf("reasons %q, allowUnchecked %v", got, c.policy.AllowUnchecked)
	}
}

// TestUnreadableTrustInput: a root or intermediate the auditor supplies
// whose key this build does not implement is an input it cannot read, and
// is refused with 64, never dropped (Verification §3.1, §6.6).
func TestUnreadableTrustInput(t *testing.T) {
	d := loadE2E(t)
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("..", "rfc3161", "testdata", "openssl-tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tokens struct {
		Roots        map[string]string `json:"roots"`
		Certificates map[string]string `json:"certificates"`
	}
	if err := json.Unmarshal(raw, &tokens); err != nil {
		t.Fatal(err)
	}
	bundle := write(t, dir, "b.json", bundleFor(t, d, 0))
	good := filepath.Join(dir, "good.pem")
	if err := os.WriteFile(good, []byte(tokens.Roots["p256"]), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"--json", "--tsa-roots", good, bundle}, &bytes.Buffer{}, &bytes.Buffer{}); code == 64 {
		t.Fatalf("a P-256 root refused")
	}
	for name, text := range map[string]string{
		"a root on brainpoolP256r1":             tokens.Roots["brainpoolP256r1"],
		"a root on an unassigned curve":         tokens.Roots["unknownCurve"],
		"a DSA certificate":                     tokens.Certificates["dsaSigner"],
		"a certificate of an unknown algorithm": tokens.Certificates["unknownAlgorithmSigner"],
	} {
		p := filepath.Join(dir, "in.pem")
		if err := os.WriteFile(p, []byte(tokens.Roots["p256"]+text), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, flag := range []string{"--tsa-roots", "--tsa-intermediates"} {
			var out, errb bytes.Buffer
			if code := Run([]string{"--json", flag, p, bundle}, &out, &errb); code != 64 || out.Len() != 0 {
				t.Errorf("%s as %s: exit %d, %d bytes of report", name, flag, code, out.Len())
			}
		}
	}
}

// TestLoneSurrogateNames: a lone surrogate in a member name a row id would
// carry (a top-level member, an extension, a nonRepudiation member, an
// anchoring key) makes the bundle unreadable, so that every report can be
// written (Bundle §4 step 9, Verification §4.1). A valid surrogate pair is
// a name like any other.
func TestLoneSurrogateNames(t *testing.T) {
	d := loadE2E(t)
	dir := t.TempDir()
	base := bundleFor(t, d, 0)
	env := g(base, "envelope")
	nr := g(env, "nonRepudiation")
	const name = "LONE_SURROGATE_NAME"
	for _, c := range []struct {
		where    string
		bundle   *jsonv.Value
		escape   string
		exit     int
		id, want string
	}{
		{"a top-level member", with(base, name, report.Obj()), `\ud800`, 2, "bundle", "checked-wrong"},
		{"a top-level member, mixed", with(base, name, report.Obj()), `x\udc00y`, 2, "bundle", "checked-wrong"},
		{"an extension", with(base, "extensions", report.Obj(name, report.Obj("a", report.N(1)))), `\ud800`, 2, "bundle", "checked-wrong"},
		{"a null extension", with(base, "extensions", report.Obj(name, report.Null())), `\ud800`, 2, "bundle", "checked-wrong"},
		{"a nonRepudiation member", with(base, "envelope", with(env, "nonRepudiation", with(nr, name, report.Obj()))), `\ud800`, 2, "bundle", "checked-wrong"},
		{"an anchoring key", with(base, "anchoring", with(g(base, "anchoring"), name, report.Obj("checkpoints", report.Arr()))), `\ud800`, 2, "bundle", "checked-wrong"},
		{"a top-level member, a valid pair", with(base, name, report.Obj()), `😀`, 4, "member[\U0001F600]", "abstain"},
		{"a nonRepudiation member, a valid pair", with(base, "envelope", with(env, "nonRepudiation", with(nr, name, report.Obj()))), `😀`, 4, "nonRepudiation.\U0001F600", "abstain"},
	} {
		b, err := canonical.Serialize(c.bundle)
		if err != nil {
			t.Fatal(err)
		}
		b = bytes.Replace(b, []byte(`"`+name+`"`), []byte(`"`+c.escape+`"`), 1)
		p := filepath.Join(dir, "lone.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		o := verify(t, p)
		if o.exit != c.exit {
			t.Errorf("%s: exit %d, want %d\n%s", c.where, o.exit, c.exit, o.text)
		}
		if got, _ := o.check(t, c.id); got != c.want {
			t.Errorf("%s: %s %s, want %s", c.where, c.id, got, c.want)
		}
		if c.exit == 2 {
			if n := len(g(o.report, "checks").A); n != 1 {
				t.Errorf("%s: %d rows, want the bundle row alone", c.where, n)
			}
			expect(t, o, "bundle", "checked-wrong", "malformed_bundle")
		}
	}
}
