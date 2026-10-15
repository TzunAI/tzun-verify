// SPDX-License-Identifier: BSD-3-Clause-Clear

package corpus

import (
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/TzunAI/tzun-verify/internal/agent"
	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/evm"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/mandate"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// TestMandateVectors: the mandate document and its digest (Record §9.7),
// the statement and its challenge, the assertion digest (§9.6), predicates
// (§9.8), the scope and limits of one record (§9.9), and the row
// mandate.issuance (Verification §4.12). Consumption across the records of
// a mandate is informative for a verifier of one record (Record §9.10), and
// the event bodies, claims and lifecycle cases are a writer's account of
// its own mandates; they are left out.
func TestMandateVectors(t *testing.T) {
	d := load(t, "mandate-vectors.json")
	for _, c := range get(t, d, "documents").A {
		name := str(t, c, "case")
		prepare := true
		if p, ok := c.Get("prepare"); ok && p.Kind == jsonv.Bool {
			prepare = p.B
		}
		doc, ok := mandate.ParseDocument(get(t, c, "document"), prepare)
		if ok != isNull(c, "violation") {
			t.Errorf("document %q: well formed %v", name, ok)
			continue
		}
		if dg, has := optStr(c, "digest"); has && (doc.Digest != dg || uint64(len(canonicalString(t, get(t, c, "document")))) != u64(t, c, "byteLength")) {
			t.Errorf("document %q: digest %s", name, doc.Digest)
		}
	}
	for _, c := range get(t, d, "statements").A {
		name := str(t, c, "case")
		st, ok := mandate.ParseStatement(get(t, c, "statement"))
		if ok != get(t, c, "wellFormed").B {
			t.Errorf("statement %q: well formed %v", name, ok)
			continue
		}
		if ok && (st.Digest != str(t, c, "digest") || mandate.Challenge(mandate.StatementDomain, st.Digest) != str(t, c, "challenge")) {
			t.Errorf("statement %q: digest %s", name, st.Digest)
		}
	}
	for _, c := range get(t, d, "assertionDigests").A {
		name := str(t, c, "case")
		g, ok := mandate.AssertionDigest(get(t, c, "assertion"))
		want, has := optStr(c, "digest")
		if ok != has || g != want {
			t.Errorf("assertion %q: %q %v", name, g, ok)
		}
	}
	for _, c := range get(t, d, "predicates").A {
		name := str(t, c, "case")
		p, ok := mandate.ParsePredicate(get(t, c, "predicate"), true)
		if ok != get(t, c, "wellFormed").B {
			t.Errorf("predicate %q: well formed %v", name, ok)
			continue
		}
		if !ok {
			continue
		}
		payload, has := c.Get("payload")
		if pj, ok := optStr(c, "payloadJson"); ok {
			payload, has = jsonOf(t, pj), true
		}
		if !has {
			t.Fatalf("predicate %q: no payload", name)
		}
		if g := p.Evaluate(payload).String(); g != str(t, c, "outcome") {
			t.Errorf("predicate %q: %s, want %s", name, g, str(t, c, "outcome"))
		}
	}
	for _, c := range get(t, d, "scope").A {
		name := str(t, c, "case")
		doc, ok := mandate.ParseDocument(get(t, c, "document"), false)
		if !ok {
			t.Fatalf("scope %q: document", name)
		}
		payload := get(t, c, "payload")
		confirm := get(t, payload, "signoffExpectation", "confirm").B
		r := mandate.Scope(doc, payload, confirm)
		want := get(t, c, "expect")
		verdict := "within"
		switch {
		case !r.AgentIn || len(r.Failed) > 0:
			verdict = "outside"
		case len(r.Undeterminable) > 0:
			verdict = "undeterminable"
		}
		failures := r.Failed
		if !r.AgentIn {
			failures = append([]string{"agents"}, failures...)
		}
		if verdict != str(t, want, "verdict") || r.AgentIn != get(t, want, "agentInMandate").B ||
			(len(r.Evaded) > 0) != get(t, want, "confirmationEvaded").B ||
			strings.Join(failures, ",") != constraints(t, get(t, want, "failures")) ||
			strings.Join(r.Undeterminable, ",") != constraints(t, get(t, want, "undeterminable")) {
			t.Errorf("scope %q: %s %+v", name, verdict, r)
		}
	}
	for _, c := range get(t, d, "limits").A {
		name := str(t, c, "case")
		doc, ok := mandate.ParseDocument(get(t, c, "document"), false)
		if !ok {
			t.Fatalf("limits %q: document", name)
		}
		payload := get(t, c, "payload")
		row := report.CheckJSON(mandate.LimitsRow(doc, payload, get(t, payload, "signoffExpectation")))
		want := get(t, c, "expect")
		outcome, reason := "checked-correct", ""
		if !get(t, want, "valid").B {
			outcome, reason = "checked-wrong", str(t, want, "reason")
		}
		expectRow(t, "limits "+name, "mandate.limits", row, outcome, reason, pick(want, "slot", "totals"))
	}
	for _, c := range get(t, d, "issuance").A {
		name := str(t, c, "case")
		env := get(t, c, "envelope")
		nr, _ := env.Get("nonRepudiation")
		block, _ := nr.Get("mandateIssuance")
		row, reported := mandate.IssuanceRow(get(t, env, "payload"), mandate.ReadBlock(block))
		want := get(t, c, "expect")
		if want.Kind == jsonv.Null {
			if reported {
				t.Errorf("issuance %q: reported", name)
			}
			continue
		}
		reason, _ := optStr(want, "reason")
		expectRow(t, "issuance "+name, "mandate.issuance", report.CheckJSON(row), str(t, want, "outcome"), reason, pick(want, "link"))
	}
}

// constraints writes a list of the vectors' constraints as names:
// predicate:<name> and confirm:<name> for a named one.
func constraints(t *testing.T, list *jsonv.Value) string {
	t.Helper()
	var out []string
	for _, c := range list.A {
		n := str(t, c, "constraint")
		if name, ok := optStr(c, "name"); ok {
			n += ":" + name
		}
		out = append(out, n)
	}
	return strings.Join(out, ",")
}

// TestAgentDescriptorVectors: the descriptor of Record §6.9, its digest
// over the sets sorted by UTF-8 bytes, its grammar, the limits a writer
// applies, and a policy engine's descriptor naming no model (Record §6.4).
func TestAgentDescriptorVectors(t *testing.T) {
	d := load(t, "agent-descriptor-vectors.json")
	for _, c := range get(t, d, "digests").A {
		name := str(t, c, "case")
		desc := get(t, c, "descriptor")
		b, err := agent.Canonical(desc)
		dg, _ := agent.Digest(desc)
		if err != nil || string(b) != str(t, c, "canonical") || uint64(len(b)) != u64(t, c, "byteLength") || dg != str(t, c, "digest") || !agent.Valid(desc) {
			t.Errorf("digest %q: %s", name, dg)
		}
	}
	for _, c := range get(t, d, "violations").A {
		name := str(t, c, "case")
		desc := substitute(get(t, c, "descriptor"))
		if g := agent.Valid(desc); g != get(t, c, "grammar").B {
			t.Errorf("violation %q: grammar %v", name, g)
		}
		if g := agent.WriterAccepts(desc); g != get(t, c, "writer").B {
			t.Errorf("violation %q: writer %v", name, g)
		}
	}
	for _, c := range get(t, d, "kinds").A {
		name := str(t, c, "case")
		mismatch := str(t, c, "kind") == "policy-engine" && agent.PolicyEngineNamesModel(get(t, c, "descriptor"))
		if mismatch != get(t, c, "mismatch").B {
			t.Errorf("kind %q: mismatch %v", name, mismatch)
		}
	}
}

// TestStoreGenerationVectors: the field set a stored record's digest
// recomputes under (Record §4.1), as record.digest reports it with the fact
// fieldSet (Verification §4.3). What a store does with the generation of its
// first record is a writer's, and is left out.
func TestStoreGenerationVectors(t *testing.T) {
	d := load(t, "store-generation-vectors.json")
	sets := map[string][]string{"0.8": canonical.HashedFieldsV1, "0.7": canonical.FieldSet07, "before-0.7": canonical.FieldSetBefore07}
	for name, fields := range sets {
		var want []string
		for _, f := range get(t, d, "fieldSets", name).A {
			want = append(want, f.S)
		}
		if strings.Join(want, " ") != strings.Join(fields, " ") {
			t.Errorf("field set %s: %v", name, want)
		}
	}
	for _, c := range get(t, d, "records").A {
		name := str(t, c, "case")
		rows, _ := bundleRows(t, get(t, c, "envelope"))
		row := rows["record.digest"]
		verified := rowLine(t, row) == "checked-correct"
		fieldSet, _ := optStr(factsOf(row), "fieldSet")
		generation := fieldSet
		if verified {
			generation = "0.8"
		}
		want := get(t, c, "expect")
		wantSet, _ := optStr(want, "fieldSet")
		wantGen, _ := optStr(want, "generation")
		if verified != get(t, want, "verified").B || fieldSet != wantSet || generation != wantGen ||
			(fieldSet == "before-0.7") != get(t, want, "predatesSignoffExpectation").B {
			t.Errorf("record %q: %s", name, rowLine(t, row))
		}
	}
}

// TestCrossSDKParityVectors: values whose spelling a JSON reader can change
// (Record §1.2, §3.1), each read with this build's own reader: the hashed
// object's canonical bytes and digest, the payload members outside the
// twelve (Verification §4.7), and the rows decider, contributions, links and
// signoff.expectation of the record in a bundle. A writer's refusals are a
// writer's.
func TestCrossSDKParityVectors(t *testing.T) {
	d := load(t, "cross-sdk-parity-vectors.json")
	for _, c := range get(t, d, "cases").A {
		name := str(t, c, "case")
		payload := jsonOf(t, str(t, c, "json"))
		h := hashedObject(t, payload)
		if h != str(t, c, "canonical") || canonical.Digest([]byte(h)) != str(t, c, "digest") || !strings.Contains(h, str(t, c, "contains")) {
			t.Errorf("%s: canonical bytes or digest", name)
			continue
		}
		env := report.Obj("envelopeVersion", report.S("e1"), "payload", payload,
			"integrity", report.Obj("canonicalDigest", report.S(str(t, c, "digest")), "chainLink", report.Null()),
			"nonRepudiation", report.Obj())
		rows, list := bundleRows(t, env)
		var unhashed []string
		for _, r := range list {
			if id := str(t, r, "id"); strings.HasPrefix(id, "payload.") {
				if rowLine(t, r) != "abstain unsupported_member" {
					t.Errorf("%s: %s %s", name, id, rowLine(t, r))
				}
				unhashed = append(unhashed, strings.TrimPrefix(id, "payload."))
			}
		}
		var want []string
		for _, u := range get(t, c, "unhashedPayloadMembers").A {
			want = append(want, u.S)
		}
		if strings.Join(unhashed, ",") != strings.Join(want, ",") {
			t.Errorf("%s: payload rows %v, want %v", name, unhashed, want)
		}
		r := get(t, c, "rows")
		for _, id := range []string{"decider", "contributions", "links"} {
			w := get(t, r, id)
			reason, _ := optStr(w, "reason")
			expectRow(t, name, id, rows[id], str(t, w, "outcome"), reason, nil)
		}
		gv, gr := expectationAnswer(rowLine(t, rows["signoff.expectation"]))
		wv, wr := wantAnswer(t, decodeDoc(t, []byte(canonicalOf(t, get(t, r, "signoffExpectation")))))
		if gv != wv || gr != wr {
			t.Errorf("%s: signoff.expectation %s, want %s %s", name, rowLine(t, rows["signoff.expectation"]), wv, wr)
		}
	}
}

// TestEVMAnchorVectors: the publisher manifest's validity window of
// Anchor §9, at, just inside and just outside a publication's block time,
// read to the full precision of its fraction, with the publication checked
// with its header, without it, and offline (Anchor §10.4).
func TestEVMAnchorVectors(t *testing.T) {
	d := load(t, "evm-anchor-vectors.json")
	pub := get(t, d, "publication")
	hs := get(t, d, "headerSource")
	source := func() *evm.StaticSource {
		src := &evm.StaticSource{Chain: new(big.Int).SetUint64(u64(t, hs, "chainId")), Finalized: u64(t, hs, "finalizedBlockNumber"),
			Blocks: map[uint64]evm.Block{}, Txs: map[common.Hash]evm.TxLookup{}}
		if str(t, hs, "finality") == "finalized" {
			src.Mode = evm.Finality{Declared: true, Finalized: true}
		}
		for _, b := range get(t, hs, "blocks").A {
			src.Blocks[u64(t, b, "number")] = evm.Block{Hash: common.HexToHash(str(t, b, "hash")), Time: u64(t, b, "timestamp")}
		}
		for _, x := range get(t, hs, "transactions").A {
			h, n, from := common.HexToHash(str(t, x, "blockHash")), u64(t, x, "blockNumber"), common.HexToAddress(str(t, x, "from"))
			src.Txs[common.HexToHash(str(t, x, "transactionId"))] = evm.TxLookup{BlockHash: &h, BlockNumber: &n, Sender: &from}
		}
		return src
	}
	noHeader := &jsonv.Value{Kind: jsonv.Object}
	for _, m := range pub.O {
		switch m.Key {
		case "blockHeader", "txIndex", "txProof":
		default:
			noHeader.O = append(noHeader.O, m)
		}
	}
	divergent := 0
	defer func() {
		t.Logf("%d cases where anchor.evm.canonical follows Anchor §10.4 item 13 rather than the vectors", divergent)
	}()
	for _, c := range get(t, d, "validityBounds").A {
		name := str(t, c, "name")
		entry := &jsonv.Value{Kind: jsonv.Object, O: append([]jsonv.Member{}, get(t, d, "manifestEntry").O...)}
		for _, b := range get(t, c, "bounds").O {
			entry.O = append(entry.O, b)
		}
		manifest := report.Obj("publishers", report.Obj(str(t, d, "anchorOrigin"), report.Arr(entry)))
		for _, mode := range []string{"header", "noHeader", "offline"} {
			in := evm.Input{Entry: pub, P: hexb(t, str(t, d, "p")), AnchorOrigin: str(t, d, "anchorOrigin"),
				Manifest: manifest, Deadline: time.Now().Add(time.Minute)}
			switch mode {
			case "header":
				in.Sources = evm.Sources{ByChain: map[string]evm.HeaderSource{str(t, d, "chain"): source()}}
			case "noHeader":
				in.Entry = noHeader
				in.Sources = evm.Sources{ByChain: map[string]evm.HeaderSource{str(t, d, "chain"): source()}}
			}
			r := evm.Verify(in)
			want := get(t, c, "expect", mode)
			valid := report.Null()
			if r.Valid != nil {
				valid = report.B(*r.Valid)
			}
			reason, _ := optStr(want, "reason")
			gotReason := r.Reason
			if r.Valid != nil && *r.Valid {
				gotReason = ""
			}
			if canonicalOf(t, valid) != canonicalOf(t, get(t, want, "valid")) || gotReason != reason {
				t.Errorf("%s, %s: valid %s %q", name, mode, canonicalOf(t, valid), r.Reason)
			}
			for _, x := range []struct {
				key string
				row report.Check
			}{{"tx", r.Tx}, {"canonical", r.Canonical}} {
				w := get(t, want, x.key)
				outcome := str(t, w, "outcome")
				rr, _ := optStr(w, "reason")
				// The vectors name the publication's own tx row without
				// its index.
				if rr == "blocked_by:anchor.evm.tx" {
					rr = "blocked_by:" + r.Tx.ID
				}
				// Item 13 of Anchor §10.4: a window that excludes the
				// sender at the time the source confirms fails
				// anchor.evm.tx, and anchor.evm.canonical, having decided
				// what it checks, stays checked-correct. The vectors block
				// it instead; the text governs (Specs §7).
				if x.key == "canonical" && mode == "noHeader" && rr == "blocked_by:"+r.Tx.ID &&
					str(t, get(t, want, "tx"), "reason") == evm.ReasonSenderMismatch {
					outcome, rr = "checked-correct", ""
					divergent++
				}
				expectRow(t, name+", "+mode, x.row.ID, report.CheckJSON(x.row), outcome, rr, nil)
			}
			if inc, ok := optStr(want, "inclusion"); ok && r.Inclusion != inc {
				t.Errorf("%s, %s: inclusion %q", name, mode, r.Inclusion)
			}
		}
	}
}

// TestEVMTransactionVectors: the transaction cases of
// evm-anchor-vectors.json, each checked offline (Anchor §10.4 item 2). A
// transaction that breaks a rule of item 2 is false, malformed_publication,
// and anchor.evm.tx reports none of its facts, since it has not decoded.
// The transaction just inside each rule is read, and its sender fact is the
// address the file states.
func TestEVMTransactionVectors(t *testing.T) {
	d := load(t, "evm-anchor-vectors.json")
	tx := get(t, d, "transactionCases")
	chain := get(t, tx, "chain")
	origin := str(t, d, "anchorOrigin")
	p := hexb(t, str(t, d, "p"))
	// "" stands for a null rule: item 2 reads the transaction.
	rules := map[string]bool{}
	ids := map[string]bool{}
	for _, c := range get(t, tx, "cases").A {
		id := str(t, c, "id")
		if ids[id] {
			t.Errorf("%s: the id is repeated", id)
		}
		ids[id] = true
		rule := ""
		if !isNull(c, "rule") {
			rule = str(t, c, "rule")
		}
		rules[rule] = true
		refuses := str(t, c, "item2") == "refuses"
		if refuses == (rule == "") {
			t.Errorf("%s: item2 %s beside rule %q", id, str(t, c, "item2"), rule)
		}
		t.Run(id, func(t *testing.T) {
			entry := report.Obj("kind", report.S(evm.Kind), "chain", chain,
				"transactionId", get(t, c, "transactionId"), "rawTransaction", get(t, c, "rawTransaction"),
				"blockNumber", get(t, tx, "blockNumber"), "blockHash", get(t, tx, "blockHash"))
			manifest := report.Obj("publishers", report.Obj(origin, report.Arr(
				report.Obj("address", get(t, c, "publisher"), "chain", chain, "namespace", report.S("test")))))
			r := evm.Verify(evm.Input{Entry: entry, P: p, AnchorOrigin: origin, Manifest: manifest,
				Deadline: time.Now().Add(time.Minute)})
			want := get(t, c, "expect")
			valid := report.Null()
			if r.Valid != nil {
				valid = report.B(*r.Valid)
			}
			reason, _ := optStr(want, "reason")
			gotReason := r.Reason
			if r.Valid != nil && *r.Valid {
				gotReason = ""
			}
			if canonicalOf(t, valid) != canonicalOf(t, get(t, want, "valid")) || gotReason != reason {
				t.Errorf("valid %s %q, want %s %q", canonicalOf(t, valid), r.Reason, canonicalOf(t, get(t, want, "valid")), reason)
			}
			for _, x := range []struct {
				key string
				row report.Check
			}{{"tx", r.Tx}, {"canonical", r.Canonical}} {
				w := get(t, want, x.key)
				rr, _ := optStr(w, "reason")
				// The vectors name the publication's own tx row without
				// its index.
				if rr == "blocked_by:anchor.evm.tx" {
					rr = "blocked_by:" + r.Tx.ID
				}
				expectRow(t, id, x.row.ID, report.CheckJSON(x.row), str(t, w, "outcome"), rr, nil)
			}
			sender, ok := r.Tx.Fact("sender")
			switch {
			case refuses && len(r.Tx.Facts) != 0:
				t.Errorf("a transaction item 2 refuses reports facts %s", canonicalOf(t, factsOf(report.CheckJSON(r.Tx))))
			case !refuses && (!ok || sender.S != strings.ToLower(str(t, c, "sender"))):
				t.Errorf("sender fact %v, want %s", sender, str(t, c, "sender"))
			}
		})
	}
	// The rules of item 2, by the labels the specification gives them.
	known := []string{"chain-id", "legacy-v", "signature-values", "fees", "recovery", "encoding", "field-sizes", ""}
	for _, rule := range known {
		if !rules[rule] {
			t.Errorf("no transaction case for rule %q", rule)
		}
		delete(rules, rule)
	}
	for rule := range rules {
		t.Errorf("a transaction case names rule %q, which is not a rule of item 2", rule)
	}
}
