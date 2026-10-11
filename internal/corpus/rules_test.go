// SPDX-License-Identifier: BSD-3-Clause-Clear

package corpus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/cli"
)

// Tests of the record-rule rows in whole bundles, on the rules the
// conformance vectors state outside a bundle, or not at all: the freshness
// reference against a header source, the mandate rows, the issuance block,
// a payload member name with a lone surrogate, an unowed confirmation, the
// link rows of a record whose digest does not hold, and row 17a.

// vectorDoc reads one entry of a vector file as a doc.
func vectorDoc(t *testing.T, file, section, key, name string) doc {
	t.Helper()
	d := loadDoc(t, filepath.Join(vectorDir, file))
	for _, x := range d[section].([]any) {
		c := x.(doc)
		if c[key] == name {
			return clone(t, c)
		}
	}
	t.Fatalf("%s: no %s %q", file, section, name)
	return nil
}

// sealed is an envelope around a payload, with the digest recomputed and
// the given nonRepudiation members.
func sealed(t *testing.T, payload doc, nr doc) doc {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonical.RecordDigest(jsonOf(t, string(b)))
	if err != nil {
		t.Fatal(err)
	}
	if nr == nil {
		nr = doc{}
	}
	return doc{"envelopeVersion": "e1", "payload": payload,
		"integrity": doc{"canonicalDigest": digest, "chainLink": nil}, "nonRepudiation": nr}
}

// runFile runs the command over a bundle file and returns its exit code.
func runFile(t *testing.T, f string) int {
	t.Helper()
	var stdout, stderr bytes.Buffer
	return cli.Run([]string{"--json", "--no-publishers", f}, &stdout, &stderr)
}

// headerFile writes a header source and returns its --evm-header-file flag
// value for the chain.
func headerFile(t *testing.T, chain string, src doc) string {
	t.Helper()
	b, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "headers.json")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return chain + "=" + f
}

// TestFreshnessRow: decider.freshness (Verification §4.9) against the
// auditor's header source for the reference's chain.
func TestFreshnessRow(t *testing.T) {
	hash := "0x" + strings.Repeat("ab", 32)
	other := "0x" + strings.Repeat("cd", 32)
	base := vectorDoc(t, "decider-vectors.json", "rows", "case", "a human under acct")["envelope"].(doc)["payload"].(doc)
	withRef := func(ref any, kind string) doc {
		p := clone(t, base)
		dec := p["decider"].(doc)
		dec["freshness"] = ref
		if kind != "" {
			dec["kind"] = kind
		}
		return bundleOf(sealed(t, p, nil))
	}
	source := func(chainID int, finalized int, blocks ...doc) doc {
		bs := []any{}
		for _, b := range blocks {
			bs = append(bs, b)
		}
		return doc{"chainId": chainID, "finality": "finalized", "finalizedBlockNumber": finalized, "blocks": bs}
	}
	// capturedAt is 2026-10-05T10:00:00.000Z, 1791194400 s.
	at := 1791194400
	ref := "eip155:31337@7:" + hash
	for _, c := range []struct {
		name  string
		b     doc
		flags []string
		row   string
		exit  int
		facts string
	}{
		{"no reference", withRef(nil, ""), nil, "not-checked absent", 0, ""},
		{"no header source", withRef(ref, ""), nil, "not-checked input_not_supplied:evm_header_source", 4, ""},
		{"the canonical block", withRef(ref, ""),
			[]string{"--evm-header-file", headerFile(t, "eip155:31337", source(31337, 9, doc{"number": 7, "hash": hash, "timestamp": at - 12}))},
			"checked-correct", 0, `{"blockTime":"2026-10-05T09:59:48.000Z","captureLag":12000,"finality":"finalized"}`},
		{"a block named after capture: a negative lag", withRef(ref, ""),
			[]string{"--evm-header-file", headerFile(t, "eip155:31337", source(31337, 9, doc{"number": 7, "hash": hash, "timestamp": at + 1}))},
			"checked-correct", 0, `{"blockTime":"2026-10-05T10:00:01.000Z","captureLag":-1000,"finality":"finalized"}`},
		{"another hash at that height", withRef(ref, ""),
			[]string{"--evm-header-file", headerFile(t, "eip155:31337", source(31337, 9, doc{"number": 7, "hash": other, "timestamp": at}))},
			"checked-wrong freshness_block_mismatch", 1, `{"finality":"finalized"}`},
		{"a height above the final one", withRef(ref, ""),
			[]string{"--evm-header-file", headerFile(t, "eip155:31337", source(31337, 6))},
			"not-checked evm_block_not_finalized", 4, `{"finality":"finalized"}`},
		{"no block at a final height", withRef(ref, ""),
			[]string{"--evm-header-file", headerFile(t, "eip155:31337", source(31337, 9))},
			"not-checked evm_header_source_inconsistent", 4, `{"finality":"finalized"}`},
		{"a source of another chain", withRef(ref, ""),
			[]string{"--evm-header-file", headerFile(t, "eip155:31337", source(1, 9, doc{"number": 7, "hash": hash, "timestamp": at}))},
			"not-checked evm_header_source_chain_mismatch", 4, ""},
		{"a source for any chain", withRef(ref, ""),
			[]string{"--evm-header-file", strings.TrimPrefix(headerFile(t, "eip155:31337", source(31337, 9, doc{"number": 7, "hash": hash, "timestamp": at})), "eip155:31337=")},
			"checked-correct", 0, `{"blockTime":"2026-10-05T10:00:00.000Z","captureLag":0,"finality":"finalized"}`},
		{"a chain outside eip155", withRef("bip122:000000000019d6689c085ae165831e93@840000:"+hash, ""), nil,
			"abstain unsupported_freshness_chain", 4, ""},
		{"a decider that does not hold", withRef(ref, "agent-mandated"), nil, "not-checked blocked_by:decider", 1, ""},
	} {
		exit, rows, rep := runDocReport(t, c.b, append([]string{"--no-publishers"}, c.flags...)...)
		if rows["decider.freshness"] != c.row || exit != c.exit {
			t.Errorf("%s: decider.freshness %q, exit %d; want %q, exit %d", c.name, rows["decider.freshness"], exit, c.row, c.exit)
		}
		if row := rowOf(t, rep, "decider.freshness"); c.facts != "" && canonicalOf(t, factsOf(row)) != c.facts {
			t.Errorf("%s: facts %s, want %s", c.name, canonicalOf(t, factsOf(row)), c.facts)
		}
	}
}

// mandated is the worked example W6, decided under the mandate of W4,
// carrying W4's mandate block.
func mandated(t *testing.T) (doc, doc) {
	t.Helper()
	w6 := vectorDoc(t, "v1.0-worked-example-vectors.json", "records", "id", "W6")["payload"].(doc)
	// The first record of its chain, so that the bundle needs no
	// predecessor; the mandate rows do not read the sequence number.
	w6["sequenceNumber"] = 1
	block := vectorDoc(t, "signoff-expectation-vectors.json", "checks", "case", "row 24: the mandate form with its mandate block")["envelope"].(doc)["nonRepudiation"].(doc)["mandate"].(doc)
	return w6, block
}

// TestMandateRowsInBundle: the rows of Verification §4.12 for a record
// decided under a mandate, and how they block on the expectation.
func TestMandateRowsInBundle(t *testing.T) {
	w6, block := mandated(t)
	run := func(name string, payload, mblock doc, mutate func(doc)) (int, map[string]string, map[string]string) {
		t.Helper()
		b := bundleOf(sealed(t, payload, doc{"mandate": mblock}))
		if mblock == nil {
			b = bundleOf(sealed(t, payload, nil))
		}
		if mutate != nil {
			mutate(b)
		}
		exit, rows, rep := runDocReport(t, b, "--no-publishers")
		facts := map[string]string{}
		for _, id := range []string{"mandate.scope", "mandate.limits"} {
			if r := rowOf(t, rep, id); r != nil {
				facts[id] = canonicalOf(t, factsOf(r))
			}
		}
		return exit, rows, facts
	}
	exit, rows, facts := run("W6", clone(t, w6), clone(t, block), nil)
	for id, want := range map[string]string{
		"signoff.expectation": "checked-correct",
		"decider":             "checked-correct",
		"contributions":       "checked-correct",
		"links":               "checked-correct",
		"links[0]":            "not-checked not_in_bundle:link_target",
		"mandate.scope":       "checked-correct",
		"mandate.limits":      "checked-correct",
		"mandate.key":         "not-checked not_in_bundle:credential",
	} {
		if rows[id] != want {
			t.Errorf("W6: %s %q, want %q", id, rows[id], want)
		}
	}
	if _, ok := rows["mandate.issuance"]; ok {
		t.Error("W6: a mandate.issuance row on a record that is not an issuance record")
	}
	if _, ok := rows["mandate.assertionTimestamp"]; ok {
		t.Error("W6: a mandate.assertionTimestamp row for a null timestamp")
	}
	if facts["mandate.limits"] != `{"slot":41,"totals":{"paid":5230000}}` {
		t.Errorf("W6: mandate.limits facts %s", facts["mandate.limits"])
	}
	if exit != 4 {
		t.Errorf("W6: exit %d, want 4 (mandate.key is never decided)", exit)
	}

	// The credentials slot filled: the key is one this build does not read.
	_, rows, _ = run("credentials", clone(t, w6), clone(t, block), func(b doc) { b["credentials"] = doc{} })
	if rows["mandate.key"] != "abstain unsupported_signoff" {
		t.Errorf("credentials: mandate.key %q", rows["mandate.key"])
	}

	// A timestamp over the assertion: abstain on it.
	ts := clone(t, block)
	ts["assertionTimestamp"] = "MAA="
	if _, rows, _ = run("timestamp", clone(t, w6), ts, nil); rows["mandate.assertionTimestamp"] != "abstain unsupported_artifact" {
		t.Errorf("timestamp: mandate.assertionTimestamp %q", rows["mandate.assertionTimestamp"])
	}

	// Outside the scope: another action, the total re-sealed.
	p := clone(t, w6)
	p["action"] = "refer-to-fraud"
	if _, rows, facts = run("action", p, clone(t, block), nil); rows["mandate.scope"] != "checked-wrong outside_mandate_scope" ||
		facts["mandate.scope"] != `{"failed":["actions"]}` {
		t.Errorf("another action: mandate.scope %q %s", rows["mandate.scope"], facts["mandate.scope"])
	}

	// A decider that is not one of the agents.
	p = clone(t, w6)
	other := "sha256:" + strings.Repeat("b2", 32)
	p["decider"].(doc)["agent"], p["decider"].(doc)["id"] = other, "desc:"+other
	p["contributions"].(doc)["steps"].([]any)[0].(doc)["actor"].(doc)["agent"] = other
	p["contributions"].(doc)["steps"].([]any)[0].(doc)["actor"].(doc)["id"] = "desc:" + other
	if _, rows, _ = run("agent", p, clone(t, block), nil); rows["mandate.scope"] != "checked-wrong agent_not_in_mandate" {
		t.Errorf("another agent: mandate.scope %q", rows["mandate.scope"])
	}

	// confirm false on a record a confirm predicate flags: evaded.
	p = clone(t, w6)
	p["aiOutput"].(doc)["fraudFlag"] = true
	if _, rows, facts = run("evaded", p, clone(t, block), nil); rows["mandate.scope"] != "checked-wrong confirmation_evaded" ||
		facts["mandate.scope"] != `{"confirm":["fraud"]}` {
		t.Errorf("evaded: mandate.scope %q %s", rows["mandate.scope"], facts["mandate.scope"])
	}

	// The amount missing: the scope predicate cannot be decided, and the cap
	// value is not an integer.
	p = clone(t, w6)
	delete(p["aiOutput"].(doc), "amountMinor")
	if _, rows, facts = run("undeterminable", p, clone(t, block), nil); rows["mandate.scope"] != "not-checked scope_undeterminable" ||
		facts["mandate.scope"] != `{"undeterminable":["predicate:cap"]}` || rows["mandate.limits"] != "checked-wrong mandate_totals_malformed" {
		t.Errorf("undeterminable: mandate.scope %q %s, mandate.limits %q", rows["mandate.scope"], facts["mandate.scope"], rows["mandate.limits"])
	}

	// A running total over the cap.
	p = clone(t, w6)
	p["signoffExpectation"].(doc)["totals"] = doc{"paid": 250000001}
	if _, rows, _ = run("over", p, clone(t, block), nil); rows["mandate.limits"] != "checked-wrong mandate_limit_exceeded" {
		t.Errorf("over the cap: mandate.limits %q", rows["mandate.limits"])
	}

	// No document in the block, and another document version.
	noDoc := clone(t, block)
	noDoc["document"] = nil
	if _, rows, _ = run("no document", clone(t, w6), noDoc, nil); rows["mandate.scope"] != "not-checked not_in_bundle:mandate_document" ||
		rows["mandate.limits"] != "not-checked not_in_bundle:mandate_document" || rows["signoff.expectation"] != "checked-correct" {
		t.Errorf("no document: %q %q %q", rows["signoff.expectation"], rows["mandate.scope"], rows["mandate.limits"])
	}

	// The block stripped: the expectation fails, and the rows it gates are
	// blocked by it.
	if exit, rows, _ = run("stripped", clone(t, w6), nil, nil); rows["signoff.expectation"] != "checked-wrong mandate_stripped" ||
		rows["mandate.scope"] != "not-checked blocked_by:signoff.expectation" ||
		rows["mandate.limits"] != "not-checked blocked_by:signoff.expectation" ||
		rows["mandate.key"] != "not-checked blocked_by:signoff.expectation" || exit != 1 {
		t.Errorf("stripped: %q %q %q %q exit %d", rows["signoff.expectation"], rows["mandate.scope"], rows["mandate.limits"], rows["mandate.key"], exit)
	}

	// Row 17a: a sign-off block and an assertion that bind nothing.
	if _, rows, _ = run("17a", clone(t, w6), clone(t, block), func(b doc) {
		nr := b["envelope"].(doc)["nonRepudiation"].(doc)
		nr["signoff"] = doc{}
		nr["webauthnAssertion"] = doc{"clientDataJSON": "e30"}
	}); rows["signoff.expectation"] != "checked-wrong signoff_unbound" {
		t.Errorf("17a: signoff.expectation %q", rows["signoff.expectation"])
	}

	// A confirmation owed and given: no row of its own.
	p = clone(t, w6)
	p["signoffExpectation"].(doc)["confirm"] = true
	_, rows, _ = run("confirm", p, clone(t, block), nil)
	if rows["signoff.expectation"] != "not-checked confirmation_missing" || rows["mandate.scope"] != "checked-correct" {
		t.Errorf("confirmation owed: %q, mandate.scope %q", rows["signoff.expectation"], rows["mandate.scope"])
	}
	if _, ok := rows["nonRepudiation.confirmation"]; ok {
		t.Error("a nonRepudiation.confirmation row with no confirmation")
	}

	// A confirmation on a record whose confirm is false: no row reads it.
	_, rows, _ = run("unowed", clone(t, w6), clone(t, block), func(b doc) {
		b["envelope"].(doc)["nonRepudiation"].(doc)["confirmation"] = doc{"clientDataJSON": "e30"}
	})
	if rows["nonRepudiation.confirmation"] != "abstain unsupported_artifact" || rows["signoff.expectation"] != "checked-correct" {
		t.Errorf("a confirmation not owed: %q, signoff.expectation %q", rows["nonRepudiation.confirmation"], rows["signoff.expectation"])
	}
}

// TestIssuanceInBundle: mandate.issuance and mandate.key for the issuance
// record W5, and an issuance block on a record that is not one.
func TestIssuanceInBundle(t *testing.T) {
	w5 := vectorDoc(t, "mandate-vectors.json", "issuance", "case", "W4's issuance record (W5)")["envelope"].(doc)
	exit, rows := runDoc(t, bundleOf(clone(t, w5)), "--no-publishers")
	if rows["mandate.issuance"] != "checked-correct" || rows["mandate.key"] != "not-checked not_in_bundle:credential" || exit != 4 {
		t.Errorf("W5: mandate.issuance %q, mandate.key %q, exit %d", rows["mandate.issuance"], rows["mandate.key"], exit)
	}
	for _, id := range []string{"mandate.scope", "mandate.limits", "nonRepudiation.mandateIssuance"} {
		if _, ok := rows[id]; ok {
			t.Errorf("W5: a %s row", id)
		}
	}
	not := vectorDoc(t, "mandate-vectors.json", "issuance", "case", "issuance material on a record that is not an issuance record")["envelope"].(doc)
	exit, rows = runDoc(t, bundleOf(not), "--no-publishers")
	if rows["mandate.issuance"] != "checked-wrong issuance_not_expected" || rows["mandate.key"] != "not-checked blocked_by:mandate.issuance" || exit != 1 {
		t.Errorf("not an issuance record: mandate.issuance %q, mandate.key %q, exit %d", rows["mandate.issuance"], rows["mandate.key"], exit)
	}
	ts := clone(t, w5)
	ts["nonRepudiation"].(doc)["mandateIssuance"].(doc)["assertionTimestamp"] = "MAA="
	if _, rows = runDoc(t, bundleOf(ts), "--no-publishers"); rows["mandate.assertionTimestamp"] != "abstain unsupported_artifact" {
		t.Errorf("W5 with a timestamp: %q", rows["mandate.assertionTimestamp"])
	}
}

// TestPayloadRows: a payload member outside the twelve has a row of its own,
// and one whose name holds a lone surrogate makes the bundle unreadable
// (Bundle §4 step 9).
func TestPayloadRows(t *testing.T) {
	base := vectorDoc(t, "decider-vectors.json", "rows", "case", "a human under acct")["envelope"].(doc)
	p := clone(t, base)["payload"].(doc)
	p["humanReason"] = "edited, and hashed by no field set"
	exit, rows := runDoc(t, bundleOf(sealed(t, p, nil)), "--no-publishers")
	if rows["payload.humanReason"] != "abstain unsupported_member" || exit != 4 {
		t.Errorf("payload.humanReason %q, exit %d", rows["payload.humanReason"], exit)
	}
	exit, rows = runDoc(t, bundleOf(sealed(t, p, nil)), "--no-publishers", "--allow-unchecked-reason", "unsupported_member")
	if exit != 0 {
		t.Errorf("the scoped allowance of unsupported_member: exit %d", exit)
	}
	b, err := json.Marshal(bundleOf(sealed(t, clone(t, base)["payload"].(doc), nil)))
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Replace(string(b), `"evidenceId":`, `"\ud800":1,"evidenceId":`, 1)
	f := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(f, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if o := runFile(t, f); o != 2 {
		t.Errorf("a payload member name with a lone surrogate: exit %d, want 2", o)
	}
}

// TestUnowedConfirmation: a confirmation on a record that owes none is
// material no row reads (Verification §4.7).
func TestUnowedConfirmation(t *testing.T) {
	base := vectorDoc(t, "decider-vectors.json", "rows", "case", "a human under acct")["envelope"].(doc)
	env := clone(t, base)
	env["nonRepudiation"] = doc{"confirmation": doc{"clientDataJSON": "e30"}}
	exit, rows := runDoc(t, bundleOf(env), "--no-publishers")
	if rows["nonRepudiation.confirmation"] != "abstain unsupported_artifact" || exit != 4 {
		t.Errorf("nonRepudiation.confirmation %q, exit %d", rows["nonRepudiation.confirmation"], exit)
	}
}

// TestLinkRowsBlockedByDigest: a record with links whose digest does not
// hold: links blocked by record.digest, each link's row by links, and each
// edge abstaining as it does on every record.
func TestLinkRowsBlockedByDigest(t *testing.T) {
	b := loadDoc(t, filepath.Join(vectorDir, "bundle-b1", "links-derived-from", "bundle.json"))
	b["envelope"].(doc)["payload"].(doc)["reason"] = "edited after capture"
	exit, rows := runDoc(t, b, "--no-publishers")
	for id, want := range map[string]string{
		"record.digest": "checked-wrong digest_mismatch",
		"links":         "not-checked blocked_by:record.digest",
		"links[0]":      "not-checked blocked_by:links",
		"links[0].edge": "abstain unsupported_link_edge",
		"links[1]":      "not-checked blocked_by:links",
		"links[1].edge": "abstain unsupported_link_edge",
	} {
		if rows[id] != want {
			t.Errorf("%s %q, want %q", id, rows[id], want)
		}
	}
	if exit != 1 {
		t.Errorf("exit %d", exit)
	}
}

// TestStepAIBomNotObject: a step's aiBom is null or an object (Record
// §7.1); any other JSON type makes the contributions malformed.
func TestStepAIBomNotObject(t *testing.T) {
	w2 := vectorDoc(t, "v1.0-worked-example-vectors.json", "records", "id", "W2")["payload"].(doc)
	w2["sequenceNumber"] = 1
	for name, val := range map[string]any{"a string": "gpt", "an array": []any{}, "a number": 7, "true": true} {
		p := clone(t, w2)
		p["contributions"].(doc)["steps"].([]any)[0].(doc)["aiBom"] = val
		exit, rows, rep := runDocReport(t, bundleOf(sealed(t, p, nil)), "--no-publishers")
		if rows["contributions"] != "checked-wrong malformed_contributions" || exit != 1 {
			t.Errorf("aiBom %s: contributions %q, exit %d", name, rows["contributions"], exit)
		}
		if f := canonicalOf(t, factsOf(rowOf(t, rep, "contributions"))); f != `{"failedStep":0}` {
			t.Errorf("aiBom %s: facts %s", name, f)
		}
	}
}

// TestFreshnessMemberMissing: a decider object without a freshness member
// is not a decider whose freshness is null (Verification §4.9 step 1), so
// decider.freshness is blocked by the decider row, as it is for a decider
// that is not an object.
func TestFreshnessMemberMissing(t *testing.T) {
	base := vectorDoc(t, "decider-vectors.json", "rows", "case", "a human under acct")["envelope"].(doc)["payload"].(doc)
	p := clone(t, base)
	delete(p["decider"].(doc), "freshness")
	_, rows := runDoc(t, bundleOf(sealed(t, p, nil)), "--no-publishers")
	if rows["decider"] != "checked-wrong malformed_decider" || rows["decider.freshness"] != "not-checked blocked_by:decider" {
		t.Errorf("no freshness member: decider %q, decider.freshness %q", rows["decider"], rows["decider.freshness"])
	}
	p = clone(t, base)
	p["decider"] = "acct:u-1"
	_, rows = runDoc(t, bundleOf(sealed(t, p, nil)), "--no-publishers")
	if rows["decider.freshness"] != "not-checked blocked_by:decider" {
		t.Errorf("a decider that is a string: decider.freshness %q", rows["decider.freshness"])
	}
}

// TestLinksOver256DigestFails: a links list longer than 256 has no
// per-link rows (Verification §4.11), also when the digest fails.
func TestLinksOver256DigestFails(t *testing.T) {
	p := clone(t, vectorDoc(t, "decider-vectors.json", "rows", "case", "a human under acct")["envelope"].(doc)["payload"].(doc))
	ls := []any{}
	for i := 0; i < 257; i++ {
		ls = append(ls, doc{"rel": "derivedFrom", "target": doc{"digest": strings.Repeat(fmt.Sprintf("%04x", i), 16), "evidenceId": nil, "locator": nil}, "attrs": nil})
	}
	p["links"] = ls
	env := sealed(t, p, nil)
	env["integrity"].(doc)["canonicalDigest"] = strings.Repeat("0", 64)
	b := bundleOf(env)
	exit, rows := runDoc(t, b, "--no-publishers")
	if rows["links"] != "not-checked blocked_by:record.digest" || exit != 1 {
		t.Errorf("links %q, exit %d", rows["links"], exit)
	}
	for id := range rows {
		if strings.HasPrefix(id, "links[") {
			t.Errorf("a %s row for a list of 257 links", id)
		}
	}
}

// TestLinkRecordNothingHeld: in a link record, a ratifies link reads the
// subject and the target; a bundle holds neither, and the row names the
// subject as the record missing.
func TestLinkRecordNothingHeld(t *testing.T) {
	p := vectorDoc(t, "v1.0-worked-example-vectors.json", "records", "id", "W7")["payload"].(doc)
	p["sequenceNumber"] = 1
	ls := p["links"].([]any)
	ls[0].(doc)["rel"] = "ratifies"
	_, rows, rep := runDocReport(t, bundleOf(sealed(t, p, nil)), "--no-publishers")
	if rows["links"] != "checked-correct" || rows["links[0]"] != "not-checked not_in_bundle:link_target" {
		t.Fatalf("links %q, links[0] %q", rows["links"], rows["links[0]"])
	}
	if f := canonicalOf(t, factsOf(rowOf(t, rep, "links[0]"))); f != `{"missing":"subject","targetHeld":false}` {
		t.Errorf("links[0] facts %s", f)
	}
}

// TestJunkSignoffBlock: a sign-off block of any JSON type is a block (Record
// §9.3), so a per-record assertion beside it is not human material that
// binds the record (§9.5), and the decider row carries no levelUndetermined.
func TestJunkSignoffBlock(t *testing.T) {
	base := vectorDoc(t, "decider-vectors.json", "rows", "case", "a human under acct with a per-record assertion bound")["envelope"].(doc)
	for name, junk := range map[string]any{"a string": "junk", "a number": 7, "an array": []any{}, "false": false} {
		env := clone(t, base)
		env["nonRepudiation"].(doc)["signoff"] = junk
		_, rows, rep := runDocReport(t, bundleOf(env), "--no-publishers")
		if rows["signoff.expectation"] != "checked-wrong signoff_unbound" {
			t.Errorf("signoff %s: signoff.expectation %q", name, rows["signoff.expectation"])
		}
		if f := canonicalOf(t, factsOf(rowOf(t, rep, "decider"))); rows["decider"] != "checked-correct" || strings.Contains(f, "levelUndetermined") {
			t.Errorf("signoff %s: decider %q %s", name, rows["decider"], f)
		}
	}
}
