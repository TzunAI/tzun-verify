// SPDX-License-Identifier: BSD-3-Clause-Clear

package corpus

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// TestCustodyMirrorEntry: custody.ledger (Verification §4.3) over corpus
// case anchored-with-newer, whose custody slot is empty and whose
// custodyChain holds one element, the entry the writer added when it
// captured the record, which has no entryHash. The chain holds no mirror
// entry (Record §2.1), so the row reads not_applicable and the case exits 0.
//
// A mirror entry, an object whose entryHash is 64 lowercase hex digits,
// appended to the chain beside a slot that holds no row, empty or null,
// names a custody row the bundle leaves out: custody.ledger is
// checked-wrong, mirror_entry_unexpected, and the exit is 1 (§6.6), under
// the auditor's allowance too, whole or scoped to unsupported_artifact. The
// chain is not hashed (Record §4.1), so the report is the corpus's with that
// row and its outcome counts changed, byte for byte, checkedAt left out.
//
// An element whose entryHash is not 64 lowercase hex digits is no mirror
// entry, and the report is the corpus's own. A slot that holds a row, or an
// object without entries, abstains, unsupported_artifact, whatever the
// chain holds (rule 2).
func TestCustodyMirrorEntry(t *testing.T) {
	dir := filepath.Join(vectorDir, "bundle-b1", "anchored-with-newer")
	in, err := jsonv.Parse(readCase(t, dir, "inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	flags := args(t, in, t.TempDir())
	want, err := jsonv.Parse(readCase(t, dir, "expected-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	base := loadDoc(t, filepath.Join(dir, "bundle.json"))
	if got := rowLine(t, rowOf(t, want, "custody.ledger")); got != "not-checked not_applicable" {
		t.Fatalf("the base case's custody.ledger is %s", got)
	}
	if e, ok := sub(base, "custody")["entries"].([]any); !ok || len(e) != 0 {
		t.Fatal("the base case's custody slot is not empty")
	}
	chain, _ := sub(base, "envelope")["custodyChain"].([]any)
	if len(chain) != 1 {
		t.Fatalf("the base case's custodyChain has %d entries, want the capture's own", len(chain))
	}
	if _, hashed := chain[0].(doc)["entryHash"]; hashed {
		t.Fatal("the base case's capture entry has an entryHash")
	}

	hash := strings.Repeat("5a", 32)
	entry := func(entryHash any) doc {
		return doc{
			"timestamp": "2026-10-01T17:40:35.754Z", "actor": "ops@example.com", "action": "reviewed",
			"systemId": "recovery", "metadata": doc{"incidentId": "corpus-1"},
			"entryHash": entryHash, "prevEntryHash": nil,
		}
	}
	mirror := entry(hash)
	// bundle is the base case with elements appended to its custodyChain
	// and slot in its custody slot.
	bundle := func(slot any, elems ...any) doc {
		d := clone(t, base)
		env := sub(d, "envelope")
		for _, e := range elems {
			if m, ok := e.(doc); ok {
				e = clone(t, m)
			}
			env["custodyChain"] = append(env["custodyChain"].([]any), e)
		}
		d["custody"] = slot
		return d
	}
	// expected is the corpus's report, checkedAt left out, with
	// custody.ledger reading outcome and reason, counted under outcome in
	// place of not-checked.
	expected := func(outcome, reason string) []byte {
		w := loadDoc(t, filepath.Join(dir, "expected-report.json"))
		for _, c := range w["checks"].([]any) {
			if c.(doc)["id"] == "custody.ledger" {
				c.(doc)["outcome"], c.(doc)["reason"] = outcome, reason
			}
		}
		counts := sub(w, "summary", "outcomes")
		for k, delta := range map[string]int64{"not-checked": -1, outcome: 1} {
			n, err := counts[k].(json.Number).Int64()
			if err != nil {
				t.Fatal(err)
			}
			counts[k] = n + delta
		}
		b, err := json.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		v, err := jsonv.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		return comparable(t, v)
	}
	run := func(d doc, extra ...string) (int, *jsonv.Value) {
		t.Helper()
		exit, _, rep := runDocReport(t, d, append(append([]string{}, flags...), extra...)...)
		return exit, rep
	}
	check := func(t *testing.T, d doc, wantExit int, wantReport []byte) {
		t.Helper()
		exit, got := run(d)
		if exit != wantExit {
			t.Errorf("exit %d, want %d", exit, wantExit)
		}
		if g := comparable(t, got); string(g) != string(wantReport) {
			w, _ := jsonv.Parse(wantReport)
			t.Errorf("report differs:%s", differences(t, got, w))
		}
	}

	// The row and its mirror entry both left out: the corpus's own case.
	t.Run("no mirror entry", func(t *testing.T) {
		check(t, base, 0, comparable(t, want))
	})

	wrong := expected("checked-wrong", "mirror_entry_unexpected")
	for _, c := range []struct {
		name  string
		slot  any
		elems []any
	}{
		{"a mirror entry beside an empty custody slot", doc{"entries": []any{}}, []any{mirror}},
		{"a mirror entry beside a null custody slot", nil, []any{mirror}},
		{"a mirror entry after an element that is not one", doc{"entries": []any{}}, []any{entry(strings.ToUpper(hash)), mirror}},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := bundle(c.slot, c.elems...)
			check(t, d, 1, wrong)
			// A checked-wrong row is a finding: no allowance turns it to 0.
			for _, allow := range [][]string{{"--allow-unchecked"}, {"--allow-unchecked-reason", "unsupported_artifact"}} {
				exit, got := run(d, allow...)
				if exit != 1 {
					t.Errorf("%v: exit %d, want 1", allow, exit)
				}
				if row := rowLine(t, rowOf(t, got, "custody.ledger")); row != "checked-wrong mirror_entry_unexpected" {
					t.Errorf("%v: custody.ledger %s", allow, row)
				}
			}
		})
	}

	// Elements that are not mirror entries (Record §2.1): beside a slot that
	// holds no row, the report is the corpus's own.
	for _, c := range []struct {
		name string
		elem any
	}{
		{"an entryHash with one uppercase digit", entry("5A" + hash[2:])},
		{"an entryHash in uppercase", entry(strings.ToUpper(hash))},
		{"an entryHash of one character", entry("x")},
		{"an entryHash of 63 digits", entry(hash[1:])},
		{"an entryHash of 65 digits", entry(hash + "5")},
		{"an entryHash with a sha256: prefix", entry("sha256:" + hash)},
		{"an entryHash that is a number", entry(5)},
		{"an entryHash that is an object", entry(doc{"entryHash": hash})},
		{"a null entryHash", entry(nil)},
		{"a string element of 64 lowercase digits", hash},
		{"an array element holding a mirror entry", []any{mirror}},
	} {
		for _, slot := range []struct {
			name string
			v    any
		}{{"an empty", doc{"entries": []any{}}}, {"a null", nil}} {
			t.Run(c.name+" beside "+slot.name+" custody slot", func(t *testing.T) {
				check(t, bundle(slot.v, c.elem), 0, comparable(t, want))
			})
		}
	}

	// A slot that holds a row, or an object without entries, abstains
	// whatever the chain holds (rule 2): the finding is for a slot that
	// holds no row.
	abstain := expected("abstain", "unsupported_artifact")
	for _, c := range []struct {
		name  string
		slot  any
		elems []any
	}{
		{"custody entries beside a mirror entry", doc{"entries": []any{doc{"entryHash": hash}}}, []any{mirror}},
		{"custody entries without a mirror entry", doc{"entries": []any{doc{"entryHash": hash}}}, nil},
		{"a custody slot without entries beside a mirror entry", doc{}, []any{mirror}},
		{"a custody slot whose entries are null beside a mirror entry", doc{"entries": nil}, []any{mirror}},
	} {
		t.Run(c.name, func(t *testing.T) {
			check(t, bundle(c.slot, c.elems...), 4, abstain)
		})
	}
}
