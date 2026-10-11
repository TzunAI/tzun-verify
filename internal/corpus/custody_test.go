package corpus

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// TestCustodyMirrorWithoutLedger: the envelope's custodyChain mirrors the
// custody ledger, one hashed entry (an entryHash) for each ledger row.
// Corpus case anchored-with-newer carries an empty custody slot and a chain
// whose one entry, the capture's own, is not hashed: custody.ledger reads
// not_applicable, and the case exits 0.
//
// The same bundle with a hashed mirror entry appended to its chain, and the
// row it mirrors left out of the slot, carries custody material: a row the
// bundle names and does not hold, which this version does not verify. It
// must not pass in silence (Bundle §6, Specs §4), so custody.ledger
// abstains, unsupported_artifact, and the exit is 4 (Verification §4.3,
// §6.6); so it does with a null slot. Every other row, and the summary but
// for its outcome counts, is as the corpus states it for the case. The
// auditor's allowance, whole or scoped to unsupported_artifact, turns the
// exit to 0. The chain is not hashed (Record §4.1), so the record digest and
// every anchor row are unchanged.
func TestCustodyMirrorWithoutLedger(t *testing.T) {
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
	chain, _ := sub(base, "envelope")["custodyChain"].([]any)
	if len(chain) != 1 {
		t.Fatalf("the base case's custodyChain has %d entries, want the capture's own", len(chain))
	}
	if _, hashed := chain[0].(doc)["entryHash"]; hashed {
		t.Fatal("the base case's capture entry is hashed")
	}

	mirror := doc{
		"timestamp": "2026-10-01T17:40:35.754Z", "actor": "ops@example.com", "action": "reviewed",
		"systemId": "recovery", "metadata": doc{"incidentId": "corpus-1"},
		"entryHash": strings.Repeat("5a", 32), "prevEntryHash": nil,
	}
	mirrored := func(slot any) doc {
		d := clone(t, base)
		env := sub(d, "envelope")
		env["custodyChain"] = append(env["custodyChain"].([]any), clone(t, mirror))
		d["custody"] = slot
		return d
	}

	run := func(d doc, extra ...string) (int, *jsonv.Value) {
		t.Helper()
		exit, _, rep := runDocReport(t, d, append(append([]string{}, flags...), extra...)...)
		return exit, rep
	}

	for _, c := range []struct {
		name string
		slot any
	}{
		{"an empty custody slot", doc{"entries": []any{}}},
		{"a null custody slot", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := mirrored(c.slot)
			exit, got := run(d)
			if exit != 4 {
				t.Errorf("exit %d, want 4", exit)
			}
			if row := rowLine(t, rowOf(t, got, "custody.ledger")); row != "abstain unsupported_artifact" {
				t.Errorf("custody.ledger %s, want abstain unsupported_artifact", row)
			}
			gotChecks, wantChecks := get(t, got, "checks").A, get(t, want, "checks").A
			if len(gotChecks) != len(wantChecks) {
				t.Fatalf("%d rows, the corpus states %d", len(gotChecks), len(wantChecks))
			}
			for i, g := range gotChecks {
				if str(t, g, "id") != "custody.ledger" && canonicalOf(t, g) != canonicalOf(t, wantChecks[i]) {
					t.Errorf("row %d: %s, the corpus states %s", i, canonicalOf(t, g), canonicalOf(t, wantChecks[i]))
				}
			}
			for _, k := range get(t, want, "summary").Keys() {
				if k == "outcomes" {
					continue
				}
				if g, w := canonicalOf(t, get(t, got, "summary", k)), canonicalOf(t, get(t, want, "summary", k)); g != w {
					t.Errorf("summary.%s %s, the corpus states %s", k, g, w)
				}
			}
			// custody.ledger moves from not-checked to abstain.
			gotN, wantN := get(t, got, "summary", "outcomes"), get(t, want, "summary", "outcomes")
			for k, delta := range map[string]float64{"checked-correct": 0, "checked-wrong": 0, "not-checked": -1, "abstain": 1} {
				if get(t, gotN, k).N != get(t, wantN, k).N+delta {
					t.Errorf("summary.outcomes.%s %v, want %v", k, get(t, gotN, k).N, get(t, wantN, k).N+delta)
				}
			}
			for _, allow := range [][]string{{"--allow-unchecked"}, {"--allow-unchecked-reason", "unsupported_artifact"}} {
				if exit, _ := run(d, allow...); exit != 0 {
					t.Errorf("%v: exit %d, want 0", allow, exit)
				}
			}
		})
	}

	// The row and its mirror entry both left out: nothing in the bundle
	// names a ledger row, and the case is the corpus's own again.
	if exit, got := run(base); exit != 0 || rowLine(t, rowOf(t, got, "custody.ledger")) != "not-checked not_applicable" {
		t.Errorf("no mirror entry: exit %d, custody.ledger %s", exit, rowLine(t, rowOf(t, got, "custody.ledger")))
	}
}
