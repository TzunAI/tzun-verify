// SPDX-License-Identifier: BSD-3-Clause-Clear

package corpus

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// anchoredBase is the corpus's anchored-with-newer case with its record
// timestamp removed, a bundle that exits 0, and the flags its inputs give.
func anchoredBase(t *testing.T) (doc, []string) {
	t.Helper()
	dir := filepath.Join(vectorDir, "bundle-b1", "anchored-with-newer")
	in, err := jsonv.Parse(readCase(t, dir, "inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	flags := args(t, in, t.TempDir())
	base := loadDoc(t, filepath.Join(dir, "bundle.json"))
	delete(sub(base, "envelope", "nonRepudiation"), "rfc3161Token")
	return base, flags
}

// TestNewerAnchorEdges covers the rows of Anchor §10.8 on bundles
// the conformance corpus does not carry. A second checkpoint whose own
// anchor the bundle does not compose authenticates nothing: there is no
// anchor.newer row (Bundle §7.5 reports it when a checkpoint
// carries the composed members), and each consistency
// row is blocked by anchor.newer. A checkpoint whose anchor size names no
// carried anchor checkpoint fails anchor.newer's shape (malformed_anchor).
func TestNewerAnchorEdges(t *testing.T) {
	base, flags := anchoredBase(t)
	delete(sub(base, "envelope", "nonRepudiation"), "rfc3161Token")
	if exit, _ := runDoc(t, base, flags...); exit != 0 {
		t.Fatalf("base: exit %d", exit)
	}
	evidence := ""
	for origin, l := range sub(base, "anchoring") {
		if cps := l.(doc)["checkpoints"].([]any); len(cps) == 2 {
			if _, ok := cps[1].(doc)["logPath"]; ok {
				evidence = origin
			}
		}
	}
	if evidence == "" {
		t.Fatal("no evidence log with a composed checkpoint in the base case")
	}
	edit := func(f func(cp doc)) doc {
		d := clone(t, base)
		cp := sub(d, "anchoring", evidence)["checkpoints"].([]any)[1].(doc)
		f(cp)
		return d
	}
	for _, c := range []struct {
		name   string
		bundle doc
		newer  string
		exit   int
	}{
		{"no composed members", edit(func(cp doc) {
			for _, k := range []string{"logPath", "anchorLeafIndex", "anchorSize", "anchorPath"} {
				delete(cp, k)
			}
		}), "", 4},
		{"an anchor size the bundle does not carry", edit(func(cp doc) { cp["anchorSize"] = 99 }), "checked-wrong malformed_anchor", 1},
	} {
		exit, rows := runDoc(t, c.bundle, flags...)
		if exit != c.exit || rows["anchor.newer"] != c.newer {
			t.Errorf("%s: exit %d, anchor.newer %q", c.name, exit, rows["anchor.newer"])
		}
		n := 0
		for id, row := range rows {
			if strings.HasPrefix(id, "anchor.consistency[") {
				n++
				if row != "not-checked blocked_by:anchor.newer" {
					t.Errorf("%s: %s %q", c.name, id, row)
				}
			}
		}
		if n != 2 {
			t.Errorf("%s: %d consistency rows, want one per origin", c.name, n)
		}
	}
}

// TestCarriedBodiesAreReadable: every carried checkpoint body parses and
// names the origin it sits under (Bundle §7.1); otherwise the bundle
// cannot be read, exit 2.
func TestCarriedBodiesAreReadable(t *testing.T) {
	base, flags := anchoredBase(t)
	for origin := range sub(base, "anchoring") {
		for _, body := range []string{"not a checkpoint", "other.tzun/0/anchors\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"} {
			d := clone(t, base)
			sub(d, "anchoring", origin)["checkpoints"].([]any)[0].(doc)["body"] = body
			exit, rows := runDoc(t, d, flags...)
			if exit != 2 || rows["bundle"] != "checked-wrong malformed_bundle" || len(rows) != 1 {
				t.Errorf("%s, body %q: exit %d %v", origin, body, exit, rows)
			}
		}
	}
}

// TestConsistencyNeedsAuthenticatedBodies: a log's two carried bodies are
// compared only when anchor or anchor.newer authenticated each
// (Bundle §7.6, Anchor §10.8). A
// body of the same log that neither authenticates, here another history of
// the evidence log at the record's size, leaves the row blocked by
// anchor.newer rather than compared.
func TestConsistencyNeedsAuthenticatedBodies(t *testing.T) {
	base, flags := anchoredBase(t)
	fork := loadDoc(t, filepath.Join(vectorDir, "bundle-b1", "split-view", "bundle.json"))

	var origin string
	for o, l := range sub(base, "anchoring") {
		if _, ok := l.(doc)["checkpoints"].([]any)[1].(doc)["logPath"]; ok {
			origin = o
		}
	}
	other := sub(fork, "anchoring", origin)["checkpoints"].([]any)[1].(doc)["body"]
	d := clone(t, base)
	sub(d, "anchoring", origin)["checkpoints"].([]any)[0].(doc)["body"] = other
	exit, rows := runDoc(t, d, flags...)
	if got := rows["anchor.consistency["+origin+"]"]; got != "not-checked blocked_by:anchor.newer" || exit != 4 {
		t.Errorf("an unauthenticated body: %q, exit %d\n%v", got, exit, rows)
	}
}

// TestPredecessor: record.chainLink names the previous record of the chain,
// and a predecessor at any other sequence number is refused.
func TestPredecessor(t *testing.T) {
	base := loadDoc(t, filepath.Join(vectorDir, "bundle-b1", "unanchored-awaiting-epoch", "bundle.json"))
	if _, rows := runDoc(t, base, "--no-publishers"); rows["record.chainLink"] != "checked-correct" {
		t.Fatalf("base: %q", rows["record.chainLink"])
	}
	for _, c := range []struct {
		name string
		edit func(d doc)
		want string
	}{
		{"a predecessor two back", func(d doc) { sub(d, "chain", "predecessor")["sequenceNumber"] = 2 }, "checked-wrong predecessor_mismatch"},
		{"no predecessor", func(d doc) { sub(d, "chain")["predecessor"] = nil }, "not-checked not_in_bundle:predecessor"},
		{"no link", func(d doc) { sub(d, "envelope", "integrity")["chainLink"] = nil }, "checked-wrong chain_link_missing"},
		{"another predecessor digest", func(d doc) { sub(d, "chain", "predecessor")["canonicalDigest"] = strings.Repeat("0", 64) },
			"checked-wrong chain_link_mismatch"},
	} {
		d := clone(t, base)
		c.edit(d)
		if _, rows := runDoc(t, d, "--no-publishers"); rows["record.chainLink"] != c.want {
			t.Errorf("%s: %q, want %q", c.name, rows["record.chainLink"], c.want)
		}
	}
}
