package bundle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
)

func loadVectors(t *testing.T) *jsonv.Value {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "signoff-expectation-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsonv.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestStatementDigestVectors: the statement digest and challenge of
// Record §6.4, and no digest for a statement outside its value
// domain (signoff-expectation-vectors.json, statementDigests).
func TestStatementDigestVectors(t *testing.T) {
	cases, _ := loadVectors(t).Get("statementDigests")
	for _, c := range cases.A {
		name, _ := member(c, "case").Str()
		st, _ := c.Get("statement")
		d, ok := statementDigest(st)
		want, hasWant := member(c, "digest").Str()
		switch {
		case ok != hasWant:
			t.Errorf("%s: digest %v, vectors say %v", name, ok, hasWant)
		case ok && d != want:
			t.Errorf("%s: digest %s, want %s", name, d, want)
		case ok:
			if ch, _ := member(c, "challenge").Str(); challenge(statementDomain, d) != ch {
				t.Errorf("%s: challenge %s, want %s", name, challenge(statementDomain, d), ch)
			}
		}
	}
	if len(cases.A) == 0 {
		t.Fatal("no statement digests")
	}
}

// TestExpectationShapes: the grammar of Record §6.2
// (signoff-expectation-vectors.json, shapes). Any violation is
// malformed_signoff_expectation.
func TestExpectationShapes(t *testing.T) {
	cases, _ := loadVectors(t).Get("shapes")
	for _, c := range cases.A {
		name, _ := member(c, "case").Str()
		value, _ := c.Get("value")
		payload := report.Obj("signoffExpectation", value)
		_, ok := parseExpectation(payload)
		if want := member(c, "violation") == nil; ok != want {
			t.Errorf("%s: accepted %v, want %v", name, ok, want)
		}
	}
	if _, ok := parseExpectation(report.Obj()); !ok {
		t.Error("an absent key is refused; it reads as null")
	}
}
