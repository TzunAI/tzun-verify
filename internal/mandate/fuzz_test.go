// SPDX-License-Identifier: BSD-3-Clause-Clear

package mandate

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// mandateVectors is what the fuzz seeds take from mandate-vectors.json.
type mandateVectors struct {
	Documents []struct {
		Document json.RawMessage `json:"document"`
	} `json:"documents"`
	Predicates []struct {
		Predicate json.RawMessage `json:"predicate"`
		Payload   json.RawMessage `json:"payload"`
	} `json:"predicates"`
}

func readMandateVectors(f *testing.F) mandateVectors {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "mandate-vectors.json"))
	if err != nil {
		f.Fatal(err)
	}
	var v mandateVectors
	if err := json.Unmarshal(b, &v); err != nil {
		f.Fatal(err)
	}
	return v
}

// refGlob is the glob of Record §9.8 as it reads, by recursion over
// segments and code points: "**" matches any run of whole segments, none
// included; "*" any run of code points within a segment and "?" one.
func refGlob(pattern, subject string) bool {
	ps, ss := strings.Split(pattern, "/"), strings.Split(subject, "/")
	memo := map[[2]int]bool{}
	var segs func(i, j int) bool
	segs = func(i, j int) bool {
		if r, ok := memo[[2]int{i, j}]; ok {
			return r
		}
		var r bool
		switch {
		case i == len(ps):
			r = j == len(ss)
		case ps[i] == "**":
			r = segs(i+1, j) || j < len(ss) && segs(i, j+1)
		default:
			r = j < len(ss) && refSegment([]rune(ps[i]), []rune(ss[j])) && segs(i+1, j+1)
		}
		memo[[2]int{i, j}] = r
		return r
	}
	return segs(0, 0)
}

func refSegment(p, s []rune) bool {
	memo := map[[2]int]bool{}
	var at func(i, j int) bool
	at = func(i, j int) bool {
		if r, ok := memo[[2]int{i, j}]; ok {
			return r
		}
		var r bool
		switch {
		case i == len(p):
			r = j == len(s)
		case p[i] == '*':
			r = at(i+1, j) || j < len(s) && at(i, j+1)
		default:
			r = j < len(s) && (p[i] == '?' || p[i] == s[j]) && at(i+1, j+1)
		}
		memo[[2]int{i, j}] = r
		return r
	}
	return at(0, 0)
}

// FuzzGlob holds Glob, the iterative two-pointer matcher, to the recursive
// reading of §9.8 above on any pattern and subject that are UTF-8.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzGlob fuzzes.
func FuzzGlob(f *testing.F) {
	for _, c := range [][2]string{
		{"a/**/b", "a/b"}, {"a/**/b", "a/x/y/b"}, {"a/**", "a"}, {"**", ""}, {"a/*", "a/x/y"}, {"a?c", "a😀c"},
		{"a??c", "a😀c"}, {"*.json", "dir/x.json"}, {"a*b*c", "abxbc"}, {"**/a/**/b/**", "x/a/y/a/b/z"},
		{"*/**/*", "a"}, {"a/**/**/b", "a/b/b"}, {"**/*?", "x/"},
	} {
		f.Add(c[0], c[1])
	}
	v := readMandateVectors(f)
	for _, p := range v.Predicates {
		var pred struct {
			Op    string `json:"op"`
			Value any    `json:"value"`
		}
		var payload struct {
			AIOutput map[string]any `json:"aiOutput"`
		}
		if json.Unmarshal(p.Predicate, &pred) != nil || pred.Op != "glob" || json.Unmarshal(p.Payload, &payload) != nil {
			continue
		}
		pats, _ := pred.Value.([]any)
		for _, pat := range pats {
			for _, k := range slices.Sorted(maps.Keys(payload.AIOutput)) {
				ps, ok1 := pat.(string)
				ss, ok2 := payload.AIOutput[k].(string)
				if ok1 && ok2 {
					f.Add(ps, ss)
				}
			}
		}
	}
	f.Fuzz(func(t *testing.T, pattern, subject string) {
		if !utf8.ValidString(pattern) || !utf8.ValidString(subject) {
			return
		}
		if got, want := Glob(pattern, subject), refGlob(pattern, subject); got != want {
			t.Fatalf("Glob(%q, %q) = %v; §9.8 reads %v", pattern, subject, got, want)
		}
	})
}

// FuzzPointer holds Pointer to RFC 6901 with only ~0 and ~1 (§9.8) on any
// string: the tokens it reads, escaped again and joined, are the pointer.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzPointer fuzzes.
func FuzzPointer(f *testing.F) {
	for _, s := range []string{"", "/", "//", "/aiOutput/a~1b/~0", "/a~", "/a~2", "a/b", "/0/-/01"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		toks, ok := Pointer(p)
		if !ok {
			return
		}
		var b strings.Builder
		for _, tok := range toks {
			b.WriteString("/" + strings.ReplaceAll(strings.ReplaceAll(tok, "~", "~0"), "/", "~1"))
		}
		if b.String() != p {
			t.Fatalf("%q reads as %q, which writes %q", p, toks, b.String())
		}
	})
}

// duals are the operations whose results are each other's negation on every
// subject either can decide, and the quantifiers that turn into each other
// under negation (De Morgan).
var (
	dualOp    = map[string]string{"eq": "ne", "ne": "eq", "in": "notIn", "notIn": "in", "lt": "ge", "ge": "lt", "le": "gt", "gt": "le"}
	dualQuant = map[string]string{"": "", "all": "any", "any": "all"}
)

// FuzzPredicate reads any predicate and payload under §9.8. A predicate the
// §9.7 restriction admits is admitted without it; it evaluates to one of
// the three truths; and its dual (eq and ne, in and notIn, lt and ge, le and
// gt, with all and any exchanged) evaluates to its negation, undeterminable
// to undeterminable.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzPredicate fuzzes.
func FuzzPredicate(f *testing.F) {
	for _, p := range readMandateVectors(f).Predicates {
		f.Add([]byte(p.Predicate), []byte(p.Payload))
	}
	f.Fuzz(func(t *testing.T, pred, payload []byte) {
		pv, err := jsonv.Parse(pred)
		if err != nil {
			return
		}
		p, ok := ParsePredicate(pv, false)
		if _, restricted := ParsePredicate(pv, true); restricted && !ok {
			t.Fatalf("admitted under the restriction and refused without it")
		}
		if !ok {
			return
		}
		doc, err := jsonv.Parse(payload)
		if err != nil {
			return
		}
		got := p.Evaluate(doc)
		if got != True && got != False && got != Undeterminable {
			t.Fatalf("truth %d", got)
		}
		dop, has := dualOp[p.Op]
		if !has {
			return
		}
		d := p
		d.Op, d.Quant = dop, dualQuant[p.Quant]
		want := map[Truth]Truth{True: False, False: True, Undeterminable: Undeterminable}[got]
		if dual := d.Evaluate(doc); dual != want {
			t.Fatalf("%s/%q is %s and its dual %s/%q is %s", p.Op, p.Quant, got, d.Op, d.Quant, dual)
		}
	})
}

// FuzzParseDocument reads any value as a mandate document (§9.7). A
// document the writer's rules admit (prepare) the reader's admit too, its
// canonical form is within MaxDocumentBytes, and its digest is
// DocumentDigest's.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzParseDocument fuzzes.
func FuzzParseDocument(f *testing.F) {
	for _, d := range readMandateVectors(f).Documents {
		f.Add([]byte(d.Document))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := jsonv.Parse(data)
		if err != nil {
			return
		}
		d, ok := ParseDocument(v, false)
		if _, prepared := ParseDocument(v, true); prepared && !ok {
			t.Fatalf("admitted under the writer's rules and refused under the reader's")
		}
		if !ok {
			return
		}
		b, err := canonical.Serialize(v)
		if err != nil || len(b) > MaxDocumentBytes {
			t.Fatalf("a document of %d canonical bytes (%v)", len(b), err)
		}
		if digest, ok := DocumentDigest(v); !ok || digest != d.Digest {
			t.Fatalf("digest %s, DocumentDigest %s", d.Digest, digest)
		}
	})
}
