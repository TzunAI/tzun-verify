// SPDX-License-Identifier: BSD-3-Clause-Clear

package jsonv

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParse holds Parse to its package comment on any input. It never
// panics: Parse recovers from a panic and returns it as an error, and every
// refusal of its own names an offset, so an error that does not is a panic
// here. It accepts exactly the texts encoding/json accepts, once the input is
// UTF-8 and nests no deeper than MaxDepth. A tree it returns agrees with
// encoding/json's reading of the same text, member by member, once each lone
// surrogate it keeps is read as U+FFFD, as encoding/json reads one, and
// keeps the invariants its readers rely on: a number's Raw is its source
// text and N the double that text reads as, a string is UTF-8 exactly when
// it holds no lone surrogate, and an object holds each key once. Since that
// comparison cannot tell a kept lone surrogate from one replaced by U+FFFD,
// the tree holds U+FFFD only where the text writes one, as its UTF-8 bytes
// or as the escape \uFFFD.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzParse fuzzes.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		`null`, `true`, `false`, `0`, `-0`, `3.0`, `1e400`, `-1e-400`, `9007199254740993`, `""`,
		`"a\ud800b"`, `"\udc00\ud800"`, `"😀"`, `"\ud83dA"`, `"😀"`, `"\u0000"`,
		`{"a":1,"b":2,"a":3}`, `{"\ud800":1,"\ud800":2}`, `{"a\udfff":[1,"\ud800"]}`, `{"\ud800":1,"\udc00":2,"\ufffd":3}`, `[[],{},[{}]]`, " \t\r\n[1 , 2]\n",
		"\xef\xbb\xbf{}", "\"\xff\"", `{"a":1,}`, `[1,]`, `01`, `1.`, `.5`, `+1`, `{} {}`, ``, `nul`, `"\x"`,
		strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth),
		strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1),
	} {
		f.Add([]byte(s))
	}
	addVectorSeeds(f, 64<<10)
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Parse(data)
		if err != nil {
			msg := err.Error()
			if !strings.HasPrefix(msg, "jsonv: offset ") && msg != "jsonv: input is not UTF-8" {
				t.Fatalf("Parse recovered from a panic: %v", err)
			}
			if v != nil {
				t.Fatalf("Parse returned a value with its error %v", err)
			}
			if utf8.Valid(data) && json.Valid(data) && !strings.Contains(msg, "nesting deeper than") {
				t.Fatalf("encoding/json accepts what Parse refuses: %v", err)
			}
			return
		}
		if !json.Valid(data) {
			t.Fatalf("Parse accepts what encoding/json refuses")
		}
		checkTree(t, v, 0)
		if got, written := countFFFD(v), fffdWritten(data); got > written {
			t.Fatalf("U+FFFD %d times in the tree, written %d times in the text", got, written)
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		var x any
		if err := dec.Decode(&x); err != nil {
			t.Fatalf("encoding/json cannot decode what both accept: %v", err)
		}
		agree(t, "$", v, x)
	})
}

// checkTree checks the invariants of one parsed value and everything in it.
func checkTree(t *testing.T, v *Value, depth int) {
	t.Helper()
	if v == nil {
		t.Fatalf("a nil value in the tree")
	}
	switch v.Kind {
	case Null, Bool:
	case Number:
		f, err := strconv.ParseFloat(v.Raw, 64)
		if v.Raw == "" || math.IsNaN(v.N) || math.Float64bits(f) != math.Float64bits(v.N) {
			t.Fatalf("number %q reads as %v, which its text does not (%v, %v)", v.Raw, v.N, f, err)
		}
	case String:
		if v.Lone == utf8.ValidString(v.S) {
			t.Fatalf("string %q: Lone is %v", v.S, v.Lone)
		}
	case Array:
		if depth >= MaxDepth || v.A == nil {
			t.Fatalf("array at depth %d (nil %v)", depth, v.A == nil)
		}
		for _, e := range v.A {
			checkTree(t, e, depth+1)
		}
	case Object:
		if depth >= MaxDepth {
			t.Fatalf("object at depth %d", depth)
		}
		seen := map[string]bool{}
		for i, m := range v.O {
			if seen[m.Key] {
				t.Fatalf("key %q twice", m.Key)
			}
			seen[m.Key] = true
			if m.KeyLone == utf8.ValidString(m.Key) {
				t.Fatalf("key %q: KeyLone is %v", m.Key, m.KeyLone)
			}
			if got, ok := v.Get(m.Key); !m.KeyLone && (!ok || got != v.O[i].Value) {
				t.Fatalf("Get(%q) does not return the member's value", m.Key)
			}
			checkTree(t, m.Value, depth+1)
		}
	default:
		t.Fatalf("unknown kind %d", v.Kind)
	}
}

// countFFFD is the number of U+FFFD in the strings and keys of a tree.
func countFFFD(v *Value) int {
	n := 0
	switch v.Kind {
	case String:
		n = strings.Count(v.S, "\uFFFD")
	case Array:
		for _, e := range v.A {
			n += countFFFD(e)
		}
	case Object:
		for _, m := range v.O {
			n += strings.Count(m.Key, "\uFFFD") + countFFFD(m.Value)
		}
	}
	return n
}

// fffdWritten is the number of times a UTF-8 text writes U+FFFD: as its
// UTF-8 bytes, or as the escape \uFFFD with hex digits of either case. It
// may count more (an escaped backslash followed by uFFFD), never fewer, so a
// tree holding more U+FFFD than this made one of its own.
func fffdWritten(data []byte) int {
	lower := bytes.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, data)
	return bytes.Count(data, []byte("\uFFFD")) + bytes.Count(lower, []byte(`\ufffd`))
}

// agree compares a parsed value with encoding/json's decoding of the same
// text (numbers as json.Number), each lone surrogate in a string or key read
// as U+FFFD (asFFFD). An object two of whose keys read the same that way,
// such as "\ud800" and "\udc00", has one member there and two here, and
// which value encoding/json kept depends on the order of the text, which
// the tree does not keep; its members are not compared.
func agree(t *testing.T, at string, v *Value, x any) {
	t.Helper()
	switch v.Kind {
	case Null:
		if x != nil {
			t.Fatalf("%s: null here, %T there", at, x)
		}
	case Bool:
		if b, ok := x.(bool); !ok || b != v.B {
			t.Fatalf("%s: %v here, %v there", at, v.B, x)
		}
	case Number:
		if n, ok := x.(json.Number); !ok || string(n) != v.Raw {
			t.Fatalf("%s: number %q here, %v there", at, v.Raw, x)
		}
	case String:
		if s, ok := x.(string); !ok || s != asFFFD(v.S) {
			t.Fatalf("%s: string %q here, %q there", at, v.S, x)
		}
	case Array:
		a, ok := x.([]any)
		if !ok || len(a) != len(v.A) {
			t.Fatalf("%s: array of %d here, %T there", at, len(v.A), x)
		}
		for i := range a {
			agree(t, at+"["+strconv.Itoa(i)+"]", v.A[i], a[i])
		}
	case Object:
		o, ok := x.(map[string]any)
		if !ok {
			t.Fatalf("%s: object here, %T there", at, x)
		}
		read := map[string]bool{}
		for _, m := range v.O {
			if read[asFFFD(m.Key)] {
				return
			}
			read[asFFFD(m.Key)] = true
		}
		if len(o) != len(v.O) {
			t.Fatalf("%s: %d members here, %d there", at, len(v.O), len(o))
		}
		for _, m := range v.O {
			e, ok := o[asFFFD(m.Key)]
			if !ok {
				t.Fatalf("%s: member %q only here", at, m.Key)
			}
			agree(t, at+"."+m.Key, m.Value, e)
		}
	}
}

// asFFFD is s with each lone surrogate Parse keeps, written as generalized
// UTF-8 (0xED, then 0xA0 to 0xBF, then a continuation byte), replaced by
// U+FFFD. Parse refuses input that is not UTF-8, so nothing else in a string
// it returns is outside UTF-8.
func asFFFD(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			b.WriteString("\uFFFD")
			i += 3
			continue
		}
		_, n := utf8.DecodeRuneInString(s[i:])
		b.WriteString(s[i : i+n])
		i += n
	}
	return b.String()
}

// addVectorSeeds adds the conformance vector files up to max bytes, and a
// bundle and its inputs from each bundle case, as seeds.
func addVectorSeeds(f *testing.F, max int64) {
	dir := filepath.Join("..", "..", "testdata", "vectors")
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	cases, _ := filepath.Glob(filepath.Join(dir, "bundle-b1", "*", "*.json"))
	for _, p := range append(files, cases...) {
		if st, err := os.Stat(p); err != nil || st.Size() > max {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
}
