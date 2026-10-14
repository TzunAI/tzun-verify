// SPDX-License-Identifier: BSD-3-Clause-Clear

package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// FuzzSerialize holds the serializer to Record §3 on any JSON text: it
// either refuses with one of the three refusals the rules require, or
// writes UTF-8 JSON that reads back as the same value (keys and order of
// members aside, numbers compared as doubles) and that serializes to itself,
// byte for byte, with every object's keys in strictly increasing UTF-16
// order.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzSerialize fuzzes.
func FuzzSerialize(f *testing.F) {
	for _, s := range []string{
		`{"b":1,"a":[true,false,null],"c":{"y":"\u0001","x":"é"}}`, `{"😀":1,"！":2,"":3}`,
		`[1e21,1e-7,100000000000000000000,0.1,-0,5e-324,1.7976931348623157e308]`, `1e400`, `"a\ud800"`,
		`{"a":1,"a":2}`, `"  \u007f"`, `[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]`,
	} {
		f.Add([]byte(s))
	}
	// The inputs of the canonical vectors, each as JSON text.
	if b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "v1.0-canonical-vectors.json")); err == nil {
		var doc struct {
			Vectors []struct {
				Input json.RawMessage `json:"input"`
			} `json:"vectors"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			f.Fatal(err)
		}
		for _, v := range doc.Vectors {
			f.Add([]byte(v.Input))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := jsonv.Parse(data)
		if err != nil {
			return
		}
		c, err := Serialize(v)
		if err != nil {
			if !errors.Is(err, ErrLoneSurrogate) && !errors.Is(err, ErrNonFinite) && !errors.Is(err, ErrDepth) {
				t.Fatalf("a refusal the rules do not name: %v", err)
			}
			return
		}
		if !utf8.Valid(c) || !json.Valid(c) {
			t.Fatalf("not UTF-8 JSON: %q", c)
		}
		w, err := jsonv.Parse(c)
		if err != nil {
			t.Fatalf("the canonical form does not parse: %v", err)
		}
		c2, err := Serialize(w)
		if err != nil || !bytes.Equal(c, c2) {
			t.Fatalf("not a fixed point:\n%s\n%s (%v)", c, c2, err)
		}
		same(t, "$", v, w)
	})
}

// same compares a value with its canonical form read back: members by key,
// keys in strictly increasing order of their UTF-16 code units in the
// canonical form (compared here with slices.Compare, not with the
// serializer's own LessUTF16; the canonical form is UTF-8, so its keys hold
// no lone surrogate), numbers as doubles (-0 is written 0).
func same(t *testing.T, at string, v, w *jsonv.Value) {
	t.Helper()
	if v.Kind != w.Kind {
		t.Fatalf("%s: %v became %v", at, v.Kind, w.Kind)
	}
	switch v.Kind {
	case jsonv.Bool:
		if v.B != w.B {
			t.Fatalf("%s: %v became %v", at, v.B, w.B)
		}
	case jsonv.Number:
		if v.N != w.N {
			t.Fatalf("%s: %v (%s) became %v (%s)", at, v.N, v.Raw, w.N, w.Raw)
		}
	case jsonv.String:
		if v.S != w.S || w.Lone {
			t.Fatalf("%s: %q became %q", at, v.S, w.S)
		}
	case jsonv.Array:
		if len(v.A) != len(w.A) {
			t.Fatalf("%s: %d elements became %d", at, len(v.A), len(w.A))
		}
		for i := range v.A {
			same(t, at+"["+strconv.Itoa(i)+"]", v.A[i], w.A[i])
		}
	case jsonv.Object:
		if len(v.O) != len(w.O) {
			t.Fatalf("%s: %d members became %d", at, len(v.O), len(w.O))
		}
		for i, m := range w.O {
			if m.KeyLone {
				t.Fatalf("%s: key %q holds a lone surrogate", at, m.Key)
			}
			if i > 0 && slices.Compare(utf16.Encode([]rune(w.O[i-1].Key)), utf16.Encode([]rune(m.Key))) >= 0 {
				t.Fatalf("%s: key %q after %q", at, m.Key, w.O[i-1].Key)
			}
			orig, ok := v.Get(m.Key)
			if !ok {
				t.Fatalf("%s: key %q appeared", at, m.Key)
			}
			same(t, at+"."+m.Key, orig, m.Value)
		}
	}
}

// FuzzFormatNumber holds FormatNumber to ECMAScript Number::toString on any
// double: NaN and the infinities are refused, and every finite double is
// written as a JSON number that reads back as the same double, with the
// digits of the shortest form that does (strconv's), in decimal notation
// exactly when its decimal exponent is within [-6, 20].
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzFormatNumber fuzzes.
func FuzzFormatNumber(f *testing.F) {
	for _, x := range []float64{0, math.Copysign(0, -1), 1, -1, 0.5, 1e-6, 1e-7, 1e20, 1e21, 1.5e-7, 123456789012345680000,
		0.30000000000000004, 5e-324, 1.7976931348623157e308, 9007199254740991, 123.456, 1e300, 2.5e21, math.NaN(), math.Inf(1), math.Inf(-1)} {
		f.Add(x)
	}
	f.Fuzz(func(t *testing.T, x float64) {
		s, err := FormatNumber(x)
		if math.IsNaN(x) || math.IsInf(x, 0) {
			if !errors.Is(err, ErrNonFinite) {
				t.Fatalf("%v: %q, %v", x, s, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("%v: %v", x, err)
		}
		v, err := jsonv.Parse([]byte(s))
		if err != nil || v.Kind != jsonv.Number || v.N != x {
			t.Fatalf("%v is written %q, which reads back as %v (%v)", x, s, v, err)
		}
		if x == 0 {
			if s != "0" {
				t.Fatalf("zero is written %q", s)
			}
			return
		}
		shortest := strconv.FormatFloat(math.Abs(x), 'e', -1, 64)
		_, e, _ := strings.Cut(shortest, "e")
		exp, _ := strconv.Atoi(e)
		exponential := strings.Contains(s, "e")
		if want := exp <= -7 || exp >= 21; exponential != want {
			t.Fatalf("%v (exponent %d) is written %q", x, exp, s)
		}
		if got, want := significand(s), significand(shortest); got != want {
			t.Fatalf("%v is written %q, with the digits %s; the shortest form %s has %s", x, s, got, shortest, want)
		}
	})
}

// significand is the significant digits of a number's text: no sign, point
// or exponent, and no leading or trailing zeros.
func significand(s string) string {
	s, _, _ = strings.Cut(strings.TrimPrefix(s, "-"), "e")
	return strings.Trim(strings.Replace(s, ".", "", 1), "0")
}
