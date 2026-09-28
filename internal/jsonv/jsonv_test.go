package jsonv

import (
	"math"
	"testing"
)

func TestIntegerRule(t *testing.T) {
	cases := []struct {
		in string
		n  uint64
		ok bool
	}{
		{"3", 3, true}, {"3.0", 3, true}, {"1e0", 1, true}, {"-0", 0, true}, {"9007199254740991", 1<<53 - 1, true},
		{"9007199254740992", 0, false}, {"true", 0, false}, {`"3"`, 0, false}, {"2.5", 0, false}, {"-1", 0, false},
		{"1e400", 0, false}, {"null", 0, false},
	}
	for _, c := range cases {
		v, err := Parse([]byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		n, ok := v.Uint53()
		if ok != c.ok || (ok && n != c.n) {
			t.Errorf("%s: %d %v", c.in, n, ok)
		}
	}
	v, _ := Parse([]byte("1e400"))
	if !math.IsInf(v.N, 1) {
		t.Errorf("overflow reads as +Inf")
	}
}

func TestStrings(t *testing.T) {
	v, err := Parse([]byte(`"a\ud800b"`))
	if err != nil || !v.Lone || v.S != "a\xed\xa0\x80b" {
		t.Errorf("lone high surrogate: %q %v %v", v.S, v.Lone, err)
	}
	v, _ = Parse([]byte(`"😀"`))
	if v.Lone || v.S != "😀" {
		t.Errorf("pair: %q", v.S)
	}
	v, _ = Parse([]byte(`"\udc00\ud800"`))
	if !v.Lone {
		t.Errorf("reversed pair is two lone surrogates")
	}
	if _, ok := v.Str(); ok {
		t.Errorf("Str refuses a lone surrogate")
	}
	for _, bad := range []string{"\"a\x01\"", `"\x"`, `"\u12"`, "\"\xff\"", "\xef\xbb\xbf{}", `{"a":1,}`, `[1,]`, `01`, `1.`, `.5`, `+1`, `{} {}`, ``, `nul`} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestDuplicateKeys(t *testing.T) {
	v, err := Parse([]byte(`{"a":1,"b":2,"a":3}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(v.O) != 2 || v.O[0].Key != "a" || v.O[0].Value.N != 3 {
		t.Errorf("a repeated key keeps its first position and its last value: %+v", v.O)
	}
}

func TestDepth(t *testing.T) {
	deep := make([]byte, 0, 2*MaxDepth+2)
	for i := 0; i <= MaxDepth; i++ {
		deep = append(deep, '[')
	}
	for i := 0; i <= MaxDepth; i++ {
		deep = append(deep, ']')
	}
	if _, err := Parse(deep); err == nil {
		t.Errorf("nesting past MaxDepth accepted")
	}
}
