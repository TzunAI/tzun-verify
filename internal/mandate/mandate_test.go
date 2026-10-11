// SPDX-License-Identifier: BSD-3-Clause-Clear

package mandate

import (
	"encoding/base64"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

func parse(t *testing.T, s string) *jsonv.Value {
	t.Helper()
	v, err := jsonv.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestPredicateTypes: eq and ne compare a subject of the value's own type
// only (Record §9.8): the number 0 is never false, "1" is never 1, and a
// fraction or a negative number is no integer at all.
func TestPredicateTypes(t *testing.T) {
	for _, c := range []struct {
		pred, payload string
		want          Truth
	}{
		{`{"path":"/aiOutput/v","op":"eq","value":false,"quant":null}`, `{"aiOutput":{"v":0}}`, False},
		{`{"path":"/aiOutput/v","op":"ne","value":false,"quant":null}`, `{"aiOutput":{"v":0}}`, True},
		{`{"path":"/aiOutput/v","op":"eq","value":0,"quant":null}`, `{"aiOutput":{"v":false}}`, False},
		{`{"path":"/aiOutput/v","op":"eq","value":1,"quant":null}`, `{"aiOutput":{"v":"1"}}`, False},
		{`{"path":"/aiOutput/v","op":"eq","value":"1","quant":null}`, `{"aiOutput":{"v":"1"}}`, True},
		{`{"path":"/aiOutput/v","op":"eq","value":1,"quant":null}`, `{"aiOutput":{"v":-1}}`, Undeterminable},
		{`{"path":"/aiOutput/v","op":"eq","value":1,"quant":null}`, `{"aiOutput":{"v":0.5}}`, Undeterminable},
		{`{"path":"/aiOutput/v","op":"eq","value":1,"quant":null}`, `{"aiOutput":{"v":{"x":1}}}`, Undeterminable},
		{`{"path":"/aiOutput/v","op":"in","value":["a"],"quant":"any"}`, `{"aiOutput":{"v":[null,"a"]}}`, True},
		{`{"path":"/aiOutput/v","op":"in","value":["a"],"quant":"all"}`, `{"aiOutput":{"v":[null,"a"]}}`, Undeterminable},
		{`{"path":"/aiOutput/v","op":"in","value":["a"],"quant":"all"}`, `{"aiOutput":{"v":[["a"]]}}`, Undeterminable},
	} {
		p, ok := ParsePredicate(parse(t, c.pred), true)
		if !ok {
			t.Fatalf("%s: not well formed", c.pred)
		}
		if got := p.Evaluate(parse(t, c.payload)); got != c.want {
			t.Errorf("%s over %s: %s, want %s", c.pred, c.payload, got, c.want)
		}
	}
}

// TestGlob: the glob of Record §9.8 over code points and whole segments.
func TestGlob(t *testing.T) {
	for _, c := range []struct {
		pattern, subject string
		want             bool
	}{
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"a/**", "a", true},
		{"**", "", true},
		{"a/*", "a/x/y", false},
		{"a?c", "a😀c", true},
		{"a??c", "a😀c", false},
		{"*.json", "x.json", true},
		{"*.json", "dir/x.json", false},
		{"a*b*c", "abxbc", true},
		{"a*b*c", "abxb", false},
	} {
		if got := Glob(c.pattern, c.subject); got != c.want {
			t.Errorf("%q ~ %q: %v", c.pattern, c.subject, got)
		}
	}
}

// TestAssertionDER: an ES256 signature is a SEQUENCE of two INTEGERs and
// nothing more: a sequence whose stated length leaves its second INTEGER
// outside it has no assertion digest.
func TestAssertionDER(t *testing.T) {
	enc := base64.RawURLEncoding
	der := []byte{0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07}
	a := func(sig []byte) *jsonv.Value {
		return parse(t, `{"algorithm":"ES256","authenticatorData":"AA","clientDataJSON":"e30","signature":"`+enc.EncodeToString(sig)+`"}`)
	}
	if _, ok := AssertionDigest(a(der)); !ok {
		t.Fatal("a minimal DER signature has no digest")
	}
	short := append([]byte{}, der...)
	short[1] = 0x03
	if _, ok := AssertionDigest(a(short)); ok {
		t.Error("a sequence shorter than its INTEGERs has a digest")
	}
	long := append(append([]byte{}, der...), 0x00)
	if _, ok := AssertionDigest(a(long)); ok {
		t.Error("a byte after the sequence has a digest")
	}
}
