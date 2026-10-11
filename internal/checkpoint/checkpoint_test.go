// SPDX-License-Identifier: BSD-3-Clause-Clear

package checkpoint

import "testing"

func TestParseOrigin(t *testing.T) {
	good := map[string]Kind{
		"a.b/0123/anchors":                 KindAnchors,
		"a.b/0123/k2":                      KindOther,
		"a.b/0123/evidence/64656661756c74": KindEvidence,
		"log.tzun.ai/0123/acc22df3":        KindOther,
	}
	for s, k := range good {
		o, ok := ParseOrigin(s)
		if !ok || o.Kind != k {
			t.Errorf("%s: %v %v", s, o, ok)
		}
	}
	for _, s := range []string{
		"a.b/0123/a+b", "a+b/0123/anchors", "a.b/01 23/anchors", "a.b/0123/anchörs", "a.b/0123/evidence",
		"a.b/0123/evidence/zz", "a.b/0123/x/64", "a.b//anchors", "a.b/0123", "a.b/0123/evidence/64/65", "/0123/anchors",
		"a.b/0123/evidence/64656661756C74", "a.b/0123/\x7f",
	} {
		if _, ok := ParseOrigin(s); ok {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestBindPlus(t *testing.T) {
	// A '+' is refused in an origin even where the body grammar is not
	// applied first.
	if r := Bind("a.b/0123/anchors", "a.b/0123/a+b", nil, true); r.Result != BindNotInDomain {
		t.Errorf("%+v", r)
	}
}

func TestBindPlatformNamespaces(t *testing.T) {
	chain := "user-123"
	for _, c := range []struct {
		anchor, log string
		want        string
	}{
		// Opaque platform source logs: the chain is left unchecked, in the
		// production and the test namespace alike (Anchor §10.3
		// step 2b).
		{"log.tzun.ai/f005/anchors", "log.tzun.ai/f005/acc22df3", BindOK},
		{"test.log.tzun.ai/f005/anchors", "test.log.tzun.ai/f005/acc22df3", BindOK},
		// A name that extends either is not the platform's.
		{"test.log.tzun.ai.example/f005/anchors", "test.log.tzun.ai.example/f005/acc22df3", BindChainIDMismatch},
		{"staging.log.tzun.ai/f005/anchors", "staging.log.tzun.ai/f005/acc22df3", BindChainIDMismatch},
		{"xlog.tzun.ai/f005/anchors", "xlog.tzun.ai/f005/acc22df3", BindChainIDMismatch},
	} {
		r := Bind(c.anchor, c.log, &chain, true)
		if r.Result != c.want || r.ChainChecked {
			t.Errorf("%s: %+v, want %s", c.log, r, c.want)
		}
	}
	// An evidence log under the test platform namespace is still checked.
	r := Bind("test.log.tzun.ai/f005/anchors", "test.log.tzun.ai/f005/evidence/757365722d313233", &chain, true)
	if r.Result != BindOK || !r.ChainChecked {
		t.Errorf("%+v", r)
	}
}
