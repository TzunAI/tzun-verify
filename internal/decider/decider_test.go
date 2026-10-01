package decider

import (
	"strings"
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

// TestReaderGrammar: the general grammar of Record §6.2, which a reader
// applies whatever the scheme.
func TestReaderGrammar(t *testing.T) {
	agent := "sha256:" + strings.Repeat("e", 64)
	long := "spiffe://a/" + strings.Repeat("b", 1024-len("spiffe://a/"))
	for _, c := range []struct {
		id string
		ok bool
	}{
		{"acct:u-4821", true},
		{"ab:c", true},
		{"a:", false},
		{"acct:", false},
		{":abc", false},
		{"Acct:x", false},
		{"a-very-long-scheme-name:x", false},
		{"acct:u 4821", false},
		{"acct:u-4821\n", false},
		{long, true},
		{long + "c", false},
		{"did:example:123", true},
	} {
		_, _, ok := SplitID(c.id)
		if ok != c.ok {
			t.Errorf("%q: %v", c.id, ok)
		}
	}
	for _, c := range []struct {
		decider string
		ok      bool
	}{
		{`{"kind":"human","id":"acct:u","agent":null,"credential":null,"freshness":null}`, true},
		{`{"kind":"human","id":"acct:u","agent":null,"credential":"` + strings.Repeat("c", 64) + `","freshness":null}`, true},
		{`{"kind":"human","id":"acct:u","agent":null,"credential":"sha256:` + strings.Repeat("c", 64) + `","freshness":null}`, false},
		{`{"kind":"human","id":"acct:u","agent":null,"credential":"` + strings.Repeat("C", 64) + `","freshness":null}`, false},
		{`{"kind":"agent","id":"desc:` + agent + `","agent":"` + agent + `","credential":null,"freshness":null}`, true},
		{`{"kind":"agent","id":"desc:` + agent + `","agent":"` + strings.Repeat("e", 64) + `","credential":null,"freshness":null}`, false},
		{`{"kind":"human","id":"acct:u","agent":null,"credential":null,"freshness":"eip155:1@1:0x` + strings.Repeat("a", 64) + `"}`, true},
		{`{"kind":"human","id":"acct:u","agent":null,"credential":null,"freshness":1}`, false},
		{`{"kind":"human","id":"acct:u","agent":null,"credential":null}`, false},
		{`{"kind":1,"id":"acct:u","agent":null,"credential":null,"freshness":null}`, false},
		{`{"kind":"committee","id":"acct:u","agent":null,"credential":null,"freshness":null}`, true},
	} {
		if _, ok := Parse(parse(t, c.decider)); ok != c.ok {
			t.Errorf("%s: %v", c.decider, ok)
		}
	}
}

// TestWriterID: the value rules of the schemes of Record §6.3, which bind
// writers: a commitment is made only over an identifier a writer writes.
func TestWriterID(t *testing.T) {
	for _, c := range []struct {
		id string
		ok bool
	}{
		{"acct:u-4821", true},
		{"acct:jane@example.com", false},
		{"acct:" + strings.Repeat("a", 129), false},
		{"spiffe://claims.example/agent/triage", true},
		{"spiffe://claims.example", false},
		{"spiffe://claims.example/agent/../triage", false},
		{"spiffe://claims.example/./triage", false},
		{"jkt:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", true},
		{"jkt:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4", false},
		{"jkt:kPrK+qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", false},
		{"desc:sha256:" + strings.Repeat("e", 64), true},
		{"desc:" + strings.Repeat("e", 64), false},
		{"cmt:" + strings.Repeat("e", 64), false},
		{"did:example:123", false},
	} {
		if WriterID(c.id) != c.ok {
			t.Errorf("%q: %v", c.id, !c.ok)
		}
	}
}
