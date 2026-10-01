package manifest

import (
	"testing"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

func TestParseTime(t *testing.T) {
	good := map[string]Instant{
		"2026-10-01T00:00:00Z":        {Sec: 1790812800},
		"2026-10-01T00:00:00.0005Z":   {Sec: 1790812800, Frac: true},
		"2026-10-01T00:00:00.000Z":    {Sec: 1790812800},
		"2026-10-01T02:00:00+02:00":   {Sec: 1790812800},
		"2026-09-30T19:00:00.5-05:00": {Sec: 1790812800, Frac: true},
		"2028-02-29T00:00:00Z":        {Sec: 1835395200},
	}
	for s, want := range good {
		got, ok := ParseTime(s)
		if !ok || got != want {
			t.Errorf("%s: %+v %v, want %+v", s, got, ok, want)
		}
	}
	for _, s := range []string{
		"2026-10-01t00:00:00Z", "2026-10-01T00:00:00z", "2026-10-01T00:00:60Z", "2026-09-31T00:00:00Z",
		"2026-10-01T24:00:00Z", "2027-02-29T00:00:00Z", "2026-13-01T00:00:00Z", "2026-00-01T00:00:00Z",
		"2026-10-01T00:60:00Z", "2026-10-01T00:00:00+24:00", "2026-10-01T00:00:00+01:60", "2026-10-01T00:00:00",
		"2026-10-01T00:00:00.Z", "2026-10-01 00:00:00Z", " 2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z\n",
		"+2026-10-01T00:00:00Z", "2026-10-01T00:00:00+0100",
	} {
		if _, ok := ParseTime(s); ok {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestValidAt(t *testing.T) {
	from := Instant{Sec: 100, Frac: true}
	until := Instant{Sec: 200, Frac: true}
	e := Entry{ValidFrom: &from, ValidUntil: &until}
	for bt, want := range map[int64]bool{100: false, 101: true, 200: true, 201: false} {
		if e.ValidAt(bt) != want {
			t.Errorf("block time %d: %v", bt, !want)
		}
	}
}

func TestLoneSurrogateChain(t *testing.T) {
	// A chain holding a lone surrogate is a string: under eip155: it breaks
	// the chain rule and the origin is unreadable; otherwise the entry is not
	// an EVM entry and is skipped.
	for doc, want := range map[string]State{
		`{"publishers":{"a/b/anchors":[{"address":"0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc","chain":"eip155:1\ud800","namespace":"test"}]}}`: Unreadable,
		`{"publishers":{"a/b/anchors":[{"address":"0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc","chain":"\ud800","namespace":"test"}]}}`:         NoEntries,
	} {
		m, err := jsonv.Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if got := ForOrigin(m, "a/b/anchors").State; got != want {
			t.Errorf("%s: %v, want %v", doc, got, want)
		}
	}
}

func TestUnknownEntryMembersIgnored(t *testing.T) {
	m, _ := jsonv.Parse([]byte(`{"publishers":{"a/b/anchors":[{"address":"0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc","chain":"eip155:1","namespace":"test","note":"x","label":{"a":1}}]}}`))
	if got := ForOrigin(m, "a/b/anchors"); got.State != OK || len(got.Entries) != 1 {
		t.Errorf("%+v", got)
	}
}

// TestNetworkRegistry: the chains every registry names (Anchor §9):
// mainnet, and the Sepolia and Hoodi test networks; any other is null.
func TestNetworkRegistry(t *testing.T) {
	for chain, want := range map[string]string{
		"eip155:1": "mainnet", "eip155:11155111": "testnet", "eip155:560048": "testnet",
		"eip155:31337": "", "eip155:5": "",
	} {
		if got := Network(chain); got != want {
			t.Errorf("%s: %q, want %q", chain, got, want)
		}
	}
}
