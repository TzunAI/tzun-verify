package links

import (
	"strings"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// TestLocatorOrigin: the origin grammar of a locator (Record §8.2): a
// store's evidence log, or a hosted log under exactly log.tzun.ai or
// test.log.tzun.ai, never an anchor log.
func TestLocatorOrigin(t *testing.T) {
	store := strings.Repeat("0f", 16)
	for _, c := range []struct {
		origin string
		ok     bool
	}{
		{"test.lender.example/" + store + "/evidence/6c656e64696e67", true},
		{"lender.example/" + store + "/evidence/6c656e64696e67", true},
		{"Lender.example/" + store + "/evidence/6c656e64696e67", false},
		{"test.lender.example/" + strings.ToUpper(store) + "/evidence/6c656e64696e67", false},
		{"test.lender.example/" + store[:30] + "/evidence/6c656e64696e67", false},
		{"test.lender.example/" + store + "/evidence/6C656e64696e67", false},
		{"test.lender.example/" + store + "/custody", false},
		{"test.lender.example/" + store + "/anchors", false},
		{"log.tzun.ai/" + store + "/" + store, true},
		{"test.log.tzun.ai/" + store + "/" + store, true},
		{"log.tzun.ai/" + store + "/anchors", false},
		{"staging.log.tzun.ai/" + store + "/" + store, false},
	} {
		if validOrigin(c.origin) != c.ok {
			t.Errorf("%s: %v", c.origin, !c.ok)
		}
	}
}

// TestRelationNames: the grammar of a registered name and of an extension
// name (Record §8.2), and the registry of §8.3.
func TestRelationNames(t *testing.T) {
	for _, c := range []struct {
		name                   string
		valid, ext, registered bool
	}{
		{"derivedFrom", true, false, true},
		{"subject", true, false, true},
		{"inspiredBy", true, false, false},
		{"x-acme.contractRenewal", true, true, false},
		{"x-a.b", true, true, false},
		{"x-acme-.renewal", false, false, false},
		{"x-" + strings.Repeat("o", 32) + "." + strings.Repeat("n", 32), true, true, false},
		{"x-" + strings.Repeat("o", 32) + "." + strings.Repeat("n", 33), false, false, false},
		{"a" + strings.Repeat("b", 31), true, false, false},
		{"a" + strings.Repeat("b", 32), false, false, false},
	} {
		if validName(c.name) != c.valid || Extension(c.name) != c.ext || Registered(c.name) != c.registered {
			t.Errorf("%s: valid %v extension %v registered %v", c.name, validName(c.name), Extension(c.name), Registered(c.name))
		}
	}
}

// held is a Resolver over a few records, each held under its own digest.
type held map[string]*Held

func (h held) ByDigest(d string) (*Held, bool)  { x, ok := h[d]; return x, ok }
func (h held) HoldsLog(string) bool             { return false }
func (h held) At(string, uint64) (string, bool) { return "", false }
func (h held) Open(string) (string, bool)       { return "", false }

func parse(t *testing.T, s string) *jsonv.Value {
	t.Helper()
	v, err := jsonv.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// record holds a payload under the digest it recomputes to.
func record(t *testing.T, h held, payload string) string {
	t.Helper()
	p := parse(t, payload)
	d, err := canonical.RecordDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	h[d] = &Held{Payload: p, Digest: d}
	return d
}

func link(rel, digest string) string {
	return `{"rel":"` + rel + `","target":{"digest":"` + digest + `","evidenceId":null,"locator":null},"attrs":null}`
}

// TestHeldTargets: target rules and root facts the vectors reach only
// together with another rule.
func TestHeldTargets(t *testing.T) {
	h := held{}
	assertion := strings.Repeat("7", 64)
	// A record that is not an issuance record, whose output names the
	// assertion all the same: a mandate link to it breaks mandate_target.
	notIssuance := record(t, h, `{"aiSystemId":"claims","action":"approve","aiOutput":{"assertionDigest":"`+assertion+`"}}`)
	mandated := `{"aiSystemId":"claims","action":"approve","decider":{"kind":"agent-mandated"},
		"signoffExpectation":{"mandateAssertion":"` + assertion + `","mandateSeq":1,"totals":null,"confirm":false},
		"links":[` + link("mandate", notIssuance) + `]}`
	r := Check(Input{Payload: parse(t, mandated), Form: "mandate", Resolver: h})
	if got := report.CheckJSON(r.Links[0]); !strings.Contains(canonicalOf(t, got), `"reason":"link_rule_violated"`) ||
		!strings.Contains(canonicalOf(t, got), `"rule":"mandate_target"`) {
		t.Errorf("a mandate link to a record that is not an issuance record: %s", canonicalOf(t, got))
	}

	// A root link whose target has a lineage link of its own, the lineage
	// target not held: rootInconsistent from the root's target alone.
	other := strings.Repeat("9", 64)
	rootTarget := record(t, h, `{"aiSystemId":"a","links":[`+link("derivedFrom", other)+`]}`)
	lineageTarget := strings.Repeat("8", 64)
	child := `{"aiSystemId":"a","links":[` + link("derivedFrom", lineageTarget) + `,` + link("root", rootTarget) + `]}`
	r = Check(Input{Payload: parse(t, child), Form: "none", Resolver: h})
	if got := canonicalOf(t, report.CheckJSON(r.Links[2])); !strings.Contains(got, `"rootInconsistent":true`) {
		t.Errorf("a root target with a lineage link of its own: %s", got)
	}
}

func canonicalOf(t *testing.T, v *jsonv.Value) string {
	t.Helper()
	b, err := canonical.Serialize(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
