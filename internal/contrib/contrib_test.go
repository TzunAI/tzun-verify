// SPDX-License-Identifier: BSD-3-Clause-Clear

package contrib

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

// TestStepGrammar: rules of Record §7.1 and §7.3 a reader holds a step to,
// beyond the cases of the conformance vectors.
func TestStepGrammar(t *testing.T) {
	d := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	bom := `{"modelDescriptorDigest":"` + d("6") + `"}`
	step := func(role, actor, verdict string) string {
		return `{"pipeline":null,"externals":[],"steps":[{"role":"` + role + `","actor":` + actor + `,"aiBom":` + bom +
			`,"inputs":[],"output":"` + d("f") + `","verdict":` + verdict + `,"reason":null,"prev":null}]}`
	}
	agent := `"` + d("e") + `"`
	for _, c := range []struct {
		name, contributions string
		ok                  bool
	}{
		{"a propose step", step("propose", "null", "null"), true},
		{"a review with a verdict", step("review", "null", `"approve"`), true},
		{"a verdict on a propose step", step("propose", "null", `"approve"`), false},
		{"a verdict on an other step", step("other:carry-out", "null", `"reject"`), false},
		{"a verdict outside the three", step("review", "null", `"maybe"`), false},
		{"an agent actor naming its reference", step("propose", `{"kind":"agent","id":"desc:`+d("e")+`","agent":`+agent+`}`, "null"), true},
		{"an agent actor naming no reference", step("propose", `{"kind":"agent","id":"spiffe://a/b","agent":null}`, "null"), false},
		{"a human actor naming a reference", step("propose", `{"kind":"human","id":"acct:u","agent":`+agent+`}`, "null"), false},
		{"a human actor under spiffe", step("propose", `{"kind":"human","id":"spiffe://a/b","agent":null}`, "null"), false},
		{"an actor of a kind this version does not know", step("propose", `{"kind":"committee","id":"acct:u","agent":null}`, "null"), true},
		{"a role name of 48 characters", step("propose:"+strings.Repeat("n", 48), "null", "null"), true},
		{"a role name of 49 characters", step("propose:"+strings.Repeat("n", 49), "null", "null"), false},
		{"an empty role name", step("propose:", "null", "null"), false},
	} {
		if _, _, ok := Parse(parse(t, c.contributions)); ok != c.ok {
			t.Errorf("%s: well formed %v", c.name, ok)
		}
	}
}
