package report

import "testing"

func TestExitCode(t *testing.T) {
	c := func(id string, o Outcome, reason string) Check { return Check{ID: id, Outcome: o, Reason: reason} }
	cases := []struct {
		name   string
		checks []Check
		p      Policy
		want   int
	}{
		{"all correct", []Check{c("a", Correct, "")}, Policy{}, 0},
		{"bundle", []Check{c("bundle", Abstain, "unsupported_bundle_version")}, Policy{}, 2},
		{"bundle verifier error", []Check{c("bundle", NotChecked, "bundle_verifier_error")}, Policy{AllowUnchecked: true}, 2},
		{"no bundle check", []Check{}, Policy{}, 2},
		{"wrong beats unchecked", []Check{c("a", Wrong, "x"), c("b", NotChecked, "y")}, Policy{}, 1},
		{"unchecked", []Check{c("a", Correct, ""), c("b", NotChecked, "input_not_supplied:evm_header_source")}, Policy{}, 4},
		{"abstain", []Check{c("a", Abstain, "unsupported_anchor_spec")}, Policy{}, 4},
		{"allow unchecked", []Check{c("a", Abstain, "unsupported_anchor_spec")}, Policy{AllowUnchecked: true}, 0},
		{"absent and not applicable do not count", []Check{c("a", NotChecked, "absent"), c("b", NotChecked, "not_applicable")}, Policy{}, 0},
		{"blocked by a check that was not decided counts", []Check{c("a", NotChecked, "absent"), c("c", NotChecked, "blocked_by:a")}, Policy{}, 4},
		{"require met", []Check{c("anchor.evm.canonical[0]", Correct, "")}, Policy{Require: []string{"anchor.evm.canonical[*]"}}, 0},
		{"require not met beats unchecked", []Check{c("anchor", NotChecked, "publication_not_checked")}, Policy{Require: []string{"anchor"}}, 3},
		{"require names nothing", []Check{c("a", Correct, "")}, Policy{Require: []string{"anchor.evm.canonical[*]"}}, 3},
		{"require-rung with no sign-off", []Check{c("a", Correct, "")}, Policy{RequireRungs: []string{"per_record"}}, 3},
		{"wrong beats require", []Check{c("a", Wrong, "x")}, Policy{Require: []string{"b"}}, 1},
		{"scoped allowance of the one reason left", []Check{c("a", Abstain, "unsupported_link_edge"), c("b", Abstain, "unsupported_link_edge")},
			Policy{AllowReasons: []string{"unsupported_link_edge"}}, 0},
		{"scoped allowance of another reason", []Check{c("a", Abstain, "unsupported_link_edge"), c("b", NotChecked, "confirmation_missing")},
			Policy{AllowReasons: []string{"unsupported_link_edge"}}, 4},
		{"scoped allowance of both reasons", []Check{c("a", Abstain, "unsupported_link_edge"), c("b", NotChecked, "confirmation_missing")},
			Policy{AllowReasons: []string{"confirmation_missing", "unsupported_link_edge"}}, 0},
		{"scoped allowance never hides a failure", []Check{c("a", Wrong, "link_rule_violated")},
			Policy{AllowReasons: []string{"link_rule_violated"}}, 1},
		{"scoped allowance of a blocked row names its reason", []Check{c("a", NotChecked, "blocked_by:links")},
			Policy{AllowReasons: []string{"blocked_by:links"}}, 0},
		{"scoped allowance and require", []Check{c("a", Abstain, "unsupported_link_edge")},
			Policy{AllowReasons: []string{"unsupported_link_edge"}, Require: []string{"a"}}, 3},
		{"an empty scoped allowance allows nothing", []Check{c("a", Abstain, "unsupported_link_edge")},
			Policy{AllowReasons: []string{}}, 4},
	}
	for _, tc := range cases {
		checks := tc.checks
		if tc.name != "bundle" && tc.name != "bundle verifier error" && tc.name != "no bundle check" {
			checks = append([]Check{c("bundle", Correct, "")}, checks...)
		}
		r := &Report{Checks: checks}
		if got := ExitCode(r, tc.p); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestMatches(t *testing.T) {
	for pat, ids := range map[string]map[string]bool{
		"anchor.evm.canonical[*]": {"anchor.evm.canonical[0]": true, "anchor.evm.canonical[12]": true, "anchor.evm.canonical[]": false, "anchor.evm.canonical[x]": false, "anchor.evm.canonical": false},
		"anchor":                  {"anchor": true, "anchor.spec": false},
	} {
		for id, want := range ids {
			if matches(pat, id) != want {
				t.Errorf("%s ~ %s: %v", pat, id, !want)
			}
		}
	}
}

func TestUnchecked(t *testing.T) {
	for _, tc := range []struct {
		c    Check
		want bool
	}{
		{Check{Outcome: NotChecked, Reason: "blocked_by:anchor"}, true},
		{Check{Outcome: NotChecked, Reason: "publication_not_checked"}, true},
		{Check{Outcome: NotChecked, Reason: "absent"}, false},
		{Check{Outcome: NotChecked, Reason: "not_applicable"}, false},
		{Check{Outcome: Abstain, Reason: "unsupported_extension"}, true},
		{Check{Outcome: Correct}, false},
		{Check{Outcome: Wrong, Reason: "merkle_proof_invalid"}, false},
	} {
		if got := Unchecked(tc.c); got != tc.want {
			t.Errorf("%+v: %v", tc.c, got)
		}
	}
	// A row blocked by a failed check never reaches exit 4: the failure
	// decides exit 1 first.
	r := &Report{Checks: []Check{
		{ID: IDBundle, Outcome: Correct},
		{ID: "anchor.inclusion", Outcome: Wrong, Reason: "merkle_proof_invalid"},
		BlockedBy("anchor.anchorInclusion", "anchor.inclusion"),
	}}
	if got := ExitCode(r, Policy{}); got != ExitWrong {
		t.Errorf("exit %d, want %d", got, ExitWrong)
	}
}
