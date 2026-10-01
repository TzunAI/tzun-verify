package corpus

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/agent"
	"github.com/TzunAI/tzun-verify/internal/bundle"
	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/cli"
	"github.com/TzunAI/tzun-verify/internal/contrib"
	"github.com/TzunAI/tzun-verify/internal/decider"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/links"
	"github.com/TzunAI/tzun-verify/internal/mandate"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// The runners of the record-format vector files: worked examples, the
// decider, contributions, links, mandates, agent descriptors, the field-set
// generation of a stored record, and the cross-implementation parity cases.
// Each replays what a verifier of one record reads. The parts of a file that
// state a writer's own refusals, or what a store does across records, are
// named where they are left out.

// jsonOf parses a JSON text a vector carries as a string.
func jsonOf(t *testing.T, s string) *jsonv.Value {
	t.Helper()
	v, err := jsonv.Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}

func canonicalString(t *testing.T, v *jsonv.Value) string {
	t.Helper()
	b, err := canonical.Serialize(v)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return string(b)
}

func optStr(v *jsonv.Value, key string) (string, bool) {
	m, ok := v.Get(key)
	if !ok || m.Kind != jsonv.String {
		return "", false
	}
	return m.S, true
}

func isNull(v *jsonv.Value, key string) bool {
	m, ok := v.Get(key)
	return !ok || m.Kind == jsonv.Null
}

// hashedObject is the hashed object of a payload under the eleven names.
func hashedObject(t *testing.T, payload *jsonv.Value) string {
	t.Helper()
	sel, err := canonical.SelectFields(payload, canonical.HashedFieldsV1)
	if err != nil {
		t.Fatal(err)
	}
	return canonicalString(t, sel)
}

// envelopeOf is a genesis envelope around a payload, its digest recomputed.
func envelopeOf(t *testing.T, payload *jsonv.Value) *jsonv.Value {
	t.Helper()
	d, err := canonical.RecordDigest(payload)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return report.Obj("envelopeVersion", report.S("e1"), "payload", payload,
		"integrity", report.Obj("canonicalDigest", report.S(d)), "nonRepudiation", report.Obj())
}

// runDocReport writes d and runs tzun-verify --json over it with extra
// flags, returning the exit code, the rows by id as runDoc does, and the
// report.
func runDocReport(t *testing.T, d doc, flags ...string) (int, map[string]string, *jsonv.Value) {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit := cli.Run(append(append([]string{"--json"}, flags...), f), &stdout, &stderr)
	if stderr.Len() > 0 {
		t.Fatalf("stderr: %s", stderr.String())
	}
	rep, err := jsonv.Parse(stdout.Bytes())
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	rows := map[string]string{}
	for _, c := range get(t, rep, "checks").A {
		rows[str(t, c, "id")] = rowLine(t, c)
	}
	return exit, rows, rep
}

// bundleRows runs an envelope through the command in a bundle with every
// other slot empty, and returns the report's rows by id.
func bundleRows(t *testing.T, env *jsonv.Value) (map[string]*jsonv.Value, []*jsonv.Value) {
	t.Helper()
	b := decodeDoc(t, []byte(canonicalString(t, env)))
	_, _, rep := runDocReport(t, bundleOf(b), "--no-publishers")
	rows := map[string]*jsonv.Value{}
	list := get(t, rep, "checks").A
	for _, c := range list {
		rows[str(t, c, "id")] = c
	}
	return rows, list
}

// factsOf is a row's facts as an object, empty when it has none.
func factsOf(row *jsonv.Value) *jsonv.Value {
	if f, ok := row.Get("facts"); ok {
		return f
	}
	return &jsonv.Value{Kind: jsonv.Object}
}

// expectRow compares a report row with an answer stated as the vectors
// state one: outcome, reason when not checked-correct, and the named facts.
func expectRow(t *testing.T, name, id string, row *jsonv.Value, outcome, reason string, facts *jsonv.Value) {
	t.Helper()
	if row == nil {
		t.Errorf("%s: no %s row", name, id)
		return
	}
	got := rowLine(t, row)
	want := outcome
	if reason != "" {
		want += " " + reason
	}
	if got != want {
		t.Errorf("%s: %s %s, want %s", name, id, got, want)
		return
	}
	if facts != nil && canonicalOf(t, factsOf(row)) != canonicalOf(t, facts) {
		t.Errorf("%s: %s facts %s, want %s", name, id, canonicalOf(t, factsOf(row)), canonicalOf(t, facts))
	}
}

// pick builds an object of the members of v named, those it has.
func pick(v *jsonv.Value, names ...string) *jsonv.Value {
	o := &jsonv.Value{Kind: jsonv.Object}
	for _, n := range names {
		if m, ok := v.Get(n); ok {
			o.O = append(o.O, jsonv.Member{Key: n, Value: m})
		}
	}
	return o
}

// TestWorkedExampleVectors: the worked examples W1 to W7 and their parts,
// each recomputed (Record §4.4, §6.3, §6.9, §7.2, §8.6, §9.4, §9.6, §9.7).
// The mandate event bodies are a store's account of a mandate, which Record
// does not define; they are left out.
func TestWorkedExampleVectors(t *testing.T) {
	d := load(t, "v1.0-worked-example-vectors.json")
	var set []string
	for _, f := range get(t, d, "hashedFieldSet").A {
		set = append(set, f.S)
	}
	if strings.Join(set, " ") != strings.Join(canonical.HashedFieldsV1, " ") {
		t.Fatalf("hashed field set %v, this build %v", set, canonical.HashedFieldsV1)
	}
	for _, r := range get(t, d, "records").A {
		id := str(t, r, "id")
		c := hashedObject(t, get(t, r, "payload"))
		if c != str(t, r, "canonical") || uint64(len(c)) != u64(t, r, "byteLength") || canonical.Digest([]byte(c)) != str(t, r, "digest") {
			t.Errorf("%s: canonical bytes or digest", id)
		}
	}
	for _, o := range get(t, d, "outputDigests").A {
		if g, err := contrib.OutputDigest(get(t, o, "value")); err != nil || g != str(t, o, "digest") {
			t.Errorf("output %s: %s", str(t, o, "label"), g)
		}
	}
	for _, s := range get(t, d, "stepDigests").A {
		if g, err := contrib.StepDigest(get(t, s, "step")); err != nil || g != str(t, s, "digest") {
			t.Errorf("step %s/%d: %s", str(t, s, "record"), u64(t, s, "index"), g)
		}
	}
	for _, a := range get(t, d, "agentDescriptors").A {
		desc := get(t, a, "descriptor")
		b, err := agent.Canonical(desc)
		dg, _ := agent.Digest(desc)
		if err != nil || string(b) != str(t, a, "canonical") || uint64(len(b)) != u64(t, a, "byteLength") || dg != str(t, a, "digest") || !agent.Valid(desc) {
			t.Errorf("agent descriptor %s: %s", str(t, a, "label"), dg)
		}
	}
	commitments(t, get(t, d, "deciderCommitments"))
	derivedSalts(t, get(t, d, "derivedSalts"))
	for _, m := range get(t, d, "mandateDocuments").A {
		doc := get(t, m, "document")
		dd, ok := mandate.ParseDocument(doc, true)
		if canonicalString(t, doc) != str(t, m, "canonical") || !ok || dd.Digest != str(t, m, "digest") ||
			uint64(len(canonicalString(t, doc))) != u64(t, m, "byteLength") {
			t.Errorf("mandate document %s", str(t, m, "label"))
		}
	}
	for _, m := range get(t, d, "mandateStatements").A {
		st, ok := mandate.ParseStatement(get(t, m, "statement"))
		if !ok || canonicalString(t, get(t, m, "statement")) != str(t, m, "canonical") || st.Digest != str(t, m, "digest") ||
			mandate.Challenge(mandate.StatementDomain, st.Digest) != str(t, m, "challenge") {
			t.Errorf("mandate statement %s", str(t, m, "label"))
		}
	}
	for _, key := range []string{"mandateAssertions", "assertionDigests"} {
		for _, m := range get(t, d, key).A {
			g, ok := mandate.AssertionDigest(get(t, m, "assertion"))
			want, has := optStr(m, "digest")
			if ok != has || g != want {
				t.Errorf("%s %s: %q", key, str(t, m, "label"), g)
			}
		}
	}
	for _, m := range get(t, d, "confirmationChallenges").A {
		if mandate.Challenge(mandate.ConfirmationDomain, str(t, m, "digest")) != str(t, m, "challenge") {
			t.Errorf("confirmation challenge %s", str(t, m, "label"))
		}
	}
}

func commitments(t *testing.T, cases *jsonv.Value) {
	t.Helper()
	for _, c := range cases.A {
		salt := hexb(t, str(t, c, "saltHex"))
		if base64.RawURLEncoding.EncodeToString(salt) != str(t, c, "saltBase64url") {
			t.Errorf("commitment salt %s", str(t, c, "saltHex"))
		}
		if g, ok := decider.Commitment(salt, str(t, c, "innerId")); !ok || g != str(t, c, "commitment") {
			t.Errorf("commitment of %s: %s", str(t, c, "innerId"), g)
		}
	}
}

// derivedSalts holds the derived salt of Record §6.3 (informative):
// HMAC-SHA256(secret, "tzun-cmt-salt-v1" ‖ len ‖ key ‖ len ‖ inner), each len
// the 4-byte big-endian length of the field after it.
func derivedSalts(t *testing.T, cases *jsonv.Value) {
	t.Helper()
	for _, c := range cases.A {
		mac := hmac.New(sha256.New, hexb(t, str(t, c, "secretHex")))
		mac.Write([]byte("tzun-cmt-salt-v1"))
		for _, f := range []string{str(t, c, "idempotencyKey"), str(t, c, "innerId")} {
			var n [4]byte
			binary.BigEndian.PutUint32(n[:], uint32(len(f)))
			mac.Write(n[:])
			mac.Write([]byte(f))
		}
		salt := mac.Sum(nil)
		if base64.RawURLEncoding.EncodeToString(salt) != str(t, c, "saltBase64url") {
			t.Errorf("derived salt for %s", str(t, c, "idempotencyKey"))
		}
		if g, ok := decider.Commitment(salt, str(t, c, "innerId")); !ok || g != str(t, c, "commitment") {
			t.Errorf("derived commitment for %s: %s", str(t, c, "idempotencyKey"), g)
		}
	}
}

// TestDeciderVectors: the decider of Record §6 as a reader reads it, and
// the decider row of Verification §4.9. A writer's refusals of values the
// reader's grammar admits (the value rules of each scheme, Record §6.3) and
// the checks a writer makes against its credential store are a writer's;
// for those the runner holds only the cases a writer accepts.
func TestDeciderVectors(t *testing.T) {
	d := load(t, "decider-vectors.json")
	for _, c := range get(t, d, "shapes").A {
		name := str(t, c, "case")
		if !isNull(c, "violation") {
			continue
		}
		dec, ok := decider.Parse(get(t, c, "value"))
		if !ok || !decider.KnownKind(dec.Kind) || !decider.KnownScheme(dec.Scheme) || !decider.Consistent(dec.Identity) {
			t.Errorf("shape %q: a writer accepts it, the reader does not", name)
		}
	}
	for _, c := range get(t, d, "freshness").A {
		name := str(t, c, "case")
		f, ok := decider.ParseFreshness(str(t, c, "reference"))
		p := get(t, c, "parsed")
		if p.Kind == jsonv.Null {
			if ok {
				t.Errorf("freshness %q: accepted", name)
			}
			continue
		}
		if !ok || f.Chain != str(t, p, "chain") || f.Namespace != str(t, p, "namespace") || f.Reference != str(t, p, "reference") ||
			f.Block != u64(t, p, "blockNumber") || f.Hash != str(t, p, "blockHash") {
			t.Errorf("freshness %q: %+v", name, f)
		}
	}
	for _, c := range get(t, d, "consistency").A {
		name := str(t, c, "case")
		agentRef, _ := optStr(c, "agent")
		scheme, _, ok := decider.SplitID(str(t, c, "id"))
		if !ok {
			t.Fatalf("consistency %q: identifier", name)
		}
		got := !decider.Consistent(decider.Identity{Kind: str(t, c, "kind"), ID: str(t, c, "id"), Scheme: scheme, Agent: agentRef})
		if got != get(t, c, "readerInconsistent").B {
			t.Errorf("consistency %q: inconsistent %v", name, got)
		}
	}
	for _, c := range get(t, d, "agreement").A {
		name := str(t, c, "case")
		if decider.Agrees(str(t, c, "kind"), str(t, c, "form")) != get(t, c, "agrees").B {
			t.Errorf("agreement %q", name)
		}
		rows, _ := bundleRows(t, envelopeOf(t, get(t, c, "payload")))
		deciderRow(t, name, rows, get(t, c, "row"))
	}
	for _, c := range get(t, d, "rows").A {
		rows, _ := bundleRows(t, get(t, c, "envelope"))
		deciderRow(t, str(t, c, "case"), rows, get(t, c, "expect"))
	}
	// material: a writer refuses an agent kind on a record that carries a
	// per-record assertion over it; the reader's side of the same material
	// is the rows above (material_unverified).
	for _, c := range get(t, d, "material").A {
		name := str(t, c, "case")
		m := get(t, c, "material")
		a, ok := m.Get("assertion")
		if !ok {
			continue
		}
		challenge, typ := mandate.ClientChallenge(a)
		perRecord := mandate.Challenge("tzun-decision-v1", str(t, m, "digest"))
		bound := typ == "webauthn.get" && challenge == perRecord
		refused := false
		if v, ok := c.Get("violation"); ok && v.Kind != jsonv.Null {
			refused = str(t, v, "code") == "kind_contradicts_material"
		}
		if decider.AgentKind(str(t, get(t, c, "decider"), "kind")) && bound != refused {
			t.Errorf("material %q: bound %v", name, bound)
		}
	}
	commitments(t, get(t, d, "commitments"))
	derivedSalts(t, get(t, d, "derivedSalts"))
	for _, c := range get(t, d, "commitmentRefusals").A {
		if _, ok := decider.Commitment(hexb(t, str(t, c, "saltHex")), str(t, c, "innerId")); ok == get(t, c, "refused").B {
			t.Errorf("commitment refusal %q", str(t, c, "case"))
		}
	}
	for _, c := range get(t, d, "openings").A {
		op := get(t, c, "opening")
		s, hasSalt := optStr(op, "salt")
		salt, err := base64.RawURLEncoding.DecodeString(s)
		opens := hasSalt && err == nil && decider.Opens(str(t, c, "id"), salt, str(t, op, "id"))
		if opens != get(t, c, "opens").B {
			t.Errorf("opening %q: %v", str(t, c, "case"), opens)
		}
	}
}

// deciderRow compares the decider row with a stated answer: outcome, reason
// and the facts of Verification §4.9.
func deciderRow(t *testing.T, name string, rows map[string]*jsonv.Value, want *jsonv.Value) {
	t.Helper()
	reason, _ := optStr(want, "reason")
	expectRow(t, name, "decider", rows["decider"], str(t, want, "outcome"), reason,
		pick(want, "kind", "scheme", "level", "levelUndetermined", "committed", "kindContradiction"))
}

// TestContributionsVectors: output and step digests (Record §7.2), the
// cases a writer accepts, which a reader's contributions row holds, and the
// rows contributions, contributions.binding and contributions.pipeline of
// Verification §4.10. The builder cases are a writer's.
func TestContributionsVectors(t *testing.T) {
	d := load(t, "contributions-vectors.json")
	for _, o := range get(t, d, "outputDigests").A {
		if g, err := contrib.OutputDigest(substitute(get(t, o, "value"))); err != nil || g != str(t, o, "digest") {
			t.Errorf("output %q: %s", str(t, o, "label"), g)
		}
	}
	for _, s := range get(t, d, "stepDigests").A {
		if g, err := contrib.StepDigest(get(t, s, "step")); err != nil || g != str(t, s, "digest") {
			t.Errorf("step %q: %s", str(t, s, "label"), g)
		}
	}
	for _, c := range get(t, d, "shapes").A {
		if !isNull(c, "violation") {
			continue
		}
		ctx := get(t, c, "context")
		payload := report.Obj("action", get(t, ctx, "action"), "reason", get(t, ctx, "reason"),
			"decider", get(t, ctx, "decider"), "contributions", get(t, c, "value"))
		if r := contrib.Check(payload, nil); r.Row.Outcome != report.Correct && r.Row.Reason != contrib.ReasonAbsent {
			t.Errorf("shape %q: a writer accepts it, the row reads %s %s", str(t, c, "case"), r.Row.Outcome, r.Row.Reason)
		}
	}
	for _, c := range get(t, d, "checks").A {
		name := str(t, c, "case")
		payload := get(t, c, "payload")
		r := contrib.Check(payload, links.Targets(payload))
		want := get(t, c, "expect")
		reason, _ := optStr(want, "reason")
		got := &jsonv.Value{Kind: jsonv.Object}
		for _, f := range r.Row.Facts {
			got.O = append(got.O, jsonv.Member{Key: f.Name, Value: f.Value})
		}
		expectRow(t, name, "contributions", rowJSON(r.Row), str(t, want, "outcome"), reason,
			pick(want, "steps", "models", "decidingStep", "failedStep"))
		b := get(t, want, "binding")
		breason, _ := optStr(b, "reason")
		var bfacts *jsonv.Value
		if o := str(t, b, "outcome"); o == "checked-correct" || o == "checked-wrong" {
			bfacts = pick(b, "approvals", "staleApprovals", "uncoveredReviews", "proposals", "decisionBinding", "failedStep", "failedDigest")
		}
		expectRow(t, name, "contributions.binding", rowJSON(r.Binding), str(t, b, "outcome"), breason, bfacts)
		p, hasPipeline := want.Get("pipeline")
		switch {
		case hasPipeline && r.Pipeline == nil:
			t.Errorf("%s: no contributions.pipeline row", name)
		case hasPipeline:
			expectRow(t, name, "contributions.pipeline", rowJSON(*r.Pipeline), str(t, p, "outcome"), str(t, p, "reason"), nil)
		case r.Pipeline != nil:
			t.Errorf("%s: a contributions.pipeline row", name)
		}
	}
}

// rowJSON renders a check as a report row.
func rowJSON(c report.Check) *jsonv.Value { return report.CheckJSON(c) }

// heldRecords is a Resolver over a links vector's resolver member.
type heldRecords struct {
	byDigest  map[string]*links.Held
	own       map[string]bool
	positions map[string]string
	openings  map[string]string
}

func posKey(origin string, seq uint64) string { return origin + "#" + strconv.FormatUint(seq, 10) }

func newResolver(t *testing.T, r *jsonv.Value) *heldRecords {
	t.Helper()
	h := &heldRecords{byDigest: map[string]*links.Held{}, own: map[string]bool{}, positions: map[string]string{}, openings: map[string]string{}}
	if held, ok := r.Get("held"); ok {
		for _, x := range held.A {
			origin, _ := optStr(x, "origin")
			h.byDigest[str(t, x, "digest")] = &links.Held{Payload: get(t, x, "payload"), Digest: str(t, x, "digest"), Origin: origin}
		}
	}
	if own, ok := r.Get("ownOrigins"); ok {
		for _, o := range own.A {
			h.own[o.S] = true
		}
	}
	if ps, ok := r.Get("positions"); ok {
		for _, p := range ps.A {
			h.positions[posKey(str(t, p, "origin"), u64(t, p, "seq"))] = str(t, p, "digest")
		}
	}
	if op, ok := r.Get("openings"); ok {
		for _, m := range op.O {
			h.openings[m.Key] = m.Value.S
		}
	}
	return h
}

func (h *heldRecords) ByDigest(d string) (*links.Held, bool) { x, ok := h.byDigest[d]; return x, ok }
func (h *heldRecords) HoldsLog(origin string) bool           { return h.own[origin] }
func (h *heldRecords) At(origin string, seq uint64) (string, bool) {
	d, ok := h.positions[posKey(origin, seq)]
	return d, ok
}
func (h *heldRecords) Open(cmt string) (string, bool) { x, ok := h.openings[cmt]; return x, ok }

// TestLinksVectors: the links of Record §8 as a reader reads them, and the
// rows links, links[<i>] and links[<i>].edge of Verification §4.11. A case
// with a resolver is read as a verifier that holds those records reads it;
// one without, as a bundle verifier, which holds no target. The capture
// cases are a writer's.
func TestLinksVectors(t *testing.T) {
	d := load(t, "links-vectors.json")
	var reg []string
	for r := range links.Registry {
		reg = append(reg, r)
	}
	sort.Strings(reg)
	var want []string
	for _, r := range get(t, d, "registry").A {
		want = append(want, r.S)
	}
	if strings.Join(reg, " ") != strings.Join(want, " ") {
		t.Errorf("registry %v, the vectors %v", reg, want)
	}
	n := 0
	for _, section := range []string{"shapes", "profiles", "listLevel", "targets"} {
		for _, c := range get(t, d, section).A {
			name := section + ": " + str(t, c, "case")
			payload := get(t, c, "payload")
			form, ok := bundle.ExpectationForm(payload)
			in := links.Input{Payload: payload, Form: form, Malformed: !ok}
			if r, has := c.Get("resolver"); has && r.Kind == jsonv.Object {
				in.Resolver = newResolver(t, r)
			}
			linkRows(t, name, links.Check(in), get(t, c, "reader"))
			n++
		}
	}
	t.Logf("%d links cases", n)
}

// linkRows compares the rows of one record with the reader's answer.
func linkRows(t *testing.T, name string, got links.Result, want *jsonv.Value) {
	t.Helper()
	reason, _ := optStr(want, "reason")
	facts := pick(want, "count", "extensions", "rule", "failedLink")
	if rn, ok := want.Get("relationNames"); ok {
		facts.O = append(facts.O, jsonv.Member{Key: "relations", Value: rn})
	}
	expectRow(t, name, "links", rowJSON(got.Row), str(t, want, "outcome"), reason, facts)
	rels := get(t, want, "relations").A
	perLink := len(got.Links) > 0
	if !perLink {
		if len(rels) > 0 && len(rels) <= 256 {
			t.Errorf("%s: no links[<i>] rows, the vectors state %d", name, len(rels))
		}
		return
	}
	if len(got.Links) != 2*len(rels) {
		t.Errorf("%s: %d link rows, want %d", name, len(got.Links), 2*len(rels))
		return
	}
	for i, r := range rels {
		row := rowJSON(got.Links[2*i])
		// The relation's name is the entry's, not a fact the vectors
		// state; a row that abstains on an unknown relation names it.
		f := factsOf(row)
		trimmed := &jsonv.Value{Kind: jsonv.Object}
		for _, m := range f.O {
			if m.Key != "rel" {
				trimmed.O = append(trimmed.O, m)
			}
		}
		if len(f.O) > 0 {
			row = pick(row, "id", "outcome", "reason")
			if len(trimmed.O) > 0 {
				row.O = append(row.O, jsonv.Member{Key: "facts", Value: trimmed})
			}
		}
		rr, _ := optStr(r, "reason")
		expected := &jsonv.Value{Kind: jsonv.Object}
		for _, m := range r.O {
			switch m.Key {
			case "index", "rel", "outcome", "valid", "reason":
			default:
				expected.O = append(expected.O, m)
			}
		}
		expectRow(t, name, str(t, row, "id"), row, str(t, r, "outcome"), rr, expected)
		edge := rowJSON(got.Links[2*i+1])
		wantEdge := "abstain unsupported_link_edge"
		if rowLine(t, edge) != wantEdge {
			t.Errorf("%s: %s %s, want %s", name, str(t, edge, "id"), rowLine(t, edge), wantEdge)
		}
	}
}
