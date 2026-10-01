package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/cli"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// Helpers for tests that start from a corpus bundle or a vector envelope,
// change it, and run it through the command.

type doc = map[string]any

func decodeDoc(t *testing.T, b []byte) doc {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var out doc
	if err := d.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func loadDoc(t *testing.T, path string) doc {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return decodeDoc(t, b)
}

func sub(d doc, path ...string) doc {
	for _, p := range path {
		d = d[p].(doc)
	}
	return d
}

// runDoc writes d and runs tzun-verify --json over it with extra flags. It
// returns the exit code and each row's "outcome reason".
func runDoc(t *testing.T, d doc, flags ...string) (int, map[string]string) {
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
		o := str(t, c, "outcome")
		if r, ok := c.Get("reason"); ok {
			o += " " + r.S
		}
		rows[str(t, c, "id")] = o
	}
	return exit, rows
}

// clone is a deep copy of a document.
func clone(t *testing.T, d doc) doc {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return decodeDoc(t, b)
}

// bundleOf wraps a vector envelope in a b1 record bundle with every other
// slot empty, as an exporter with no anchoring and no custody material
// writes it.
func bundleOf(env doc) doc {
	payload := env["payload"].(doc)
	return doc{
		"bundleVersion": "b1", "profile": "record",
		"subject":  doc{"evidenceId": payload["evidenceId"], "canonicalDigest": env["integrity"].(doc)["canonicalDigest"]},
		"envelope": env,
		"chain":    doc{"chainId": "vectors", "predecessor": nil},
		"custody":  nil, "credentials": nil, "relatedRecords": nil, "anchoring": nil,
		"anchorPending": nil, "policy": nil, "extensions": nil, "exporter": nil,
	}
}

// expectationAnswer reads the signoff.expectation row as the vectors state
// an answer: valid true, false or null, and a reason. The row's
// blocked_by:record.digest is the vectors' digest_invalid (the expectation
// is read only when the digest holds, Verification §5).
func expectationAnswer(row string) (valid, reason string) {
	switch row {
	case "checked-correct":
		return "true", ""
	case "not-checked blocked_by:record.digest":
		return "null", "digest_invalid"
	}
	for _, p := range []struct{ prefix, valid string }{{"checked-wrong ", "false"}, {"not-checked ", "null"}} {
		if len(row) > len(p.prefix) && row[:len(p.prefix)] == p.prefix {
			return p.valid, row[len(p.prefix):]
		}
	}
	return "?", row
}

func wantAnswer(t *testing.T, e doc) (valid, reason string) {
	t.Helper()
	switch v := e["valid"].(type) {
	case bool:
		valid = map[bool]string{true: "true", false: "false"}[v]
	case nil:
		valid = "null"
	default:
		t.Fatalf("valid %v", v)
	}
	reason, _ = e["reason"].(string)
	return valid, reason
}

// TestSignoffExpectationVectors runs every envelope of the sign-off
// expectation vectors through the command, each in a bundle, and holds its
// signoff.expectation row to the answer stated (Record §9,
// Verification §5).
//   - checks: the table of Verification §5, row by row;
//   - verifications: whole records, with and without a digest that holds;
//     verified is record.digest checked-correct.
//
// The statement digests and the grammar are internal/bundle's tests.
func TestSignoffExpectationVectors(t *testing.T) {
	d := loadDoc(t, filepath.Join(vectorDir, "signoff-expectation-vectors.json"))
	checks := d["checks"].([]any)
	for _, x := range checks {
		c := x.(doc)
		name := c["case"].(string)
		_, rows := runDoc(t, bundleOf(c["envelope"].(doc)), "--no-publishers")
		if rows["record.digest"] != "checked-correct" {
			t.Errorf("%s: record.digest %q", name, rows["record.digest"])
		}
		gv, gr := expectationAnswer(rows["signoff.expectation"])
		wv, wr := wantAnswer(t, c["expect"].(doc))
		if gv != wv || gr != wr {
			t.Errorf("%s: signoff.expectation %q, want valid %s %s", name, rows["signoff.expectation"], wv, wr)
		}
	}
	verifications := d["verifications"].([]any)
	for _, x := range verifications {
		c := x.(doc)
		name := c["case"].(string)
		exp := c["expect"].(doc)
		_, rows := runDoc(t, bundleOf(c["envelope"].(doc)), "--no-publishers")
		if verified := rows["record.digest"] == "checked-correct"; verified != exp["verified"].(bool) {
			t.Errorf("%s: record.digest %q, verified %v", name, rows["record.digest"], exp["verified"])
		}
		gv, gr := expectationAnswer(rows["signoff.expectation"])
		wv, wr := wantAnswer(t, exp["signoffExpectation"].(doc))
		if gv != wv || gr != wr {
			t.Errorf("%s: signoff.expectation %q, want valid %s %s", name, rows["signoff.expectation"], wv, wr)
		}
	}
	t.Logf("%d checks, %d verifications", len(checks), len(verifications))
}

// TestSignoffKey is signoff.key (Verification §4.5), on
// the rules the corpus does not reach: a filled credentials slot is a key
// this build does not read, an abstention, unless signoff.expectation
// failed or the record owes a signature and carries no assertion.
func TestSignoffKey(t *testing.T) {
	d := loadDoc(t, filepath.Join(vectorDir, "signoff-expectation-vectors.json"))
	byName := map[string]doc{}
	for _, x := range d["checks"].([]any) {
		c := x.(doc)
		byName[c["case"].(string)] = c["envelope"].(doc)
	}
	for _, c := range []struct {
		envelope    string
		credentials any
		key         string
		exit        int
	}{
		{"null, nothing carried", nil, "not-checked absent", 0},
		{"null, nothing carried", doc{}, "abstain unsupported_signoff", 4},
		{"null, a per-record signature nobody required", nil, "not-checked not_in_bundle:credential", 4},
		{"null, a per-record signature nobody required", doc{"credential-1": doc{"coseKey": "x"}}, "abstain unsupported_signoff", 4},
		{"policy, nothing carried (awaiting sign-off, or stripped)", doc{}, "not-checked signature_missing", 4},
		{"policy, an assertion about another record", nil, "not-checked not_in_bundle:credential", 4},
		{"session, the sign-off stripped", doc{}, "not-checked blocked_by:signoff.expectation", 1},
		{"null, a batch signoff block without an assertion (no sign-off is carried)", nil, "not-checked absent", 0},
	} {
		b := bundleOf(clone(t, byName[c.envelope]))
		b["credentials"] = c.credentials
		exit, rows := runDoc(t, b, "--no-publishers")
		if rows["signoff.key"] != c.key || exit != c.exit {
			t.Errorf("%s, credentials %v: signoff.key %q exit %d, want %q exit %d", c.envelope, c.credentials, rows["signoff.key"], exit, c.key, c.exit)
		}
	}
}

// TestSignoffBindingRules: binding rules (Record §9.5) that the vectors do not
// separate. A per-record assertion binds only as a webauthn.get; a batch
// sign-off binds only with a statement whose mode is batch, even when the
// assertion carries the challenge of that statement and the path verifies.
func TestSignoffBindingRules(t *testing.T) {
	d := loadDoc(t, filepath.Join(vectorDir, "signoff-expectation-vectors.json"))
	byName := map[string]doc{}
	for _, x := range d["checks"].([]any) {
		c := x.(doc)
		byName[c["case"].(string)] = c["envelope"].(doc)
	}
	clientData := func(t *testing.T, a doc) doc {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(a["clientDataJSON"].(string))
		if err != nil {
			t.Fatal(err)
		}
		return decodeDoc(t, raw)
	}
	setClientData := func(t *testing.T, a doc, cd doc) {
		t.Helper()
		b, err := json.Marshal(cd)
		if err != nil {
			t.Fatal(err)
		}
		a["clientDataJSON"] = base64.RawURLEncoding.EncodeToString(b)
	}

	env := clone(t, byName["policy, a per-record signature over this record"])
	a := sub(env, "nonRepudiation", "webauthnAssertion")
	cd := clientData(t, a)
	cd["type"] = "webauthn.create"
	setClientData(t, a, cd)
	if _, rows := runDoc(t, bundleOf(env), "--no-publishers"); rows["signoff.expectation"] != "not-checked signature_missing" {
		t.Errorf("a per-record challenge in a webauthn.create: %q", rows["signoff.expectation"])
	}

	// The batch statement relabelled, and the assertion's challenge made
	// the relabelled statement's: only mode batch binds.
	for _, c := range []struct{ mode, want string }{{"batch", "checked-correct"}, {"record", "checked-wrong signoff_unbound"}} {
		env := clone(t, byName["policy, a batch sign-off that covers this record"])
		st := sub(env, "nonRepudiation", "signoff", "statement")
		st["mode"] = c.mode
		b, _ := json.Marshal(st)
		sv, err := jsonv.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		cb, err := canonical.Serialize(sv)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte("tzun-signoff-v1" + canonical.Digest(cb)))
		a := sub(env, "nonRepudiation", "webauthnAssertion")
		cd := clientData(t, a)
		cd["challenge"] = base64.RawURLEncoding.EncodeToString(sum[:])
		setClientData(t, a, cd)
		if _, rows := runDoc(t, bundleOf(env), "--no-publishers"); rows["signoff.expectation"] != c.want {
			t.Errorf("a statement of mode %s: %q, want %q", c.mode, rows["signoff.expectation"], c.want)
		}
	}
}

// TestSessionSignoffNeedsNoAssertion: Record §9.3 defines a session sign-off by
// its signoff block alone (a statement whose mode is session, or a
// sessionSeq member), and the rows that answer session_signoff_not_expected
// come before any rule that asks for an assertion. So under a null or a
// {policyDigest} expectation a session block is checked-wrong whether the
// assertion is there, absent, null or not an object. signoff.key is then
// blocked by the expectation, and the exit is 1.
func TestSessionSignoffNeedsNoAssertion(t *testing.T) {
	d := loadDoc(t, filepath.Join(vectorDir, "signoff-expectation-vectors.json"))
	byName := map[string]doc{}
	for _, x := range d["checks"].([]any) {
		c := x.(doc)
		byName[c["case"].(string)] = c["envelope"].(doc)
	}
	const (
		wantRow = "checked-wrong session_signoff_not_expected"
		wantKey = "not-checked blocked_by:signoff.expectation"
	)
	assertions := []struct {
		name  string
		set   bool
		value any
	}{
		{"kept", false, nil},
		{"removed", true, "delete"},
		{"null", true, nil},
		{"a string", true, "x"},
		{"an array", true, []any{}},
	}
	withAssertion := func(env doc, i int) doc {
		env = clone(t, env)
		nr := sub(env, "nonRepudiation")
		switch a := assertions[i]; {
		case !a.set:
		case a.value == "delete":
			delete(nr, "webauthnAssertion")
		default:
			nr["webauthnAssertion"] = a.value
		}
		return env
	}
	for _, name := range []string{
		"null, a session sign-off transplanted onto it",
		"null, a signoff block carrying sessionSeq beside a batch statement",
		"policy, a session sign-off",
	} {
		for i, a := range assertions {
			exit, rows := runDoc(t, bundleOf(withAssertion(byName[name], i)), "--no-publishers")
			if rows["signoff.expectation"] != wantRow || rows["signoff.key"] != wantKey || exit != 1 {
				t.Errorf("%s, assertion %s: signoff.expectation %q, signoff.key %q, exit %d", name, a.name, rows["signoff.expectation"], rows["signoff.key"], exit)
			}
		}
	}

	// The same two records built from the bundle corpus: a transplanted
	// session block whose assertion was removed, and a policy record whose
	// signature was stripped, given that session block with no assertion.
	dir := filepath.Join(vectorDir, "bundle-b1")
	caseFlags := func(t *testing.T, name string) []string {
		t.Helper()
		in, err := jsonv.Parse(readCase(t, filepath.Join(dir, name), "inputs.json"))
		if err != nil {
			t.Fatal(err)
		}
		return args(t, in, t.TempDir())
	}
	transplanted := loadDoc(t, filepath.Join(dir, "session-signoff-transplanted", "bundle.json"))
	block := sub(transplanted, "envelope", "nonRepudiation")["signoff"]
	delete(sub(transplanted, "envelope", "nonRepudiation"), "webauthnAssertion")
	if _, rows := runDoc(t, transplanted, caseFlags(t, "session-signoff-transplanted")...); rows["signoff.expectation"] != wantRow {
		t.Errorf("session-signoff-transplanted without its assertion: %q", rows["signoff.expectation"])
	}
	stripped := loadDoc(t, filepath.Join(dir, "signature-stripped", "bundle.json"))
	sub(stripped, "envelope", "nonRepudiation")["signoff"] = block
	if _, rows := runDoc(t, stripped, caseFlags(t, "signature-stripped")...); rows["signoff.expectation"] != wantRow {
		t.Errorf("signature-stripped with a session block and no assertion: %q", rows["signoff.expectation"])
	}
}
