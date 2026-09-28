package bundle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/merkle"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// The two sign-off rows a b1 report carries (Verification §4.5),
// in this order. This build verifies no WebAuthn signature:
// signoff.expectation needs no key, and signoff.key says why no key was
// used.
const (
	IDSignoffExpectation = "signoff.expectation"
	IDSignoffKey         = "signoff.key"

	ReasonNoCredential       = "not_in_bundle:credential"
	ReasonUnsupportedSignoff = "unsupported_signoff"

	// The answers of Verification §5 for signoff.expectation.
	// signature_missing is the one not-checked answer: a policy record whose
	// signature may still come.
	ReasonSignatureMissing     = "signature_missing"
	ReasonSignoffStripped      = "signoff_stripped"
	ReasonSignoffUnbound       = "signoff_unbound"
	ReasonStatementDigest      = "statement_digest_mismatch"
	ReasonSessionSeq           = "session_seq_mismatch"
	ReasonSessionNotExpected   = "session_signoff_not_expected"
	ReasonMalformedExpectation = "malformed_signoff_expectation"
)

// Domain prefixes of the challenges an assertion can present
// (Record §6.4).
const (
	perRecordDomain = "tzun-decision-v1"
	statementDomain = "tzun-signoff-v1"
)

// signoffMaterial is what the record holds under nonRepudiation.
type signoffMaterial struct {
	// assertion is webauthnAssertion when it is an object, nil otherwise:
	// only an object is an assertion (Record §6.3).
	assertion *jsonv.Value
	// block is the signoff member, any value but null.
	block *jsonv.Value
	// presented is the challenge the assertion's clientDataJSON presents,
	// "" when there is none to read; get tells whether its type is
	// webauthn.get.
	presented string
	get       bool
}

func (v *verification) signoffRows() {
	m := readSignoff(v.nr)
	exp := v.expectationRow(m)
	v.add(exp)
	v.add(v.keyRow(m, exp))
}

func readSignoff(nr *jsonv.Value) signoffMaterial {
	m := signoffMaterial{block: member(nr, "signoff")}
	if a := member(nr, "webauthnAssertion"); isObject(a) {
		m.assertion = a
	}
	s, ok := member(m.assertion, "clientDataJSON").Str()
	if !ok {
		return m
	}
	raw, ok := decodeB64(s)
	if !ok {
		return m
	}
	cd, err := jsonv.Parse(raw)
	if err != nil || !isObject(cd) {
		return m
	}
	m.presented, _ = member(cd, "challenge").Str()
	t, _ := member(cd, "type").Str()
	m.get = t == "webauthn.get"
	return m
}

// decodeB64 reads base64url or standard base64, padded or not.
func decodeB64(s string) ([]byte, bool) {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, true
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, true
	}
	return nil, false
}

// challenge is base64url without padding of SHA-256(domain ‖ text), the
// form of both challenges of Record §6.4.
func challenge(domain, text string) string {
	s := sha256.Sum256([]byte(domain + text))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// statementDigest is the digest of a statement (Record §6.4), in
// hex. Only a statement inside that section's value domain has one: an
// object with nothing nested, its keys and strings in printable ASCII, its
// numbers safe integers of zero or more. For such a statement the DEO
// serializer writes the canonical bytes that section hashes.
func statementDigest(st *jsonv.Value) (string, bool) {
	if !isObject(st) {
		return "", false
	}
	for _, m := range st.O {
		if m.KeyLone || !printableASCII(m.Key) {
			return "", false
		}
		switch m.Value.Kind {
		case jsonv.String:
			if s, ok := m.Value.Str(); !ok || !printableASCII(s) {
				return "", false
			}
		case jsonv.Number:
			if _, ok := m.Value.Uint53(); !ok {
				return "", false
			}
		default:
			return "", false
		}
	}
	b, err := canonical.Serialize(st)
	if err != nil {
		return "", false
	}
	return canonical.Digest(b), true
}

// expectation is a signoffExpectation read by the grammar of
// Record §6.2.
type expectation struct {
	form            string // "none", "policy" or "session"
	statementDigest string
	sessionSeq      uint64
}

// parseExpectation reads the grammar of Record §6.2. An absent key
// reads as null, as the canonical form writes it. Each object form has
// exactly its keys: {policyDigest}, or {statementDigest, sessionSeq},
// digests as 64 lowercase hex characters and the slot a safe integer of at
// least 1.
func parseExpectation(payload *jsonv.Value) (expectation, bool) {
	x, _ := payload.Get(canonical.SignoffExpectationKey)
	if x == nil || x.Kind == jsonv.Null {
		return expectation{form: "none"}, true
	}
	if x.Kind != jsonv.Object {
		return expectation{}, false
	}
	switch len(x.O) {
	case 1:
		pd, ok := member(x, "policyDigest").Str()
		return expectation{form: "policy"}, ok && isLowerHex64(pd)
	case 2:
		sd, ok1 := member(x, "statementDigest").Str()
		seq, ok2 := member(x, "sessionSeq").Uint53()
		if !ok1 || !ok2 || !isLowerHex64(sd) || seq == 0 {
			return expectation{}, false
		}
		return expectation{form: "session", statementDigest: sd, sessionSeq: seq}, true
	}
	return expectation{}, false
}

// carried reports whether the record carries a sign-off: a signoff block
// and an assertion (Record §6.3). The unbound and binding rules
// read it.
func (m signoffMaterial) carried() bool { return m.block != nil && m.assertion != nil }

// session reports whether the record carries a session sign-off: a signoff
// block whose statement's mode is session, or that carries sessionSeq
// (Record §6.3). An assertion is not part of that definition, so a
// session block counts with or without one.
func (m signoffMaterial) session() bool {
	if m.block == nil {
		return false
	}
	if member(m.block, "sessionSeq") != nil {
		return true
	}
	mode, _ := member(member(m.block, "statement"), "mode").Str()
	return mode == "session"
}

// bindsBatch reports whether the carried block and assertion bind the
// record as a batch sign-off (Record §6.5): a batch statement inside
// the value domain, an assertion whose clientDataJSON carries that
// statement's challenge, and a Merkle path that places the record's digest
// in the tree of the statement's root and size.
func (v *verification) bindsBatch(m signoffMaterial) bool {
	st := member(m.block, "statement")
	if mode, _ := member(st, "mode").Str(); mode != "batch" {
		return false
	}
	sd, ok := statementDigest(st)
	if !ok || m.presented != challenge(statementDomain, sd) {
		return false
	}
	root, okRoot := merkle.ParseHash(member(st, "root"))
	size, okSize := member(st, "treeSize").Uint53()
	inc := member(m.block, "inclusion")
	index, okIndex := member(inc, "leafIndex").Uint53()
	path, okPath := merkle.ParsePath(member(inc, "path"))
	if !okRoot || !okSize || !okIndex || !okPath {
		return false
	}
	return merkle.VerifyInclusion(v.digest, index, size, path, root)
}

// presentsPerRecord reports whether the assertion is a webauthn.get that
// presented the record's own per-record challenge.
func (v *verification) presentsPerRecord(m signoffMaterial) bool {
	return m.get && m.presented == challenge(perRecordDomain, hex.EncodeToString(v.digest))
}

// expectationRow is signoff.expectation (Verification §5): the
// record's hashed signoffExpectation against the sign-off material it
// carries, by that section's table, whose first matching rule decides. It needs no key and no
// signature. The expectation is authenticated by the digest alone, so the
// row is blocked by record.digest unless that holds.
func (v *verification) expectationRow(m signoffMaterial) report.Check {
	if v.digest == nil {
		return report.BlockedBy(IDSignoffExpectation, IDDigest)
	}
	c := report.Check{ID: IDSignoffExpectation}
	set := func(o report.Outcome, reason string) report.Check {
		c.Outcome, c.Reason = o, reason
		return c
	}
	exp, ok := parseExpectation(v.payload)
	if !ok {
		return set(report.Wrong, ReasonMalformedExpectation)
	}
	switch exp.form {
	case "none":
		switch {
		case m.session():
			return set(report.Wrong, ReasonSessionNotExpected)
		case m.carried() && !v.bindsBatch(m):
			return set(report.Wrong, ReasonSignoffUnbound)
		}
		return set(report.Correct, "")
	case "policy":
		switch {
		case m.session():
			return set(report.Wrong, ReasonSessionNotExpected)
		case m.assertion == nil:
			return set(report.NotChecked, ReasonSignatureMissing)
		case m.block != nil && v.bindsBatch(m):
			return set(report.Correct, "")
		case m.block != nil:
			return set(report.Wrong, ReasonSignoffUnbound)
		case v.presentsPerRecord(m):
			return set(report.Correct, "")
		}
		return set(report.NotChecked, ReasonSignatureMissing)
	}
	// The session form.
	if m.block == nil {
		return set(report.Wrong, ReasonSignoffStripped)
	}
	if sd, ok := statementDigest(member(m.block, "statement")); !ok || sd != exp.statementDigest {
		return set(report.Wrong, ReasonStatementDigest)
	}
	if seq, ok := member(m.block, "sessionSeq").Uint53(); !ok || seq != exp.sessionSeq {
		return set(report.Wrong, ReasonSessionSeq)
	}
	switch {
	case m.assertion == nil:
		return set(report.Wrong, ReasonSignoffStripped)
	case m.presented != challenge(statementDomain, exp.statementDigest):
		return set(report.Wrong, ReasonSignoffUnbound)
	}
	return set(report.Correct, "")
}

// keyRow is signoff.key (Verification §4.5): blocked when the
// expectation failed; signature_missing when the record owes a signature
// and carries no assertion; an abstention when the credentials slot is
// filled, since this build reads no credential; absent when no assertion
// is carried; otherwise the key is not in the bundle, because no b1 slot
// carries it yet.
func (v *verification) keyRow(m signoffMaterial, exp report.Check) report.Check {
	c := report.Check{ID: IDSignoffKey}
	switch {
	case exp.Outcome == report.Wrong:
		return report.BlockedBy(IDSignoffKey, IDSignoffExpectation)
	case exp.Reason == ReasonSignatureMissing && m.assertion == nil:
		c.Outcome, c.Reason = report.NotChecked, ReasonSignatureMissing
	case member(v.root, "credentials") != nil:
		c.Outcome, c.Reason = report.Abstain, ReasonUnsupportedSignoff
	case m.assertion == nil:
		c.Outcome, c.Reason = report.NotChecked, ReasonAbsent
	default:
		c.Outcome, c.Reason = report.NotChecked, ReasonNoCredential
	}
	return c
}
