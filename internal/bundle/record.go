package bundle

import (
	"encoding/hex"
	"sort"
	"strings"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/merkle"
	"github.com/TzunAI/tzun-verify/internal/report"
	"github.com/TzunAI/tzun-verify/internal/rfc3161"
)

// Reasons of the record rows (Verification §4.3).
const (
	ReasonUnsupportedSchema   = "unsupported_schema_version"
	ReasonUnsupportedEnvelope = "unsupported_envelope_version"
	ReasonDigestMismatch      = "digest_mismatch"
	ReasonUnserializable      = "payload_unserializable"
	ReasonLinkMismatch        = "chain_link_mismatch"
	ReasonLinkMissing         = "chain_link_missing"
	ReasonPredecessorMismatch = "predecessor_mismatch"
	ReasonNoPredecessor       = "not_in_bundle:predecessor"
)

// EnvelopeVersion is the one envelope version this build reads
// (Record §4.3).
const EnvelopeVersion = "e1"

func (v *verification) recordRows() {
	v.add(v.subjectRow())
	v.add(v.digestRow())
	v.add(v.chainLinkRow())
	v.add(v.custodyRow())
	v.add(v.recordTimestampRows()...)
}

// hexDigest reads a 64-character hex digest, any case, as bytes.
func hexDigest(x *jsonv.Value) ([]byte, bool) {
	s, ok := x.Str()
	if !ok {
		return nil, false
	}
	return merkle.ParseHashString(s)
}

// subjectRow: the bundle's subject names the envelope's record, by its
// evidence id and by the digest the envelope stores (Bundle §5.1). It
// compares with the stored digest, not a recomputed one, so a tampered
// payload fails at record.digest alone.
func (v *verification) subjectRow() report.Check {
	wrong := report.Check{ID: IDSubject, Outcome: report.Wrong, Reason: ReasonSubjectMismatch}
	subject := member(v.root, "subject")
	sid, ok1 := member(subject, "evidenceId").Str()
	pid, ok2 := member(v.payload, "evidenceId").Str()
	sd, ok3 := hexDigest(member(subject, "canonicalDigest"))
	ed, ok4 := hexDigest(member(v.integrity, "canonicalDigest"))
	if !ok1 || !ok2 || !ok3 || !ok4 || sid != pid || string(sd) != string(ed) {
		return wrong
	}
	return report.Check{ID: IDSubject, Outcome: report.Correct}
}

// digestRow recomputes the digest from the payload under its schema and
// compares it with integrity.canonicalDigest (Verification §4.3).
// An envelope version other than e1, whether another tag, null or none, and
// a schema other than v1.0 are abstentions. The digest is taken over the
// eleven names of Record §4.1, and an absent key is hashed as null
// (Record §4.2): a record whose null key is left out still recomputes, and a
// digest computed over another set of names does not (digest_mismatch).
func (v *verification) digestRow() report.Check {
	c := report.Check{ID: IDDigest}
	if s, ok := member(v.env, "envelopeVersion").Str(); !ok || s != EnvelopeVersion {
		c.Outcome, c.Reason = report.Abstain, ReasonUnsupportedEnvelope
		return c
	}
	if s, ok := member(v.payload, "schemaVersion").Str(); !ok || s != "v1.0" {
		c.Outcome, c.Reason = report.Abstain, ReasonUnsupportedSchema
		return c
	}
	stored, okStored := hexDigest(member(v.integrity, "canonicalDigest"))
	d, err := canonical.RecordDigest(v.payload)
	if err != nil {
		c.Outcome, c.Reason = report.Wrong, ReasonUnserializable
		return c
	}
	if !okStored || d != hex.EncodeToString(stored) {
		c.Outcome, c.Reason = report.Wrong, ReasonDigestMismatch
		// A stored digest that recomputes under an earlier field set is
		// named: the fact explains the mismatch and never excuses it.
		if okStored {
			if fs := fieldSetFact(v.payload, stored); fs != "" {
				c.Facts = []report.Fact{{Name: "fieldSet", Value: report.S(fs)}}
			}
		}
		return c
	}
	v.digest, _ = hex.DecodeString(d)
	c.Outcome = report.Correct
	return c
}

// chainLinkRow checks integrity.chainLink against chain.predecessor. The
// link is SHA-256 over the predecessor's digest and then this record's, as
// hex text (v1.0-integrity-vectors.json pins the form). It reads the stored
// digests: a payload edited under its digest is record.digest's finding.
// The first record of a chain, sequence number 1, has no link.
func (v *verification) chainLinkRow() report.Check {
	c := report.Check{ID: IDChainLink}
	seq, okSeq := member(v.payload, "sequenceNumber").Uint53()
	link := member(v.integrity, "chainLink")
	pred := member(member(v.root, "chain"), "predecessor")
	digest, okDigest := hexDigest(member(v.integrity, "canonicalDigest"))
	if !okSeq || seq == 0 || !okDigest {
		c.Outcome, c.Reason = report.Wrong, ReasonLinkMismatch
		return c
	}
	if seq == 1 {
		switch {
		case link != nil:
			c.Outcome, c.Reason = report.Wrong, ReasonLinkMismatch
			return c
		case pred != nil:
			c.Outcome, c.Reason = report.Wrong, ReasonPredecessorMismatch
			return c
		}
		c.Outcome = report.Correct
		return c
	}
	if link == nil {
		c.Outcome, c.Reason = report.Wrong, ReasonLinkMissing
		return c
	}
	if pred == nil {
		c.Outcome, c.Reason = report.NotChecked, ReasonNoPredecessor
		return c
	}
	pseq, ok1 := member(pred, "sequenceNumber").Uint53()
	pdigest, ok2 := hexDigest(member(pred, "canonicalDigest"))
	if !ok1 || !ok2 || pseq != seq-1 {
		c.Outcome, c.Reason = report.Wrong, ReasonPredecessorMismatch
		return c
	}
	want := canonical.ChainLink(hex.EncodeToString(pdigest), hex.EncodeToString(digest))
	got, ok := link.Str()
	if !ok || strings.ToLower(got) != want {
		c.Outcome, c.Reason = report.Wrong, ReasonLinkMismatch
		return c
	}
	c.Outcome = report.Correct
	return c
}

// custodyRow is custody.ledger (Verification §4.3). This version
// does not verify custody material, so the row is never checked-correct.
// It reads not_applicable only for a bundle that carries none: a null slot
// or one whose entries are an empty array, beside an envelope whose
// custodyChain mirrors no ledger row. Anything else abstains, so that what
// the bundle holds is never passed over (Bundle §6, Specs §4): a hashed
// mirror entry beside a ledger that holds no rows names a row the bundle
// leaves out, and only a verifier of custody material could decide it.
func (v *verification) custodyRow() report.Check {
	slot := member(v.root, "custody")
	if entries := member(slot, "entries"); (slot == nil || entries != nil && entries.Kind == jsonv.Array && len(entries.A) == 0) && !mirrorsLedger(v.env) {
		return report.Check{ID: IDCustody, Outcome: report.NotChecked, Reason: ReasonNA}
	}
	return report.Check{ID: IDCustody, Outcome: report.Abstain, Reason: ReasonUnsupported}
}

// mirrorsLedger reports whether the envelope's custodyChain holds a hashed
// entry: an object whose entryHash is present and not null, the mirror of a
// custody ledger row. An entry without one, such as the capture's own,
// mirrors no row (Record §2.1 leaves the chain's content undefined).
func mirrorsLedger(env *jsonv.Value) bool {
	chain := member(env, "custodyChain")
	if chain == nil || chain.Kind != jsonv.Array {
		return false
	}
	for _, e := range chain.A {
		if isObject(e) && member(e, "entryHash") != nil {
			return true
		}
	}
	return false
}

// recordTimestampRows run Anchor §10.5 over the record's own token
// with the recomputed digest as the imprint. An absent token is absent; a
// token present with no digest to hold it to is blocked by record.digest.
func (v *verification) recordTimestampRows() []report.Check {
	tok := member(v.nr, "rfc3161Token")
	if tok == nil {
		return []report.Check{
			{ID: rfc3161.IDRecordToken, Outcome: report.NotChecked, Reason: ReasonAbsent},
			{ID: rfc3161.IDRecordTrust, Outcome: report.NotChecked, Reason: ReasonAbsent},
		}
	}
	if v.digest == nil {
		return []report.Check{
			report.BlockedBy(rfc3161.IDRecordToken, IDDigest),
			report.BlockedBy(rfc3161.IDRecordTrust, IDDigest),
		}
	}
	r := rfc3161.VerifyRecordToken(tok, v.digest, v.opts.Trust)
	if r.Token.Outcome == report.Correct && r.Trust.Outcome == report.Correct {
		v.recordTS = &r
	}
	return []report.Check{r.Token, r.Trust}
}

// sortedMembers returns an object's members in byte order of their keys.
// Every object it is given is one whose names readFrame has checked for
// lone surrogates (Bundle §4 step 9).
func sortedMembers(obj *jsonv.Value) []jsonv.Member {
	if !isObject(obj) {
		return nil
	}
	out := append([]jsonv.Member(nil), obj.O...)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
