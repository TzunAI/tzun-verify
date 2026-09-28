// Package bundle verifies a b1 record bundle, as Bundle specifies it, and
// builds its tzun-verify-report/1 report (Verification §6).
//
// The rows, in report order:
//
//   - bundle: the version, the profile and the shape of every slot;
//   - subject, record.digest, record.chainLink, custody.ledger: the record
//     itself (record.go);
//   - ts.record.token, ts.record.trust: the record's own RFC 3161 token,
//     under Anchor §10.5 with the digest as the imprint;
//   - signoff.expectation and signoff.key (signoff.go);
//   - anchor and its steps (Anchor §10.3 to §10.7), then
//     anchor.newer and anchor.consistency[<origin>] (Bundle §7.5 and
//     §7.6), from the bundle's anchoring slot (anchoring.go);
//   - anchor.pending, extension[<key>], the filled relatedRecords and
//     policy slots, member[<key>], and a row for every other artifact
//     present that this build does not verify.
//
// It is written from Verification, Bundle and Anchor §10, and held to the
// expected reports of the b1 conformance corpus (Bundle §13).
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/TzunAI/tzun-verify/internal/anchor"
	"github.com/TzunAI/tzun-verify/internal/checkpoint"
	"github.com/TzunAI/tzun-verify/internal/evm"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
	"github.com/TzunAI/tzun-verify/internal/rfc3161"
)

// Version is the one bundle version this verifier reads
// (Bundle §4).
const Version = "b1"

// Row ids and reasons of the bundle rows that neither the anchor catalogue
// nor the sign-off catalogue defines (Verification §2.3, §4).
const (
	IDBundle    = report.IDBundle
	IDSubject   = "subject"
	IDDigest    = "record.digest"
	IDChainLink = "record.chainLink"
	IDCustody   = "custody.ledger"
	IDPending   = "anchor.pending"

	ReasonMalformedBundle    = "malformed_bundle"
	ReasonUnsupportedVersion = "unsupported_bundle_version"
	ReasonUnsupportedProfile = "unsupported_bundle_profile"
	ReasonBundleError        = "bundle_verifier_error"
	ReasonSubjectMismatch    = "subject_mismatch"
	ReasonNotYetPublished    = "not_yet_published"
	ReasonUnsupportedExt     = "unsupported_extension"
	ReasonUnsupportedSlot    = "unsupported_slot"
	ReasonUnsupportedMember  = "unsupported_member"
	// ReasonUnsupported is this build's abstention on material inside the
	// envelope that no row verifies: present, so never passed over, and
	// never a failure.
	ReasonUnsupported = "unsupported_artifact"
	ReasonAbsent      = "absent"
	ReasonNA          = "not_applicable"
)

// Options are the auditor's inputs.
type Options struct {
	// Manifest is the primary publisher manifest, nil for none.
	Manifest *jsonv.Value
	// ManifestBytes are the manifest's bytes as read; the report names the
	// manifest by their SHA-256 (Verification §6.2). Without them it
	// is named by the SHA-256 of its canonical form.
	ManifestBytes []byte
	Sources       evm.Sources
	Trust         rfc3161.Trust
	// Timeout is the one deadline every header-source call of the
	// verification shares (Anchor §10.4 item 8); 0 means the default.
	Timeout time.Duration
}

// ExistedBy is the summary's earliest proven bound: when, from what kind of
// evidence, and which row proved it.
type ExistedBy struct {
	At     time.Time
	Source string
	Check  string
}

// Result is one bundle's verification.
type Result struct {
	Report *report.Report
	// Anchor is the verdict on the record's own artifact, nil when it was
	// not run (no readable bundle, or no digest to run it over).
	Anchor *anchor.Verdict
	// Newer is the verdict behind anchor.newer, nil when there is none.
	Newer     *anchor.Verdict
	ExistedBy *ExistedBy
	// Digest is the record's stored canonicalDigest as the envelope states
	// it, "" when it states none.
	Digest     string
	EvidenceID string
	ChainID    string
	Sequence   *jsonv.Value
}

// Verify reads and verifies one bundle. It never panics: a failure inside
// the verifier is the bundle row not-checked, bundle_verifier_error, and
// the exit code 2.
func Verify(data []byte, opts Options) (res *Result) {
	started := time.Now()
	defer func() {
		if r := recover(); r != nil {
			res = &Result{Report: &report.Report{CheckedAt: started, Inputs: inputsOf(opts)}}
			res.Report.Checks = []report.Check{{ID: IDBundle, Outcome: report.NotChecked, Reason: ReasonBundleError}}
			res.Report.Summary = summarize(res)
		}
	}()
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = anchor.DefaultTimeout
	}
	v := &verification{opts: opts, deadline: started.Add(timeout)}
	res = &Result{Report: &report.Report{CheckedAt: started, Inputs: inputsOf(opts)}}
	v.res = res
	if frame := v.readFrame(data); frame.Outcome != report.Correct {
		res.Report.Checks = []report.Check{frame}
		res.Report.Summary = summarize(res)
		return res
	}
	v.add(report.Check{ID: IDBundle, Outcome: report.Correct})
	v.recordRows()
	v.signoffRows()
	v.anchorRows()
	v.trailingRows()
	res.Report.Checks = v.checks
	res.ExistedBy = v.existedBy()
	res.Report.Summary = summarize(res)
	return res
}

// verification is the state of one run: the bundle's parts, the rows so far
// and what later rows take from earlier ones.
type verification struct {
	opts     Options
	deadline time.Time
	res      *Result
	checks   []report.Check

	root, env, payload, integrity, nr *jsonv.Value
	anchoring                         *jsonv.Value

	// digest is the recomputed digest, set only when record.digest is
	// checked-correct: every row that takes the digest as input reads it
	// from here, and is blocked_by record.digest without it.
	digest []byte
	// recordTS is the record timestamp's result when both its rows hold.
	recordTS *rfc3161.Result
}

func (v *verification) add(cs ...report.Check) { v.checks = append(v.checks, cs...) }

// member returns obj[key] with null read as absent.
func member(obj *jsonv.Value, key string) *jsonv.Value {
	m, ok := obj.Get(key)
	if !ok || m.Kind == jsonv.Null {
		return nil
	}
	return m
}

func isObject(v *jsonv.Value) bool { return v != nil && v.Kind == jsonv.Object }

// optionalObject reports whether obj[key] is absent, null or an object.
func optionalObject(obj *jsonv.Value, key string) bool {
	m := member(obj, key)
	return m == nil || m.Kind == jsonv.Object
}

// slots are the members a b1 record bundle carries (Bundle §3.2). b1
// carries every slot, and absent material fills its slot with null, so a
// slot that is missing, rather than null, is not a b1 bundle.
var slots = []string{
	"subject", "envelope", "chain", "custody", "credentials", "relatedRecords",
	"anchoring", "anchorPending", "policy", "extensions", "exporter",
}

// readFrame decides the bundle row. The version is read first, then the
// profile, then the slots (Bundle §4): an unknown version or
// profile is an abstention on the whole bundle, and a slot missing or of the
// wrong type, or a lone surrogate in a name a row id would carry, makes the
// bundle unreadable.
func (v *verification) readFrame(data []byte) report.Check {
	wrong := report.Check{ID: IDBundle, Outcome: report.Wrong, Reason: ReasonMalformedBundle}
	root, err := jsonv.Parse(data)
	if err != nil || root.Kind != jsonv.Object {
		return wrong
	}
	v.root = root
	if bv, ok := root.Get("bundleVersion"); ok {
		v.res.Report.BundleVersion = bv
	}
	if s, ok := root.Get("subject"); ok {
		v.res.Report.Subject = s
	}
	if s, ok := member(root, "bundleVersion").Str(); !ok || s != Version {
		return report.Check{ID: IDBundle, Outcome: report.Abstain, Reason: ReasonUnsupportedVersion}
	}
	if s, ok := member(root, "profile").Str(); !ok || s != "record" {
		return report.Check{ID: IDBundle, Outcome: report.Abstain, Reason: ReasonUnsupportedProfile}
	}

	for _, slot := range slots {
		if !root.Has(slot) {
			return wrong
		}
	}
	v.env = member(root, "envelope")
	v.payload = member(v.env, "payload")
	v.integrity = member(v.env, "integrity")
	if !isObject(v.env) || !isObject(v.payload) || !isObject(v.integrity) || !optionalObject(v.env, "nonRepudiation") {
		return wrong
	}
	v.nr = member(v.env, "nonRepudiation")
	for _, slot := range slots {
		if !optionalObject(root, slot) {
			return wrong
		}
	}
	if ch := member(root, "chain"); ch != nil {
		if id := member(ch, "chainId"); id != nil && id.Kind != jsonv.String {
			return wrong
		}
		if !optionalObject(ch, "predecessor") {
			return wrong
		}
	}
	if !optionalObject(root, "anchoring") || !anchoringReadable(member(root, "anchoring")) {
		return wrong
	}
	v.anchoring = member(root, "anchoring")
	// Step 9: no name a row id can carry holds a lone surrogate, so every
	// row can be written (Verification §4.1).
	for _, obj := range []*jsonv.Value{root, member(root, "extensions"), v.nr, v.anchoring} {
		if loneKey(obj) {
			return wrong
		}
	}

	if id, ok := member(v.payload, "evidenceId").Str(); ok {
		v.res.EvidenceID = id
	}
	v.res.Sequence = member(v.payload, "sequenceNumber")
	if d, ok := member(v.integrity, "canonicalDigest").Str(); ok {
		v.res.Digest = d
	}
	if id, ok := member(member(root, "chain"), "chainId").Str(); ok {
		v.res.ChainID = id
	}
	return report.Check{ID: IDBundle, Outcome: report.Correct}
}

// loneKey reports whether a member name of obj holds a lone surrogate.
func loneKey(obj *jsonv.Value) bool {
	if obj == nil {
		return false
	}
	for _, m := range obj.O {
		if m.KeyLone {
			return true
		}
	}
	return false
}

// anchoringReadable applies the shape of Bundle §7.1 to the
// anchoring slot: each origin maps to {checkpoints, consistency}; a
// checkpoint is an object whose body parses (Anchor §4.2) and
// names the origin it sits under, so that
// checkpoints of two logs are never compared as one; a record bundle
// carries at most two checkpoints per log; a consistency entry is an
// object. What the other members hold is for the checks.
func anchoringReadable(a *jsonv.Value) bool {
	if a == nil {
		return true
	}
	for _, m := range a.O {
		if m.KeyLone || !isObject(m.Value) {
			return false
		}
		cps, ok := m.Value.Get("checkpoints")
		if !ok || cps.Kind != jsonv.Array || len(cps.A) > 2 {
			return false
		}
		for _, cp := range cps.A {
			if !isObject(cp) {
				return false
			}
			if b, ok := checkpoint.Parse(member(cp, "body")); !ok || b.Origin != m.Key {
				return false
			}
		}
		if cons := member(m.Value, "consistency"); cons != nil {
			if cons.Kind != jsonv.Array {
				return false
			}
			for _, c := range cons.A {
				if !isObject(c) {
					return false
				}
			}
		}
	}
	return true
}

// recordMembers are the top-level members of a b1 record bundle: its
// version, its profile and its slots.
var recordMembers = map[string]bool{"bundleVersion": true, "profile": true}

func init() {
	for _, s := range slots {
		recordMembers[s] = true
	}
}

// trailingRows follow the anchor rows, in the order of Verification §4.1:
// the anchorPending slot, each extension with a value, the reserved
// slots this build does not read, when they are filled, each top-level member
// a record bundle does not have, and then this build's own abstentions on
// envelope material no row verifies.
func (v *verification) trailingRows() {
	if member(v.root, "anchorPending") != nil {
		v.add(report.Check{ID: IDPending, Outcome: report.NotChecked, Reason: ReasonNotYetPublished})
	}
	if ext := member(v.root, "extensions"); ext != nil {
		for _, m := range sortedMembers(ext) {
			if m.Value.Kind != jsonv.Null {
				v.add(report.Check{ID: "extension[" + m.Key + "]", Outcome: report.Abstain, Reason: ReasonUnsupportedExt})
			}
		}
	}
	for _, slot := range []string{"relatedRecords", "policy"} {
		if member(v.root, slot) != nil {
			v.add(report.Check{ID: slot, Outcome: report.Abstain, Reason: ReasonUnsupportedSlot})
		}
	}
	for _, m := range sortedMembers(v.root) {
		if !recordMembers[m.Key] {
			v.add(report.Check{ID: "member[" + m.Key + "]", Outcome: report.Abstain, Reason: ReasonUnsupportedMember})
		}
	}
	v.add(v.unreadRows()...)
}

// unreadRows abstain on each item of nonRepudiation that no row reads, so
// none of it passes silently (Verification §4.7, §6.6). An empty
// member is not present.
func (v *verification) unreadRows() []report.Check {
	var out []report.Check
	for _, m := range sortedMembers(v.nr) {
		if m.Value.Kind == jsonv.Null {
			continue
		}
		switch m.Key {
		case "anchor", "rfc3161Token", "webauthnAssertion", "signoff":
			// Rows of their own.
		case "rfc3161Metadata":
			// A copy of the token's own fields for display; never an input.
		case "blockchainAnchor":
			// Alone, it is the anchor row's legacy abstention. Beside an
			// anchor it is a second artifact nobody verifies.
			if member(v.nr, "anchor") != nil {
				out = append(out, report.Check{ID: "nonRepudiation.blockchainAnchor", Outcome: report.Abstain, Reason: anchor.ReasonLegacy})
			}
		case "assertionTimestamp":
			out = append(out, report.Check{ID: "ts.assertion.token", Outcome: report.Abstain, Reason: ReasonUnsupported})
		default:
			out = append(out, report.Check{ID: "nonRepudiation." + m.Key, Outcome: report.Abstain, Reason: ReasonUnsupported})
		}
	}
	return out
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
