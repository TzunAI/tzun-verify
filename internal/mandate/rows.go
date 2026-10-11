// SPDX-License-Identifier: BSD-3-Clause-Clear

package mandate

import (
	"github.com/TzunAI/tzun-verify/internal/grammar"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// Row ids and reasons of Verification §4.12.
const (
	IDIssuance  = "mandate.issuance"
	IDScope     = "mandate.scope"
	IDLimits    = "mandate.limits"
	IDKey       = "mandate.key"
	IDTimestamp = "mandate.assertionTimestamp"

	ReasonIssuanceNotExpected = "issuance_not_expected"
	ReasonIssuanceStripped    = "issuance_material_stripped"
	ReasonIssuanceMismatch    = "issuance_material_mismatch"
	ReasonNoDocument          = "not_in_bundle:mandate_document"
	ReasonUnsupportedDocument = "unsupported_mandate_document"
	ReasonMalformedDocument   = "malformed_mandate_document"
	ReasonAgentNotIn          = "agent_not_in_mandate"
	ReasonOutside             = "outside_mandate_scope"
	ReasonConfirmationEvaded  = "confirmation_evaded"
	ReasonUndeterminable      = "scope_undeterminable"
	ReasonTotalsMalformed     = "mandate_totals_malformed"
	ReasonLimitExceeded       = "mandate_limit_exceeded"
)

// Block is a mandate block or an issuance block (§9.6), read member by
// member. Every member is nil when the block is not an object.
type Block struct {
	Raw       *jsonv.Value
	Statement *jsonv.Value
	Assertion *jsonv.Value
	// Document is nil when the block carries none: no document member, or
	// one that is null.
	Document  *jsonv.Value
	Timestamp *jsonv.Value
}

// ReadBlock reads a block; v nil or null is no block.
func ReadBlock(v *jsonv.Value) *Block {
	if v == nil || v.Kind == jsonv.Null {
		return nil
	}
	b := &Block{Raw: v}
	if v.Kind != jsonv.Object {
		return b
	}
	b.Statement = member(v, "statement")
	b.Assertion = member(v, "assertion")
	if d := member(v, "document"); d != nil && d.Kind != jsonv.Null {
		b.Document = d
	}
	b.Timestamp = member(v, "assertionTimestamp")
	return b
}

// Issuance reports whether a payload is an issuance record (§9.6).
func Issuance(payload *jsonv.Value) bool {
	s1, _ := member(payload, "aiSystemId").Str()
	s2, _ := member(payload, "action").Str()
	return s1 == "tzun:mandate" && s2 == "issue-mandate"
}

// IssuanceRow decides mandate.issuance (Verification §4.12) for a record
// whose digest holds. reported is false when the row is not reported: the
// record carries no issuance block and is not an issuance record.
func IssuanceRow(payload *jsonv.Value, block *Block) (c report.Check, reported bool) {
	isRecord := Issuance(payload)
	if block == nil && !isRecord {
		return c, false
	}
	c.ID = IDIssuance
	switch {
	case block != nil && !isRecord:
		c.Outcome, c.Reason = report.Wrong, ReasonIssuanceNotExpected
		return c, true
	case block == nil:
		c.Outcome, c.Reason = report.Wrong, ReasonIssuanceStripped
		return c, true
	}
	if link := issuanceLink(payload, block); link != "" {
		c.Outcome, c.Reason = report.Wrong, ReasonIssuanceMismatch
		c.Facts = []report.Fact{{Name: "link", Value: report.S(link)}}
		return c, true
	}
	c.Outcome = report.Correct
	return c, true
}

// issuanceLink returns the first link of the issuance material that does
// not hold, in the order the conformance vectors name them: document,
// statement, signer, challenge, assertion, decider. Material that is
// missing or of the wrong type fails the first link that needs it.
func issuanceLink(payload *jsonv.Value, b *Block) string {
	out := member(payload, "aiOutput")
	want := func(k string) string { s, _ := member(out, k).Str(); return s }
	doc, ok := ParseDocument(b.Document, false)
	stMandate, _ := member(b.Statement, "mandateDigest").Str()
	if !ok || doc.Digest != want("mandateDigest") || doc.Digest != stMandate {
		return "document"
	}
	st, ok := ParseStatement(b.Statement)
	if !ok || st.Digest != want("statementDigest") {
		return "statement"
	}
	if doc.Signer != st.Signer {
		return "signer"
	}
	if !Presents(b.Assertion, Challenge(StatementDomain, st.Digest)) {
		return "challenge"
	}
	if d, ok := AssertionDigest(b.Assertion); !ok || d != want("assertionDigest") {
		return "assertion"
	}
	dec := member(payload, "decider")
	kind, _ := member(dec, "kind").Str()
	id, _ := member(dec, "id").Str()
	if dec == nil || dec.Kind != jsonv.Object || kind != "human" || id != "acct:"+st.Signer {
		return "decider"
	}
	return ""
}

// ScopeResult is a record held to a document's scope (§9.9). Names are
// the constraints of Verification §4.12: schemaVersion, aiSystemIds,
// actions, models, predicate:<name>, confirm:<name>, and restriction when
// the record's own schema version is one this version does not hold.
type ScopeResult struct {
	AgentIn        bool
	Failed         []string
	Undeterminable []string
	// Evaded names the confirm predicates that hold on a record whose
	// confirm is false.
	Evaded []string
}

// Within reports whether every constraint holds.
func (r ScopeResult) Within() bool {
	return r.AgentIn && len(r.Failed) == 0 && len(r.Undeterminable) == 0
}

func in(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// stepModels reads the models a record names: the modelDescriptorDigest of
// every step's aiBom that is not null. readable is false when a step's
// aiBom is not null and does not name its model as a string.
func stepModels(payload *jsonv.Value) (models []string, readable bool) {
	readable = true
	steps := member(member(payload, "contributions"), "steps")
	if steps == nil || steps.Kind != jsonv.Array {
		return nil, true
	}
	for _, s := range steps.A {
		a := member(s, "aiBom")
		if a == nil || a.Kind == jsonv.Null {
			continue
		}
		d, ok := member(a, "modelDescriptorDigest").Str()
		if a.Kind != jsonv.Object || !ok {
			readable = false
			continue
		}
		models = append(models, d)
	}
	return models, readable
}

// Scope holds a record to a document's scope. confirm is the record's
// expectation's confirm.
func Scope(d Document, payload *jsonv.Value, confirm bool) ScopeResult {
	var r ScopeResult
	dec := member(payload, "decider")
	id, _ := member(dec, "id").Str()
	agent, okAgent := member(dec, "agent").Str()
	r.AgentIn = id != "" && in(d.Agents, id) || okAgent && in(d.Agents, "desc:"+agent)

	switch sv, _ := member(payload, "schemaVersion").Str(); {
	case sv != "v1.0":
		r.Undeterminable = append(r.Undeterminable, "restriction")
	case sv != d.SchemaVersion:
		r.Failed = append(r.Failed, "schemaVersion")
	}
	if d.HasAISystemIDs {
		if s, ok := member(payload, "aiSystemId").Str(); !ok || !in(d.AISystemIDs, s) {
			r.Failed = append(r.Failed, "aiSystemIds")
		}
	}
	if d.HasActions {
		if s, ok := member(payload, "action").Str(); !ok || !in(d.Actions, s) {
			r.Failed = append(r.Failed, "actions")
		}
	}
	if d.HasModels {
		models, readable := stepModels(payload)
		outside := false
		for _, m := range models {
			if !in(d.Models, m) {
				outside = true
			}
		}
		switch {
		case outside:
			r.Failed = append(r.Failed, "models")
		case !readable || len(models) == 0:
			r.Undeterminable = append(r.Undeterminable, "models")
		}
	}
	for _, p := range d.Scope {
		switch p.Evaluate(payload) {
		case False:
			r.Failed = append(r.Failed, "predicate:"+p.Name)
		case Undeterminable:
			r.Undeterminable = append(r.Undeterminable, "predicate:"+p.Name)
		}
	}
	if !confirm {
		var undet []string
		for _, p := range d.Confirm {
			switch p.Evaluate(payload) {
			case True:
				r.Evaded = append(r.Evaded, p.Name)
			case Undeterminable:
				undet = append(undet, "confirm:"+p.Name)
			}
		}
		if len(r.Evaded) == 0 {
			r.Undeterminable = append(r.Undeterminable, undet...)
		}
	}
	return r
}

func names(xs []string) *jsonv.Value {
	a := report.Arr()
	for _, x := range xs {
		a.A = append(a.A, report.S(x))
	}
	return a
}

// ScopeRow decides mandate.scope from its step 2 on (Verification §4.12):
// the caller has applied step 1. It also returns whether the document was
// read, which mandate.limits needs.
func ScopeRow(payload *jsonv.Value, block *Block, confirm bool) (report.Check, *Document) {
	c := report.Check{ID: IDScope}
	if block == nil || block.Document == nil {
		c.Outcome, c.Reason = report.NotChecked, ReasonNoDocument
		return c, nil
	}
	if v, ok := member(block.Document, "v").Str(); !ok || v != DocumentVersion {
		c.Outcome, c.Reason = report.Abstain, ReasonUnsupportedDocument
		return c, nil
	}
	d, ok := ParseDocument(block.Document, false)
	if !ok {
		c.Outcome, c.Reason = report.Wrong, ReasonMalformedDocument
		return c, nil
	}
	r := Scope(d, payload, confirm)
	switch {
	case !r.AgentIn:
		c.Outcome, c.Reason = report.Wrong, ReasonAgentNotIn
	case len(r.Failed) > 0:
		c.Outcome, c.Reason = report.Wrong, ReasonOutside
		c.Facts = []report.Fact{{Name: "failed", Value: names(r.Failed)}}
	case len(r.Evaded) > 0:
		c.Outcome, c.Reason = report.Wrong, ReasonConfirmationEvaded
		c.Facts = []report.Fact{{Name: "confirm", Value: names(r.Evaded)}}
	case len(r.Undeterminable) > 0:
		c.Outcome, c.Reason = report.NotChecked, ReasonUndeterminable
		c.Facts = []report.Fact{{Name: "undeterminable", Value: names(r.Undeterminable)}}
	default:
		c.Outcome = report.Correct
	}
	return c, &d
}

// LimitsRow holds a record to a document's limits (§9.9) from step 4 of
// mandate.limits on: the caller has applied steps 1 to 3. exp is the
// record's signoffExpectation.
func LimitsRow(d Document, payload, exp *jsonv.Value) report.Check {
	c := report.Check{ID: IDLimits}
	slot, okSlot := grammar.Integer(member(exp, "mandateSeq"))
	if !okSlot || slot < 1 {
		c.Outcome, c.Reason = report.Wrong, ReasonTotalsMalformed
		return c
	}
	totals := member(exp, "totals")
	if totals == nil {
		totals = &jsonv.Value{Kind: jsonv.Null}
	}
	c.Facts = []report.Fact{{Name: "slot", Value: report.N(slot)}, {Name: "totals", Value: totals}}
	wrong := func(reason string) report.Check {
		c.Outcome, c.Reason = report.Wrong, reason
		return c
	}
	if d.Caps == nil {
		if totals.Kind != jsonv.Null {
			return wrong(ReasonTotalsMalformed)
		}
	} else if totals.Kind != jsonv.Object || len(totals.O) != len(d.Caps) {
		return wrong(ReasonTotalsMalformed)
	}
	running := make([]uint64, len(d.Caps))
	values := make([]uint64, len(d.Caps))
	for i, cp := range d.Caps {
		t, ok := grammar.Integer(member(totals, cp.Name))
		if !ok {
			return wrong(ReasonTotalsMalformed)
		}
		sv, okv := Resolve(payload, cp.toks)
		v, ok := grammar.Integer(sv)
		if !okv || !ok {
			return wrong(ReasonTotalsMalformed)
		}
		running[i], values[i] = t, v
	}
	if d.MaxRecords != nil && slot > *d.MaxRecords {
		return wrong(ReasonLimitExceeded)
	}
	for i, cp := range d.Caps {
		if running[i] < values[i] || running[i] > cp.Max {
			return wrong(ReasonLimitExceeded)
		}
	}
	c.Outcome = report.Correct
	return c
}
