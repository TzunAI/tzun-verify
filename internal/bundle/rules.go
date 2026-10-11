// SPDX-License-Identifier: BSD-3-Clause-Clear

package bundle

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/contrib"
	"github.com/TzunAI/tzun-verify/internal/decider"
	"github.com/TzunAI/tzun-verify/internal/evm"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/links"
	"github.com/TzunAI/tzun-verify/internal/mandate"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// Row ids and reasons of the record rules that are not their packages'.
const (
	IDFreshness = "decider.freshness"

	ReasonUnsupportedFreshness = "unsupported_freshness_chain"
	ReasonFreshnessMismatch    = "freshness_block_mismatch"
)

// ruleRows are the rows of Verification §4.9 to §4.12, between the
// sign-off rows and the anchor rows: decider, contributions, links and
// mandates.
func (v *verification) ruleRows() {
	v.deciderRows()
	v.contributionRows()
	v.linkRows()
	v.mandateRows()
}

// expectationMalformed reports whether signoff.expectation found the
// expectation malformed (Record §9.2).
func (v *verification) expectationMalformed() bool {
	return v.expectation.Outcome == report.Wrong && v.expectation.Reason == ReasonMalformedExpectation
}

// humanMaterialBound reports whether the record carries human decision
// material that binds it (Record §6.5): a per-record assertion, with no
// sign-off block, that is a webauthn.get presenting the per-record
// challenge; or a batch sign-off that binds.
func (v *verification) humanMaterialBound() bool {
	m := v.material
	if m.assertion == nil {
		return false
	}
	if m.block == nil {
		return v.presentsPerRecord(m)
	}
	return v.bindsBatch(m)
}

// deciderRows are decider and decider.freshness (Verification §4.9).
func (v *verification) deciderRows() {
	if v.digest == nil {
		v.add(report.BlockedBy(decider.ID, IDDigest), report.BlockedBy(IDFreshness, IDDigest))
		return
	}
	dv, _ := v.payload.Get("decider")
	var row report.Check
	var d *decider.Decider
	if v.expectationMalformed() {
		row = report.BlockedBy(decider.ID, IDSignoffExpectation)
	} else {
		row, d = decider.Row(dv, v.exp.form, v.humanMaterialBound())
	}
	v.add(row)
	v.add(v.freshnessRow(dv, d))
}

// captureRE is the form of capturedAt that decider.freshness reads.
var captureRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$`)

// capturedAtMillis reads payload.capturedAt for captureLag: the pattern of
// Verification §4.9 naming a real instant, its fraction truncated to whole
// milliseconds.
func capturedAtMillis(payload *jsonv.Value) (int64, bool) {
	s, ok := member(payload, "capturedAt").Str()
	if !ok || !captureRE.MatchString(s) {
		return 0, false
	}
	base, frac, _ := strings.Cut(strings.TrimSuffix(s, "Z"), ".")
	t, err := time.Parse("2006-01-02T15:04:05", base)
	if err != nil || t.Format("2006-01-02T15:04:05") != base {
		return 0, false
	}
	ms := int64(0)
	for i := 0; i < 3; i++ {
		ms *= 10
		if i < len(frac) {
			ms += int64(frac[i] - '0')
		}
	}
	return t.Unix()*1000 + ms, true
}

// freshnessRow is decider.freshness: the finalized-block reference against
// the auditor's header source for its chain, asked as Anchor §10.4 items 8
// to 11 ask it, under the deadline every header-source call shares.
func (v *verification) freshnessRow(dv *jsonv.Value, d *decider.Decider) report.Check {
	c := report.Check{ID: IDFreshness}
	if dv == nil || dv.Kind == jsonv.Null {
		c.Outcome, c.Reason = report.NotChecked, ReasonAbsent
		return c
	}
	if f, ok := dv.Get("freshness"); dv.Kind == jsonv.Object && ok && f.Kind == jsonv.Null {
		c.Outcome, c.Reason = report.NotChecked, ReasonAbsent
		return c
	}
	if d == nil {
		return report.BlockedBy(IDFreshness, decider.ID)
	}
	f := d.Fresh
	if f.Namespace != "eip155" {
		c.Outcome, c.Reason = report.Abstain, ReasonUnsupportedFreshness
		return c
	}
	src := v.opts.Sources.For(f.Chain)
	if src == nil {
		c.Outcome, c.Reason = report.NotChecked, evm.ReasonNoSource
		return c
	}
	ctx, cancel := context.WithDeadline(context.Background(), v.deadline)
	defer cancel()
	notChecked := func(reason string) report.Check {
		c.Outcome, c.Reason = report.NotChecked, reason
		return c
	}
	chain, err := src.ChainID(ctx)
	if err != nil || chain == nil {
		if err == nil {
			err = errors.New("the header source gave no chain id")
		}
		return notChecked(evm.SourceErrReason(ctx, err))
	}
	want, _ := new(big.Int).SetString(f.Reference, 10)
	if chain.Cmp(want) != 0 {
		return notChecked(evm.ReasonSourceChain)
	}
	if fin := src.Finality(); fin.Declared {
		c.SetFact("finality", fin.JSON())
	}
	finalized, err := src.FinalizedHeight(ctx)
	if err != nil {
		return notChecked(evm.SourceErrReason(ctx, err))
	}
	if f.Block > finalized {
		return notChecked(evm.ReasonNotFinalized)
	}
	blk, err := src.BlockAt(ctx, f.Block)
	if err != nil {
		return notChecked(evm.SourceErrReason(ctx, err))
	}
	if blk == nil {
		return notChecked(evm.ReasonInconsistent)
	}
	if blk.Hash != common.HexToHash(f.Hash) {
		c.Outcome, c.Reason = report.Wrong, ReasonFreshnessMismatch
		return c
	}
	c.Outcome = report.Correct
	c.SetFact("blockTime", report.S(evm.ISOTime(blk.Time)))
	if at, ok := capturedAtMillis(v.payload); ok {
		c.SetFact("captureLag", report.Int(at-int64(blk.Time)*1000))
	}
	return c
}

// contributionRows are contributions, contributions.binding and, when
// reported, contributions.pipeline (Verification §4.10).
func (v *verification) contributionRows() {
	if v.digest == nil {
		v.add(report.BlockedBy(contrib.ID, IDDigest), report.BlockedBy(contrib.IDBinding, IDDigest))
		return
	}
	r := contrib.Check(v.payload, links.Targets(v.payload))
	v.add(r.Row, r.Binding)
	if r.Pipeline != nil {
		v.add(*r.Pipeline)
	}
}

// linkRows are links and, for a list of 1 to 256 elements, links[<i>] and
// links[<i>].edge (Verification §4.11). A bundle carries no target record,
// so no target is held.
func (v *verification) linkRows() {
	if v.digest == nil {
		v.add(report.BlockedBy(links.ID, IDDigest))
		if l := member(v.payload, "links"); l != nil && l.Kind == jsonv.Array && len(l.A) >= 1 && len(l.A) <= 256 {
			for i := range l.A {
				v.add(report.BlockedBy(links.LinkID(i), links.ID), links.EdgeRow(i))
			}
		}
		return
	}
	in := links.Input{Payload: v.payload, Malformed: v.expectationMalformed()}
	if v.exp != nil {
		in.Form = v.exp.form
	}
	r := links.Check(in)
	v.add(r.Row)
	v.add(r.Links...)
}

// mandateRows are mandate.issuance, mandate.scope, mandate.limits,
// mandate.key and mandate.assertionTimestamp, each when reported
// (Verification §4.12).
func (v *verification) mandateRows() {
	issuanceBlock := mandate.ReadBlock(member(v.nr, "mandateIssuance"))
	exp, _ := parseExpectation(v.payload)
	mandateForm := exp.form == decider.FormMandate

	var issuance report.Check
	reported := issuanceBlock != nil || mandate.Issuance(v.payload)
	if reported {
		if v.digest == nil {
			issuance = report.BlockedBy(mandate.IDIssuance, IDDigest)
		} else {
			issuance, _ = mandate.IssuanceRow(v.payload, issuanceBlock)
		}
		v.add(issuance)
	}

	if mandateForm {
		e := v.expectation
		held := e.Outcome == report.Correct || e.Outcome == report.NotChecked && e.Reason == ReasonConfirmationMissing
		block := v.material.mandate
		if !held {
			v.add(report.BlockedBy(mandate.IDScope, IDSignoffExpectation), report.BlockedBy(mandate.IDLimits, IDSignoffExpectation))
		} else {
			scope, doc := mandate.ScopeRow(v.payload, block, exp.confirm)
			v.add(scope)
			switch {
			case block == nil || block.Document == nil:
				v.add(report.Check{ID: mandate.IDLimits, Outcome: report.NotChecked, Reason: mandate.ReasonNoDocument})
			case doc == nil:
				v.add(report.BlockedBy(mandate.IDLimits, mandate.IDScope))
			default:
				v.add(mandate.LimitsRow(*doc, v.payload, exp.raw))
			}
		}
	}

	if mandateForm || issuanceBlock != nil {
		key := report.Check{ID: mandate.IDKey}
		switch {
		case mandateForm && v.expectation.Outcome == report.Wrong:
			key = report.BlockedBy(mandate.IDKey, IDSignoffExpectation)
		case !mandateForm && reported && issuance.Outcome == report.Wrong:
			key = report.BlockedBy(mandate.IDKey, mandate.IDIssuance)
		case member(v.root, "credentials") != nil:
			key.Outcome, key.Reason = report.Abstain, ReasonUnsupportedSignoff
		default:
			key.Outcome, key.Reason = report.NotChecked, ReasonNoCredential
		}
		v.add(key)
	}

	var timestamped *mandate.Block
	switch {
	case mandateForm:
		timestamped = v.material.mandate
	case mandate.Issuance(v.payload):
		timestamped = issuanceBlock
	}
	if timestamped != nil && timestamped.Timestamp != nil && timestamped.Timestamp.Kind != jsonv.Null {
		v.add(report.Check{ID: mandate.IDTimestamp, Outcome: report.Abstain, Reason: ReasonUnsupported})
	}
}

// confirmationRead reports whether the row signoff.expectation reads
// nonRepudiation.confirmation: when the payload's signoffExpectation is an
// object with a mandateAssertion member and a confirm member that is true
// (Verification §4.7).
func (v *verification) confirmationRead() bool {
	x := member(v.payload, "signoffExpectation")
	if x == nil || x.Kind != jsonv.Object || !x.Has("mandateAssertion") {
		return false
	}
	c, ok := x.Get("confirm")
	return ok && c.Kind == jsonv.Bool && c.B
}

// fieldSetFact names the earlier field set a mismatching stored digest
// recomputes under (Verification §4.3), "" for none.
func fieldSetFact(payload *jsonv.Value, stored []byte) string {
	return canonical.EarlierFieldSet(payload, hex.EncodeToString(stored))
}
