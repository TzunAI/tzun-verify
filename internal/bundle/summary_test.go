// SPDX-License-Identifier: BSD-3-Clause-Clear

package bundle

import (
	"testing"
	"time"

	"github.com/TzunAI/tzun-verify/internal/anchor"
	"github.com/TzunAI/tzun-verify/internal/rfc3161"
)

// TestExistedByOrder: the summary's existedBy is the earliest bound, and of
// equal instants it names the record's anchor, then the newer anchor, then
// the record timestamp (Verification §6.4). Instants compare as the report
// writes them, to the millisecond with the digits beyond dropped
// (Verification §6.5), so bounds that differ only below the millisecond
// are equal instants.
func TestExistedByOrder(t *testing.T) {
	at := time.Date(2026, 9, 27, 13, 9, 41, 0, time.UTC)
	yes, no := true, false
	verdict := func(valid *bool, when time.Time, source string) *anchor.Verdict {
		return &anchor.Verdict{Valid: valid, ExistedBy: &anchor.ExistedBy{At: when, Source: source}}
	}
	record := func(when time.Time) *rfc3161.Result { return &rfc3161.Result{GenTime: when} }
	us := time.Microsecond
	for _, c := range []struct {
		name       string
		own, newer *anchor.Verdict
		rec        *rfc3161.Result
		at         time.Time
		source     string
		check      string
	}{
		{"all three at one instant", verdict(&yes, at, "evm-calldata"), verdict(&yes, at, "evm-calldata"), record(at),
			at, "evm-calldata", anchor.IDAnchor},
		{"the record's anchor false", verdict(&no, at, "evm-calldata"), verdict(&yes, at, "evm-calldata"), record(at),
			at, "evm-calldata", anchor.IDNewer},
		{"no anchor", nil, nil, record(at),
			at, "record-timestamp", rfc3161.IDRecordTrust},
		{"the record timestamp a millisecond earlier", verdict(&yes, at, "evm-calldata"), verdict(&yes, at, "evm-calldata"), record(at.Add(-time.Millisecond)),
			at.Add(-time.Millisecond), "record-timestamp", rfc3161.IDRecordTrust},
		{"the record's anchor at +0.5 ms, the record timestamp at +0.1 ms", verdict(&yes, at.Add(500*us), "rfc3161"), nil, record(at.Add(100 * us)),
			at, "rfc3161", anchor.IDAnchor},
		{"the record's anchor at +0.9 ms, the newer at +0.2 ms", verdict(&yes, at.Add(900*us), "rfc3161"), verdict(&yes, at.Add(200*us), "rfc3161"), nil,
			at, "rfc3161", anchor.IDAnchor},
		{"the record timestamp alone at +0.7 ms", nil, nil, record(at.Add(700 * us)),
			at, "record-timestamp", rfc3161.IDRecordTrust},
	} {
		v := &verification{res: &Result{Anchor: c.own, Newer: c.newer}, recordTS: c.rec}
		e := v.existedBy()
		if e == nil || !e.At.Equal(c.at) || e.Source != c.source || e.Check != c.check {
			t.Errorf("%s: existedBy %+v, want %s %s at %s", c.name, e, c.check, c.source, c.at.Format(timeLayout))
		}
	}
}
