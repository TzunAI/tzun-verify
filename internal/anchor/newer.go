package anchor

import (
	"github.com/TzunAI/tzun-verify/internal/checkpoint"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/merkle"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// Check ids of §10.8. A bundle reports anchor.consistency once per origin,
// as anchor.consistency[<origin>].
const (
	IDNewer       = "anchor.newer"
	IDConsistency = "anchor.consistency"
)

// Reasons of §10.8.
const (
	ReasonSplitView     = "split_view"
	ReasonInconsistent  = "log_inconsistent_with_anchor"
	ReasonNoConsistency = "not_in_bundle:consistency_proof"
)

// ConsistencyID is the check id of the consistency between two checkpoint
// bodies of one log.
func ConsistencyID(origin string) string { return IDConsistency + "[" + origin + "]" }

// Consistency is §10.8 between two authenticated checkpoint bodies of one
// log, with both sizes and roots taken from the parsed bodies. proof is the
// carried PROOF(m, n) between the smaller and the larger size, nil when none
// is carried. The caller has already established that both bodies are
// authenticated.
func Consistency(id string, a, b *checkpoint.Body, proof *jsonv.Value) report.Check {
	if a.Size > b.Size {
		a, b = b, a
	}
	sizes := []report.Fact{{Name: "fromSize", Value: report.N(a.Size)}, {Name: "toSize", Value: report.N(b.Size)}}
	if a.Size == b.Size {
		if string(a.Root) != string(b.Root) {
			return report.Check{ID: id, Outcome: report.Wrong, Reason: ReasonSplitView}
		}
		return report.Check{ID: id, Outcome: report.Correct, Facts: sizes}
	}
	if proof == nil {
		return report.Check{ID: id, Outcome: report.NotChecked, Reason: ReasonNoConsistency}
	}
	path, ok := merkle.ParsePath(proof)
	if !ok || !merkle.VerifyConsistency(a.Size, b.Size, path, a.Root, b.Root) {
		return report.Check{ID: id, Outcome: report.Wrong, Reason: ReasonInconsistent}
	}
	return report.Check{ID: id, Outcome: report.Correct, Facts: sizes}
}
