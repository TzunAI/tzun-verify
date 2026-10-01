// Package contrib reads payload.contributions (Record §7) and decides the
// rows contributions, contributions.binding and contributions.pipeline of
// Verification §4.10. A bare §n in this package's comments is a section of
// Record.
//
// The contributions row checks the form of the member: its grammar, the
// rules of §7.3 and the step chain. contributions.binding checks the
// process the steps state (§7.5), which a writer may record as it happened:
// its findings are about the decision, never about the record's form.
package contrib

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/decider"
	"github.com/TzunAI/tzun-verify/internal/grammar"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// Row ids and reasons (Verification §4.10).
const (
	ID         = "contributions"
	IDBinding  = "contributions.binding"
	IDPipeline = "contributions.pipeline"

	ReasonAbsent              = "absent"
	ReasonMalformed           = "malformed_contributions"
	ReasonChainBroken         = "step_chain_broken"
	ReasonNotDecidingActor    = "decider_not_deciding_actor"
	ReasonDecidingOutput      = "deciding_output_mismatch"
	ReasonUnsupportedKind     = "unsupported_actor_kind"
	ReasonUnsupportedScheme   = "unsupported_identifier_scheme"
	ReasonInputUndeclared     = "input_undeclared"
	ReasonReviewUnbound       = "review_unbound"
	ReasonDecisionUnbound     = "decision_unbound"
	ReasonDecidedOutputDiffer = "decided_output_differs"
	ReasonUnsupportedPipeline = "unsupported_pipeline"
)

// The step classes of §7.1.
const (
	ClassPropose = "propose"
	ClassReview  = "review"
	ClassDecide  = "decide"
	ClassOther   = "other"
)

// OutputDigest is "sha256:" and the hex SHA-256 of the canonical bytes of a
// value (§7.2).
func OutputDigest(v *jsonv.Value) (string, error) {
	b, err := canonical.Serialize(v)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:]), nil
}

// StepDigest is the output digest of a step (§7.2).
func StepDigest(step *jsonv.Value) (string, error) { return OutputDigest(step) }

// Step is one well-formed step.
type Step struct {
	Raw   *jsonv.Value
	Class string
	// Actor is nil for a null actor.
	Actor *decider.Identity
	// AIBom is the step's aiBom, nil for null.
	AIBom   *jsonv.Value
	Inputs  []string
	Output  string
	Verdict string
	// Prev is "" for null.
	Prev string
}

// Contributions is a well-formed contributions member.
type Contributions struct {
	Pipeline  string
	Externals []string
	Steps     []Step
	// Deciding is the index of the deciding step, -1 for none.
	Deciding int
}

func member(v *jsonv.Value, key string) *jsonv.Value {
	m, _ := v.Get(key)
	return m
}

// class reads a role (§7.1): a class, optionally ":" and a name.
func class(role string) (string, bool) {
	c, name, hasName := strings.Cut(role, ":")
	switch c {
	case ClassPropose, ClassReview, ClassDecide, ClassOther:
	default:
		return "", false
	}
	if hasName && !grammar.RoleName(name) {
		return "", false
	}
	return c, true
}

// parseStep reads one step under §7.1 and the per-step rules of §7.3.
func parseStep(v *jsonv.Value) (Step, bool) {
	if !grammar.Exact(v, "role", "actor", "aiBom", "inputs", "output", "verdict", "reason", "prev") {
		return Step{}, false
	}
	s := Step{Raw: v}
	role, ok := member(v, "role").Str()
	if !ok {
		return Step{}, false
	}
	if s.Class, ok = class(role); !ok {
		return Step{}, false
	}
	if a := member(v, "aiBom"); !grammar.IsNull(a) {
		if a.Kind != jsonv.Object {
			return Step{}, false
		}
		s.AIBom = a
	}
	if a := member(v, "actor"); grammar.IsNull(a) {
		// A step has an identity or a model, and a decision has an
		// identity.
		if s.AIBom == nil || s.Class == ClassDecide {
			return Step{}, false
		}
	} else {
		idn, ok := decider.ParseActor(a)
		if !ok || decider.KnownKind(idn.Kind) && !decider.Consistent(idn) {
			return Step{}, false
		}
		s.Actor = &idn
	}
	if s.Inputs, ok = grammar.Set(member(v, "inputs"), 0, 64, grammar.PrefixedDigest); !ok {
		return Step{}, false
	}
	if s.Output, ok = member(v, "output").Str(); !ok || !grammar.PrefixedDigest(s.Output) {
		return Step{}, false
	}
	switch vd := member(v, "verdict"); {
	case grammar.IsNull(vd):
	default:
		s.Verdict, ok = vd.Str()
		if !ok || s.Verdict != "approve" && s.Verdict != "reject" && s.Verdict != "concerns" {
			return Step{}, false
		}
		if s.Class == ClassPropose || s.Class == ClassOther {
			return Step{}, false
		}
	}
	if r := member(v, "reason"); !grammar.IsNull(r) {
		if r.Kind != jsonv.String {
			return Step{}, false
		}
	}
	if p := member(v, "prev"); !grammar.IsNull(p) {
		s.Prev, ok = p.Str()
		if !ok || !grammar.PrefixedDigest(s.Prev) {
			return Step{}, false
		}
	}
	return s, true
}

// Parse reads contributions under §7.1 and §7.3, apart from the vocabulary
// of an actor's kind and scheme. On failure, step is the index of the step
// that breaks a rule of its own, -1 when the failure is not one step's.
func Parse(v *jsonv.Value) (c Contributions, step int, ok bool) {
	if !grammar.Exact(v, "pipeline", "externals", "steps") {
		return c, -1, false
	}
	if p := member(v, "pipeline"); !grammar.IsNull(p) {
		s, ok := p.Str()
		if !ok || !grammar.PrefixedDigest(s) {
			return c, -1, false
		}
		c.Pipeline = s
	}
	if c.Externals, ok = grammar.Set(member(v, "externals"), 0, 64, grammar.PrefixedDigest); !ok {
		return c, -1, false
	}
	steps := member(v, "steps")
	if steps == nil || steps.Kind != jsonv.Array || len(steps.A) < 1 || len(steps.A) > 32 {
		return c, -1, false
	}
	c.Deciding = -1
	for i, sv := range steps.A {
		s, ok := parseStep(sv)
		if !ok {
			return c, i, false
		}
		c.Steps = append(c.Steps, s)
	}
	for i, s := range c.Steps {
		switch {
		case s.Class == ClassDecide && c.Deciding >= 0:
			return c, -1, false
		case s.Class == ClassDecide:
			c.Deciding = i
		case c.Deciding >= 0 && (s.Class == ClassPropose || s.Class == ClassReview):
			return c, i, false
		}
	}
	return c, -1, true
}

// sameIdentity compares a decider and an actor as canonical bytes of their
// kind, id and agent (§7.3).
func sameIdentity(d, a *jsonv.Value) bool {
	pick := func(v *jsonv.Value) []byte {
		o := &jsonv.Value{Kind: jsonv.Object}
		for _, k := range []string{"kind", "id", "agent"} {
			m, ok := v.Get(k)
			if !ok {
				m = &jsonv.Value{Kind: jsonv.Null}
			}
			o.O = append(o.O, jsonv.Member{Key: k, Value: m})
		}
		b, err := canonical.Serialize(o)
		if err != nil {
			return nil
		}
		return b
	}
	x, y := pick(d), pick(a)
	return x != nil && y != nil && string(x) == string(y)
}

// decisionDigest is outputDigest({action, reason}) from the record's own
// members, null for one the payload lacks (§7.3).
func decisionDigest(payload *jsonv.Value) (string, error) {
	o := &jsonv.Value{Kind: jsonv.Object}
	for _, k := range []string{"action", "reason"} {
		m, ok := payload.Get(k)
		if !ok {
			m = &jsonv.Value{Kind: jsonv.Null}
		}
		o.O = append(o.O, jsonv.Member{Key: k, Value: m})
	}
	return OutputDigest(o)
}

// Result is the three rows of one record. Pipeline is nil when the row is
// not reported.
type Result struct {
	Row      report.Check
	Binding  report.Check
	Pipeline *report.Check
}

func failedStep(i int) report.Fact {
	return report.Fact{Name: "failedStep", Value: report.N(uint64(i))}
}

// Check decides the rows of Verification §4.10 for a payload whose digest
// holds. linkTargets are the target digests the record's links declare, nil
// when its links do not meet the grammar of Record §8.2 (they then declare
// no input).
func Check(payload *jsonv.Value, linkTargets []string) Result {
	v := member(payload, "contributions")
	if v == nil || v.Kind == jsonv.Null {
		return Result{
			Row:     report.Check{ID: ID, Outcome: report.NotChecked, Reason: ReasonAbsent},
			Binding: report.Check{ID: IDBinding, Outcome: report.NotChecked, Reason: ReasonAbsent},
		}
	}
	res := Result{Row: report.Check{ID: ID}}
	blocked := report.BlockedBy(IDBinding, ID)
	wrong := func(reason string, facts ...report.Fact) Result {
		res.Row.Outcome, res.Row.Reason, res.Row.Facts = report.Wrong, reason, facts
		res.Binding = blocked
		return res
	}
	c, bad, ok := Parse(v)
	if !ok {
		if bad >= 0 {
			return wrong(ReasonMalformed, failedStep(bad))
		}
		return wrong(ReasonMalformed)
	}
	for i, s := range c.Steps {
		want := ""
		if i > 0 {
			d, err := StepDigest(c.Steps[i-1].Raw)
			if err != nil {
				return wrong(ReasonMalformed)
			}
			want = d
		}
		if s.Prev != want {
			return wrong(ReasonChainBroken, failedStep(i))
		}
	}
	if c.Deciding >= 0 {
		s := c.Steps[c.Deciding]
		if !sameIdentity(member(payload, "decider"), member(s.Raw, "actor")) {
			return wrong(ReasonNotDecidingActor, failedStep(c.Deciding))
		}
	}
	decision, err := decisionDigest(payload)
	if err != nil {
		return wrong(ReasonMalformed)
	}
	for i, s := range c.Steps {
		if s.Class == ClassDecide && s.Output != decision {
			return wrong(ReasonDecidingOutput, failedStep(i))
		}
	}
	for _, s := range c.Steps {
		if s.Actor != nil && !decider.KnownKind(s.Actor.Kind) {
			res.Row.Outcome, res.Row.Reason, res.Binding = report.Abstain, ReasonUnsupportedKind, blocked
			return res
		}
	}
	for _, s := range c.Steps {
		if s.Actor != nil && !decider.KnownScheme(s.Actor.Scheme) {
			res.Row.Outcome, res.Row.Reason, res.Binding = report.Abstain, ReasonUnsupportedScheme, blocked
			return res
		}
	}

	res.Row.Outcome = report.Correct
	// The distinct model digests that are strings, in the order the steps
	// first name them, as the conformance vectors state them.
	seen := map[string]bool{}
	ms := report.Arr()
	for _, s := range c.Steps {
		if d, ok := member(s.AIBom, "modelDescriptorDigest").Str(); ok && !seen[d] {
			seen[d] = true
			ms.A = append(ms.A, report.S(d))
		}
	}
	deciding := report.S("record")
	if c.Deciding >= 0 {
		deciding = report.N(uint64(c.Deciding))
	}
	res.Row.Facts = []report.Fact{
		{Name: "steps", Value: report.N(uint64(len(c.Steps)))},
		{Name: "models", Value: ms},
		{Name: "decidingStep", Value: deciding},
	}
	res.Binding = binding(payload, c, linkTargets)
	if c.Pipeline != "" {
		res.Pipeline = &report.Check{ID: IDPipeline, Outcome: report.Abstain, Reason: ReasonUnsupportedPipeline}
	}
	return res
}

func indexes(xs []int) *jsonv.Value {
	a := report.Arr()
	for _, x := range xs {
		a.A = append(a.A, report.N(uint64(x)))
	}
	return a
}

// binding decides contributions.binding (§7.5, Verification §4.10) for
// contributions that are well formed.
func binding(payload *jsonv.Value, c Contributions, linkTargets []string) report.Check {
	row := report.Check{ID: IDBinding}

	// P*: the last propose step before the deciding step, or the last
	// propose step when there is none.
	pstar := -1
	limit := len(c.Steps)
	if c.Deciding >= 0 {
		limit = c.Deciding
	}
	var proposals []int
	for i, s := range c.Steps {
		if s.Class == ClassPropose {
			proposals = append(proposals, i)
			if i < limit {
				pstar = i
			}
		}
	}
	// covers[i] is the propose step a review covers: the last one before
	// it, -1 for none. An approval counts only when the review is bound to
	// the output it covers, as the conformance vectors count it: an unbound
	// review is the finding review_unbound, never an approval.
	var approvals, stale, uncovered []int
	covers := map[int]int{}
	last := -1
	for i, s := range c.Steps {
		switch s.Class {
		case ClassPropose:
			last = i
		case ClassReview:
			covers[i] = last
			switch {
			case last < 0:
				uncovered = append(uncovered, i)
			case s.Verdict != "approve" || !contains(s.Inputs, c.Steps[last].Output):
			case pstar >= 0 && c.Steps[last].Output == c.Steps[pstar].Output:
				approvals = append(approvals, i)
			default:
				stale = append(stale, i)
			}
		}
	}
	decisionBinding := "checked"
	if pstar < 0 {
		decisionBinding = "not-applicable"
	}
	row.Facts = []report.Fact{
		{Name: "proposals", Value: indexes(proposals)},
		{Name: "approvals", Value: indexes(approvals)},
		{Name: "staleApprovals", Value: indexes(stale)},
		{Name: "uncoveredReviews", Value: indexes(uncovered)},
		{Name: "decisionBinding", Value: report.S(decisionBinding)},
	}
	fail := func(reason string, step int, digest string) report.Check {
		row.Outcome, row.Reason = report.Wrong, reason
		row.Facts = append(row.Facts, failedStep(step), report.Fact{Name: "failedDigest", Value: report.S(digest)})
		return row
	}

	// Input provenance.
	declared := map[string]bool{}
	for _, e := range c.Externals {
		declared[e] = true
	}
	for _, t := range linkTargets {
		declared["sha256:"+t] = true
	}
	produced := map[string]bool{}
	for i, s := range c.Steps {
		for _, in := range s.Inputs {
			if !produced[in] && !declared[in] {
				return fail(ReasonInputUndeclared, i, in)
			}
		}
		produced[s.Output] = true
	}
	// Review binding.
	for i, s := range c.Steps {
		if s.Class != ClassReview || covers[i] < 0 {
			continue
		}
		out := c.Steps[covers[i]].Output
		if !contains(s.Inputs, out) {
			return fail(ReasonReviewUnbound, i, out)
		}
	}
	// Decision binding.
	if pstar >= 0 {
		out := c.Steps[pstar].Output
		if c.Deciding >= 0 && !contains(c.Steps[c.Deciding].Inputs, out) {
			return fail(ReasonDecisionUnbound, c.Deciding, out)
		}
		ai, ok := payload.Get("aiOutput")
		if !ok {
			ai = &jsonv.Value{Kind: jsonv.Null}
		}
		if d, err := OutputDigest(ai); err != nil || d != out {
			return fail(ReasonDecidedOutputDiffer, pstar, out)
		}
	}
	row.Outcome = report.Correct
	return row
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
