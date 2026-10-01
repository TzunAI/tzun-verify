// Package report holds the check model of the verification contract
// (Verification §2, Anchor §10.1), the tzun-verify-report/1
// JSON report, the human-readable report and the exit codes of
// Verification §6.
package report

import (
	"strings"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// Outcome is one of the four outcomes of Verification §2.1.
type Outcome string

// The four outcomes.
const (
	Correct    Outcome = "checked-correct"
	Wrong      Outcome = "checked-wrong"
	NotChecked Outcome = "not-checked"
	Abstain    Outcome = "abstain"
)

// Fact is one named fact of a check. Value is a JSON value built with the
// helpers below.
type Fact struct {
	Name  string
	Value *jsonv.Value
}

// Check is one entry of the report's checks list.
type Check struct {
	ID      string
	Outcome Outcome
	// Reason is empty on a checked-correct check with no reason.
	Reason string
	Facts  []Fact
}

// Decided reports whether a check was decided and holds.
func (c *Check) Decided() bool { return c != nil && c.Outcome == Correct }

// SetFact adds or replaces a fact.
func (c *Check) SetFact(name string, v *jsonv.Value) {
	for i := range c.Facts {
		if c.Facts[i].Name == name {
			c.Facts[i].Value = v
			return
		}
	}
	c.Facts = append(c.Facts, Fact{Name: name, Value: v})
}

// Fact returns a fact by name.
func (c *Check) Fact(name string) (*jsonv.Value, bool) {
	for _, f := range c.Facts {
		if f.Name == name {
			return f.Value, true
		}
	}
	return nil, false
}

// BlockedBy is the not-checked outcome of a check whose prerequisite was
// not decided (Verification §2.2).
func BlockedBy(id, prerequisite string) Check {
	return Check{ID: id, Outcome: NotChecked, Reason: "blocked_by:" + prerequisite}
}

// IsBlocked reports whether a reason is blocked_by:<id>.
func IsBlocked(reason string) bool { return strings.HasPrefix(reason, "blocked_by:") }

// JSON value helpers for facts.

// S is a JSON string.
func S(s string) *jsonv.Value { return &jsonv.Value{Kind: jsonv.String, S: s} }

// B is a JSON boolean.
func B(b bool) *jsonv.Value { return &jsonv.Value{Kind: jsonv.Bool, B: b} }

// N is a JSON number from an integer.
func N(n uint64) *jsonv.Value { return &jsonv.Value{Kind: jsonv.Number, N: float64(n)} }

// Int is a JSON number from a signed integer.
func Int(n int64) *jsonv.Value { return &jsonv.Value{Kind: jsonv.Number, N: float64(n)} }

// Null is the JSON null.
func Null() *jsonv.Value { return &jsonv.Value{Kind: jsonv.Null} }

// SOrNull is a string, or null when s is nil.
func SOrNull(s *string) *jsonv.Value {
	if s == nil {
		return Null()
	}
	return S(*s)
}

// Obj builds a JSON object from name/value pairs.
func Obj(kv ...any) *jsonv.Value {
	o := &jsonv.Value{Kind: jsonv.Object}
	for i := 0; i+1 < len(kv); i += 2 {
		o.O = append(o.O, jsonv.Member{Key: kv[i].(string), Value: kv[i+1].(*jsonv.Value)})
	}
	return o
}

// Arr builds a JSON array.
func Arr(vs ...*jsonv.Value) *jsonv.Value {
	a := &jsonv.Value{Kind: jsonv.Array, A: []*jsonv.Value{}}
	a.A = append(a.A, vs...)
	return a
}
