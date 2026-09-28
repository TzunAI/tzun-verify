package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// Version is the report format.
const Version = "tzun-verify-report/1"

// Report is one verification's result (Verification §6).
type Report struct {
	BundleVersion *jsonv.Value
	Subject       *jsonv.Value
	Inputs        *jsonv.Value
	Checks        []Check
	// Summary is derived from the checks and the verdicts, never an input.
	Summary *jsonv.Value
	// CheckedAt is excluded from comparisons.
	CheckedAt time.Time
}

// IDBundle is the row on the bundle as a whole (Bundle §4): its
// version, its profile and the shape of its slots. A report whose bundle row
// fails has no other row, and exits 2.
const IDBundle = "bundle"

// Readable reports whether the bundle check holds: the bundle was neither
// abstained on as a whole nor unreadable.
func (r *Report) Readable() bool {
	for _, c := range r.Checks {
		if c.ID == IDBundle {
			return c.Outcome == Correct
		}
	}
	return false
}

// CheckJSON renders one check: id, outcome, reason when set, facts when any.
func CheckJSON(c Check) *jsonv.Value {
	o := Obj("id", S(c.ID), "outcome", S(string(c.Outcome)))
	if c.Reason != "" {
		o.O = append(o.O, jsonv.Member{Key: "reason", Value: S(c.Reason)})
	}
	if len(c.Facts) > 0 {
		f := &jsonv.Value{Kind: jsonv.Object}
		for _, x := range c.Facts {
			f.O = append(f.O, jsonv.Member{Key: x.Name, Value: x.Value})
		}
		o.O = append(o.O, jsonv.Member{Key: "facts", Value: f})
	}
	return o
}

// JSON renders the report. withCheckedAt adds checkedAt, which comparisons
// leave out.
func (r *Report) JSON(withCheckedAt bool) *jsonv.Value {
	checks := Arr()
	for _, c := range r.Checks {
		checks.A = append(checks.A, CheckJSON(c))
	}
	o := Obj(
		"reportVersion", S(Version),
		"bundleVersion", orNull(r.BundleVersion),
		"subject", orNull(r.Subject),
		"inputs", orNull(r.Inputs),
		"checks", checks,
		"summary", orNull(r.Summary),
	)
	if withCheckedAt {
		o.O = append(o.O, jsonv.Member{Key: "checkedAt", Value: S(r.CheckedAt.UTC().Format("2006-01-02T15:04:05.000Z"))})
	}
	return o
}

// Canonical serialises the report in DEO canonical form.
func (r *Report) Canonical(withCheckedAt bool) ([]byte, error) {
	return canonical.Serialize(r.JSON(withCheckedAt))
}

func orNull(v *jsonv.Value) *jsonv.Value {
	if v == nil {
		return Null()
	}
	return v
}

// Counts counts each outcome.
func Counts(checks []Check) map[Outcome]int {
	m := map[Outcome]int{Correct: 0, Wrong: 0, NotChecked: 0, Abstain: 0}
	for _, c := range checks {
		m[c.Outcome]++
	}
	return m
}

// CountsJSON renders Counts: the summary's outcomes.
func CountsJSON(checks []Check) *jsonv.Value {
	m := Counts(checks)
	return Obj(
		string(Abstain), N(uint64(m[Abstain])),
		string(Correct), N(uint64(m[Correct])),
		string(Wrong), N(uint64(m[Wrong])),
		string(NotChecked), N(uint64(m[NotChecked])),
	)
}

// Policy is the auditor's regime (Verification §3.2).
type Policy struct {
	// Require lists check ids that must be checked-correct. An id ending in
	// "[*]" matches that check at every index.
	Require []string
	// RequireRungs lists sign-off rungs that must be met.
	RequireRungs []string
	// AllowUnchecked turns off exit code 4.
	AllowUnchecked bool
}

// Exit codes of Verification §6.6.
const (
	ExitOK         = 0
	ExitWrong      = 1
	ExitBundle     = 2
	ExitRequire    = 3
	ExitUnchecked  = 4
	ExitUsageError = 64
)

// matches reports whether a --require pattern names a check id.
func matches(pattern, id string) bool {
	if strings.HasSuffix(pattern, "[*]") {
		base := strings.TrimSuffix(pattern, "[*]")
		if !strings.HasPrefix(id, base+"[") || !strings.HasSuffix(id, "]") {
			return false
		}
		idx := id[len(base)+1 : len(id)-1]
		if idx == "" {
			return false
		}
		for _, c := range idx {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	return pattern == id
}

// Unchecked reports whether a row leaves an artifact present in the bundle
// abstained on or not checked (Verification §6.6): every
// abstention, and every not-checked row except not_applicable and absent,
// which are not unchecked artifacts. A row blocked_by another counts, since
// the artifact behind it was never checked. That section also exempts a row
// blocked_by a check that failed;
// ExitCode returns 1 before it asks about exit 4 whenever a check failed, so
// that exemption never has a row to apply to.
func Unchecked(c Check) bool {
	switch c.Outcome {
	case Abstain:
		return true
	case NotChecked:
		return c.Reason != "not_applicable" && c.Reason != "absent"
	}
	return false
}

// RequireMet reports whether every --require pattern names at least one
// check and every check it names is checked-correct, and whether every
// required rung is met. This build verifies no sign-off, so no rung is met.
func RequireMet(checks []Check, p Policy) bool {
	for _, pat := range p.Require {
		seen := false
		for _, c := range checks {
			if matches(pat, c.ID) {
				seen = true
				if c.Outcome != Correct {
					return false
				}
			}
		}
		if !seen {
			return false
		}
	}
	return len(p.RequireRungs) == 0
}

// ExitCode applies Verification §6.6: 2 when the bundle check is
// not checked-correct,
// then 1, then 3, then 4, then 0.
func ExitCode(r *Report, p Policy) int {
	if !r.Readable() {
		return ExitBundle
	}
	for _, c := range r.Checks {
		if c.Outcome == Wrong {
			return ExitWrong
		}
	}
	if !RequireMet(r.Checks, p) {
		return ExitRequire
	}
	if !p.AllowUnchecked {
		for _, c := range r.Checks {
			if Unchecked(c) {
				return ExitUnchecked
			}
		}
	}
	return ExitOK
}

// label is the line tag of the human-readable report.
func label(o Outcome) string {
	switch o {
	case Correct:
		return "OK"
	case Wrong:
		return "FAIL"
	case NotChecked:
		return "NOT CHECKED"
	case Abstain:
		return "ABSTAIN"
	}
	return string(o)
}

func factText(v *jsonv.Value) string {
	b, err := canonical.Serialize(v)
	if err != nil {
		return "?"
	}
	s := string(b)
	if v.Kind == jsonv.String {
		s = v.S
	}
	return s
}

// WriteText prints the human-readable report: every check, with every
// not-checked and every abstention and its reason, then the summary lines
// and the exit code.
func WriteText(w io.Writer, r *Report, header []string, summary []string, exit int) {
	for _, h := range header {
		fmt.Fprintln(w, h)
	}
	// Reasons line up after the ids, up to a width; a longer id, such as a
	// consistency check named by its log's origin, pushes its own reason
	// along. Facts go on the next line, under the id.
	const maxWidth = 24
	width := 0
	for _, c := range r.Checks {
		if len(c.ID) > width && len(c.ID) <= maxWidth {
			width = len(c.ID)
		}
	}
	for _, c := range r.Checks {
		line := fmt.Sprintf("  %-11s %-*s", label(c.Outcome), width, c.ID)
		if c.Reason != "" {
			line += "  " + c.Reason
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
		if len(c.Facts) > 0 {
			names := make([]string, 0, len(c.Facts))
			vals := map[string]string{}
			for _, f := range c.Facts {
				names = append(names, f.Name)
				vals[f.Name] = factText(f.Value)
			}
			sort.Strings(names)
			parts := make([]string, 0, len(names))
			for _, n := range names {
				parts = append(parts, n+"="+vals[n])
			}
			fmt.Fprintf(w, "  %-11s   %s\n", "", strings.Join(parts, " "))
		}
	}
	for _, s := range summary {
		fmt.Fprintln(w, s)
	}
	m := Counts(r.Checks)
	fmt.Fprintf(w, "Result      %d correct · %d wrong · %d not checked · %d abstained        exit %d\n",
		m[Correct], m[Wrong], m[NotChecked], m[Abstain], exit)
}
