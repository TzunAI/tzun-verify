// SPDX-License-Identifier: BSD-3-Clause-Clear

// Package decider reads payload.decider (Record §6) and a step's actor
// (Record §7.1), and decides the decider row of Verification §4.9. A bare
// §n in this package's comments is a section of Record.
//
// A reader judges an identifier by the general grammar of §6.2 and the
// consistency of §6.4 alone: the value rules of each scheme (§6.3) bind
// writers and are not applied here, so every reader of one record reads its
// decider the same way.
package decider

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"

	"github.com/TzunAI/tzun-verify/internal/grammar"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// The kinds of §6.1.
const (
	KindHuman         = "human"
	KindAgent         = "agent"
	KindAgentMandated = "agent-mandated"
	KindPolicyEngine  = "policy-engine"
)

// KnownKind reports whether a kind is one of the four of §6.1. A reader that
// meets another abstains rather than calling it malformed.
func KnownKind(k string) bool {
	switch k {
	case KindHuman, KindAgent, KindAgentMandated, KindPolicyEngine:
		return true
	}
	return false
}

// AgentKind reports whether a kind is one of the agent kinds of §6.4.
func AgentKind(k string) bool {
	return k == KindAgent || k == KindAgentMandated || k == KindPolicyEngine
}

// KnownScheme reports whether a scheme is one of §6.3.
func KnownScheme(s string) bool {
	switch s {
	case "acct", "spiffe", "jkt", "desc", "cmt":
		return true
	}
	return false
}

var schemeRE = regexp.MustCompile(`^[a-z][a-z0-9+.-]{0,15}$`)

// SplitID applies the identifier grammar of §6.2: 3 to 1,024 characters of
// visible ASCII, a scheme before the first ":" matching
// /[a-z][a-z0-9+.-]{0,15}/, and a value after it that is not empty.
func SplitID(id string) (scheme, value string, ok bool) {
	if len(id) < 3 || len(id) > 1024 || !grammar.VisibleASCII(id) {
		return "", "", false
	}
	scheme, value, found := strings.Cut(id, ":")
	if !found || value == "" || !schemeRE.MatchString(scheme) {
		return "", "", false
	}
	return scheme, value, true
}

var (
	freshnessRE = regexp.MustCompile(`^([-a-z0-9]{3,8}):([-_a-zA-Z0-9]{1,32})@(0|[1-9][0-9]{0,15}):0x([0-9a-f]{64})$`)
	eip155RefRE = regexp.MustCompile(`^[1-9][0-9]{0,30}$`)
)

// Freshness is a parsed finalized-block reference (§6.2).
type Freshness struct {
	// Chain is the CAIP-2 chain, namespace:reference.
	Chain     string
	Namespace string
	Reference string
	Block     uint64
	// Hash is the block hash, 0x and 64 lowercase hex characters.
	Hash string
}

// ParseFreshness reads a finalized-block reference: the pattern of §6.2,
// a block number of at most 2^53 − 1, and, for the eip155 namespace, a
// reference with no leading zero so that one chain has one spelling.
func ParseFreshness(s string) (Freshness, bool) {
	m := freshnessRE.FindStringSubmatch(s)
	if m == nil {
		return Freshness{}, false
	}
	n, err := strconv.ParseUint(m[3], 10, 64)
	if err != nil || n > 1<<53-1 {
		return Freshness{}, false
	}
	if m[1] == "eip155" && !eip155RefRE.MatchString(m[2]) {
		return Freshness{}, false
	}
	return Freshness{Chain: m[1] + ":" + m[2], Namespace: m[1], Reference: m[2], Block: n, Hash: "0x" + m[4]}, true
}

// Identity is the kind, identifier and agent reference a decider and an
// actor share.
type Identity struct {
	Kind   string
	ID     string
	Scheme string
	// Agent is the agent reference, "" for null.
	Agent string
}

// Decider is a well-formed decider (§6.2).
type Decider struct {
	Identity
	// Credential and Freshness are "" for null.
	Credential string
	Freshness  string
	// Fresh is the parsed reference when Freshness is set.
	Fresh Freshness
}

// identity reads kind, id and agent under §6.2.
func identity(v *jsonv.Value) (Identity, bool) {
	kind, ok1 := member(v, "kind").Str()
	id, ok2 := member(v, "id").Str()
	if !ok1 || !ok2 {
		return Identity{}, false
	}
	scheme, _, ok := SplitID(id)
	if !ok {
		return Identity{}, false
	}
	r := Identity{Kind: kind, ID: id, Scheme: scheme}
	switch a := member(v, "agent"); {
	case grammar.IsNull(a):
	default:
		s, ok := a.Str()
		if !ok || !grammar.PrefixedDigest(s) {
			return Identity{}, false
		}
		r.Agent = s
	}
	return r, true
}

func member(v *jsonv.Value, key string) *jsonv.Value {
	m, _ := v.Get(key)
	return m
}

// Parse reads payload.decider under the grammar of §6.2: an object with
// exactly the five members of §6.1, every one present. It does not judge the
// kind's vocabulary, the consistency of §6.4 or the scheme's value rules.
func Parse(v *jsonv.Value) (Decider, bool) {
	if !grammar.Exact(v, "kind", "id", "agent", "credential", "freshness") {
		return Decider{}, false
	}
	idn, ok := identity(v)
	if !ok {
		return Decider{}, false
	}
	d := Decider{Identity: idn}
	if c := member(v, "credential"); !grammar.IsNull(c) {
		s, ok := c.Str()
		if !ok || !grammar.BareDigest(s) {
			return Decider{}, false
		}
		d.Credential = s
	}
	if f := member(v, "freshness"); !grammar.IsNull(f) {
		s, ok := f.Str()
		if !ok {
			return Decider{}, false
		}
		fr, ok := ParseFreshness(s)
		if !ok {
			return Decider{}, false
		}
		d.Freshness, d.Fresh = s, fr
	}
	return d, true
}

// ParseActor reads a step's actor under §7.1: exactly kind, id and agent,
// under the grammar of §6.2.
func ParseActor(v *jsonv.Value) (Identity, bool) {
	if !grammar.Exact(v, "kind", "id", "agent") {
		return Identity{}, false
	}
	return identity(v)
}

// Consistent applies §6.4 to an identity of a known kind: the agent
// reference against the kind, whatever the scheme; the scheme against the
// kind, only for the schemes of §6.3; and a desc value equal to the agent
// reference.
func Consistent(i Identity) bool {
	switch {
	case i.Kind == KindHuman:
		if i.Agent != "" {
			return false
		}
		if KnownScheme(i.Scheme) && i.Scheme != "acct" && i.Scheme != "cmt" {
			return false
		}
	case AgentKind(i.Kind):
		if i.Agent == "" {
			return false
		}
		if KnownScheme(i.Scheme) && i.Scheme == "acct" {
			return false
		}
	}
	if i.Scheme == "desc" && i.ID != "desc:"+i.Agent {
		return false
	}
	return true
}

// Expectation forms of §9.1, as Agrees reads them.
const (
	FormNone    = "none"
	FormPolicy  = "policy"
	FormSession = "session"
	FormMandate = "mandate"
)

// Agrees applies the table of §6.5: whether a stated kind agrees with the
// form of the signature expectation.
func Agrees(kind, form string) bool {
	switch kind {
	case KindHuman:
		return form != FormMandate
	case KindAgent, KindPolicyEngine:
		return form == FormNone || form == FormPolicy
	case KindAgentMandated:
		return form == FormMandate
	}
	return false
}

// Reasons and facts of the decider row (Verification §4.9).
const (
	ID                          = "decider"
	ReasonMalformed             = "malformed_decider"
	ReasonUnsupportedKind       = "unsupported_decider_kind"
	ReasonInconsistent          = "decider_inconsistent"
	ReasonKindContradicted      = "decider_kind_contradicted"
	ReasonUnsupportedScheme     = "unsupported_identifier_scheme"
	ReasonMaterialUnverified    = "material_unverified"
	ReasonAbsent                = "absent"
	LevelHumanAsserted          = "human-asserted"
	LevelAgentAsserted          = "agent-asserted"
	LevelUndeterminedHumanProof = "human-proven"
)

// Row decides the decider row from step 3 of Verification §4.9 on: the
// caller has applied steps 1 and 2 (the digest, and a malformed
// expectation). form is the expectation's form; bound reports whether the
// record carries human decision material that binds it (Record §6.5).
// It returns the row and, when the row holds, the parsed decider.
func Row(v *jsonv.Value, form string, bound bool) (report.Check, *Decider) {
	c := report.Check{ID: ID}
	if v == nil || v.Kind == jsonv.Null {
		c.Outcome, c.Reason = report.NotChecked, ReasonAbsent
		return c, nil
	}
	d, ok := Parse(v)
	if !ok {
		c.Outcome, c.Reason = report.Wrong, ReasonMalformed
		return c, nil
	}
	kindFact := report.Fact{Name: "kind", Value: report.S(d.Kind)}
	schemeFact := report.Fact{Name: "scheme", Value: report.S(d.Scheme)}
	if !KnownKind(d.Kind) {
		c.Outcome, c.Reason, c.Facts = report.Abstain, ReasonUnsupportedKind, []report.Fact{kindFact}
		return c, nil
	}
	c.Facts = []report.Fact{kindFact, schemeFact}
	switch {
	case !Consistent(d.Identity):
		c.Outcome, c.Reason = report.Wrong, ReasonInconsistent
		return c, nil
	case !Agrees(d.Kind, form):
		c.Outcome, c.Reason = report.Wrong, ReasonKindContradicted
		return c, nil
	case !KnownScheme(d.Scheme):
		c.Outcome, c.Reason = report.Abstain, ReasonUnsupportedScheme
		return c, nil
	case AgentKind(d.Kind) && bound:
		c.Outcome, c.Reason = report.NotChecked, ReasonMaterialUnverified
		c.Facts = append(c.Facts, report.Fact{Name: "kindContradiction", Value: report.S("undetermined")})
		return c, nil
	}
	c.Outcome = report.Correct
	if d.Kind == KindHuman {
		c.Facts = append(c.Facts, report.Fact{Name: "level", Value: report.S(LevelHumanAsserted)})
		if bound {
			c.Facts = append(c.Facts, report.Fact{Name: "levelUndetermined", Value: report.S(LevelUndeterminedHumanProof)})
		}
	} else {
		c.Facts = append(c.Facts, report.Fact{Name: "level", Value: report.S(LevelAgentAsserted)})
	}
	if d.Scheme == "cmt" {
		c.Facts = append(c.Facts, report.Fact{Name: "committed", Value: report.B(true)})
	}
	return c, &d
}

// CommitmentDomain is the tag a cmt identifier is computed under (§6.3).
const CommitmentDomain = "tzun-decider-cmt-v1"

var spiffeRE = regexp.MustCompile(`^spiffe://[a-z0-9._-]+(/[A-Za-z0-9._-]+)+$`)

// WriterID applies the writer rules of the schemes of §6.3 other than cmt:
// an acct value of /[A-Za-z0-9._-]{1,128}/, a SPIFFE ID with no "." or ".."
// segment, a jkt value of 43 characters of base64url, and a desc value that
// is a prefixed digest. A reader never applies them.
func WriterID(id string) bool {
	scheme, value, ok := SplitID(id)
	if !ok {
		return false
	}
	switch scheme {
	case "acct":
		return grammar.AcctValue(value)
	case "spiffe":
		if !spiffeRE.MatchString(id) {
			return false
		}
		for _, seg := range strings.Split(strings.TrimPrefix(id, "spiffe://"), "/")[1:] {
			if seg == "." || seg == ".." {
				return false
			}
		}
		return true
	case "jkt":
		if len(value) != 43 {
			return false
		}
		for i := 0; i < len(value); i++ {
			c := value[i]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
		return true
	case "desc":
		return grammar.PrefixedDigest(value)
	}
	return false
}

// Commitment is the cmt identifier of an inner identifier under a 32-byte
// salt: "cmt:" and hex(SHA-256(UTF-8("tzun-decider-cmt-v1") ‖ salt ‖
// UTF-8(inner))). It returns false for a salt of another length and for an
// inner identifier that a writer would not write: one of a scheme other
// than acct, spiffe, jkt and desc, or outside its scheme's value rule.
func Commitment(salt []byte, inner string) (string, bool) {
	if len(salt) != 32 || !WriterID(inner) {
		return "", false
	}
	h := sha256.New()
	h.Write([]byte(CommitmentDomain))
	h.Write(salt)
	h.Write([]byte(inner))
	return "cmt:" + hex.EncodeToString(h.Sum(nil)), true
}

// Opens reports whether an opening (salt, inner) opens a cmt identifier.
func Opens(id string, salt []byte, inner string) bool {
	c, ok := Commitment(salt, inner)
	return ok && c == id
}
