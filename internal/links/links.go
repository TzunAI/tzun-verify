// SPDX-License-Identifier: BSD-3-Clause-Clear

// Package links reads payload.links (Record §8) and decides the rows links,
// links[<i>] and links[<i>].edge of Verification §4.11. A bare §n in this
// package's comments is a section of Record.
//
// A verifier of a b1 bundle holds no target record (Bundle §8): it checks
// the grammar, the list-level rules, each relation's profile and its
// record-local rules, and reports every target rule not checked. A verifier
// that holds records by other means passes a Resolver, and the target rules
// and the member-by-member target check of §8.8 then run too. No edge is
// verified in this version: every links[<i>].edge row abstains.
//
// Where the conformance vectors state a fact or a rule name, the rows give
// the vectors' (rule names such as ratifies_decider_human, the facts rule
// and failedLink of a malformed list); the specification text is to follow.
package links

import (
	"regexp"
	"sort"
	"strings"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/checkpoint"
	"github.com/TzunAI/tzun-verify/internal/grammar"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// Row ids and reasons (Verification §4.11).
const (
	ID = "links"

	ReasonAbsent              = "absent"
	ReasonMalformed           = "malformed_links"
	ReasonRuleViolated        = "link_rule_violated"
	ReasonUnsupportedRelation = "unsupported_link_relation"
	ReasonAttrsInvalid        = "link_attrs_invalid"
	ReasonTargetMismatch      = "link_target_mismatch"
	ReasonUnsupportedRule     = "unsupported_link_rule"
	ReasonUndetermined        = "link_rule_undetermined"
	ReasonNoTarget            = "not_in_bundle:link_target"
	ReasonUnsupportedEdge     = "unsupported_link_edge"
	IDExpectation             = "signoff.expectation"
)

// The grammar rules a malformed member breaks, named in the fact rule.
const (
	RuleNotAnArray          = "not_an_array"
	RuleEmpty               = "empty_links"
	RuleTooMany             = "too_many_links"
	RuleUnknownMembers      = "link_unknown_members"
	RuleMissingMembers      = "link_missing_members"
	RuleInvalidRelation     = "invalid_relation"
	RuleInvalidTarget       = "invalid_target"
	RuleInvalidTargetDigest = "invalid_target_digest"
	RuleInvalidEvidenceID   = "invalid_target_evidence_id"
	RuleInvalidLocator      = "invalid_locator"
	RuleInvalidAttrs        = "invalid_attrs"
	RuleTooManyAttrs        = "too_many_attrs"
	RuleNotASet             = "not_a_set"
)

// The names of the list-level, record-local and target rules, as the
// conformance vectors report them in the fact rule.
const (
	RuleMandateLink      = "mandate_link"
	RuleRevokesLink      = "revokes_link"
	RuleSubjectLink      = "subject_link"
	RuleAtMostOne        = "at_most_one"
	RuleRootLineage      = "root_without_lineage"
	RuleRatifierHuman    = "ratifies_decider_human"
	RuleRatifiedNotHuman = "ratifies_target_not_human"
	RuleReviewerDistinct = "reviews_distinct_decider"
	RuleSameSystem       = "supersedes_same_system"
	RuleMandateTarget    = "mandate_target"
	RuleRevokesTarget    = "revokes_target"
)

// System records (§8.6, §9.6).
const (
	SystemMandate = "tzun:mandate"
	SystemLink    = "tzun:link"
)

var (
	registeredRE = regexp.MustCompile(`^[a-z][A-Za-z0-9]{0,31}$`)
	extensionRE  = regexp.MustCompile(`^x-[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?\.[a-z][A-Za-z0-9]{0,31}$`)
)

// attrType is the type a relation's profile gives one attribute.
type attrType int

const (
	attrBareDigest attrType = iota + 1
	attrInteger
	attrPositive
)

// relation is one entry of the registry of §8.3.
type relation struct {
	// attrs is the attribute profile: nil admits none (attrs null), and
	// otherwise every named attribute is required.
	attrs   map[string]attrType
	lineage bool
	// target says the relation has a target rule; undefined, that the rule
	// is one this version does not define.
	target    bool
	undefined bool
}

// Registry is the relation registry of §8.3.
var Registry = map[string]relation{
	"derivedFrom": {lineage: true},
	"reviews":     {lineage: true, target: true},
	"supersedes":  {lineage: true, target: true},
	"appeals":     {lineage: true},
	"ratifies":    {lineage: true, target: true},
	"implements":  {lineage: true},
	"delegatedBy": {lineage: true, target: true, undefined: true},
	"closes": {lineage: true, target: true, undefined: true,
		attrs: map[string]attrType{"statement": attrBareDigest, "size": attrInteger, "treeRoot": attrBareDigest}},
	"fanoutOf": {lineage: true, target: true, undefined: true,
		attrs: map[string]attrType{"statement": attrBareDigest, "slot": attrPositive}},
	"root":    {},
	"mandate": {target: true},
	"revokes": {target: true},
	"subject": {},
}

// Extension reports whether a relation or attribute name is an extension
// name, x-<org>.<name>, of at most 67 characters.
func Extension(name string) bool { return len(name) <= 67 && extensionRE.MatchString(name) }

// Registered reports whether a name is in the registry.
func Registered(name string) bool {
	_, ok := Registry[name]
	return ok
}

func validName(name string) bool { return registeredRE.MatchString(name) || Extension(name) }

// Link is one link that meets the grammar of §8.2.
type Link struct {
	Raw        *jsonv.Value
	Rel        string
	Digest     string
	EvidenceID string // "" for null
	Origin     string // "" for a null locator
	Seq        uint64
	Attrs      *jsonv.Value // nil for null
}

func member(v *jsonv.Value, key string) *jsonv.Value {
	m, _ := v.Get(key)
	return m
}

// validOrigin is the origin grammar of a locator (§8.2): a store's
// evidence log, or a hosted log under exactly log.tzun.ai or
// test.log.tzun.ai whose last segment is not anchors.
func validOrigin(s string) bool {
	o, ok := checkpoint.ParseOrigin(s)
	if !ok {
		return false
	}
	switch o.Kind {
	case checkpoint.KindEvidence:
		store := strings.Split(s, "/")[1]
		return checkpoint.ValidNamespace(o.Namespace) && grammar.LowerHex(store, 32)
	case checkpoint.KindOther:
		return checkpoint.IsPlatformNamespace(o.Namespace)
	}
	return false
}

// parseLink reads one link under §8.2, naming the rule it breaks.
func parseLink(v *jsonv.Value) (Link, string) {
	if v == nil || v.Kind != jsonv.Object {
		return Link{}, RuleUnknownMembers
	}
	if unknown, missing := grammar.Members(v, "rel", "target", "attrs"); unknown {
		return Link{}, RuleUnknownMembers
	} else if missing {
		return Link{}, RuleMissingMembers
	}
	l := Link{Raw: v}
	rel, ok := member(v, "rel").Str()
	if !ok || !validName(rel) {
		return Link{}, RuleInvalidRelation
	}
	l.Rel = rel
	t := member(v, "target")
	if !grammar.Exact(t, "digest", "evidenceId", "locator") {
		return Link{}, RuleInvalidTarget
	}
	if l.Digest, ok = member(t, "digest").Str(); !ok || !grammar.BareDigest(l.Digest) {
		return Link{}, RuleInvalidTargetDigest
	}
	if e := member(t, "evidenceId"); !grammar.IsNull(e) {
		l.EvidenceID, ok = e.Str()
		if !ok || len(l.EvidenceID) < 1 || len(l.EvidenceID) > 128 || !grammar.VisibleASCII(l.EvidenceID) {
			return Link{}, RuleInvalidEvidenceID
		}
	}
	if loc := member(t, "locator"); !grammar.IsNull(loc) {
		if !grammar.Exact(loc, "origin", "seq") {
			return Link{}, RuleInvalidLocator
		}
		origin, ok1 := member(loc, "origin").Str()
		seq, ok2 := grammar.Integer(member(loc, "seq"))
		if !ok1 || !ok2 || seq < 1 || !validOrigin(origin) {
			return Link{}, RuleInvalidLocator
		}
		l.Origin, l.Seq = origin, seq
	}
	if a := member(v, "attrs"); !grammar.IsNull(a) {
		if a.Kind != jsonv.Object || len(a.O) == 0 {
			return Link{}, RuleInvalidAttrs
		}
		if len(a.O) > 16 {
			return Link{}, RuleTooManyAttrs
		}
		for _, m := range a.O {
			if m.KeyLone || !validName(m.Key) || !attrValue(m.Value) {
				return Link{}, RuleInvalidAttrs
			}
		}
		l.Attrs = a
	}
	return l, ""
}

// attrValue is the general grammar of an attribute's value: a string of 0
// to 256 characters of printable ASCII, an integer, or a boolean.
func attrValue(v *jsonv.Value) bool {
	switch v.Kind {
	case jsonv.String:
		s, ok := v.Str()
		return ok && len(s) <= 256 && grammar.PrintableASCII(s)
	case jsonv.Number:
		_, ok := grammar.Integer(v)
		return ok
	case jsonv.Bool:
		return true
	}
	return false
}

// before reports whether link a sorts strictly before link b by the pair
// (rel, target.digest), each by bytes.
func before(a, b Link) bool {
	if a.Rel != b.Rel {
		return a.Rel < b.Rel
	}
	return a.Digest < b.Digest
}

// Parse reads the member under §8.2. On failure it names the rule broken
// and the index of the link at fault, -1 when no one link is.
func Parse(v *jsonv.Value) (ls []Link, rule string, index int) {
	if v == nil || v.Kind != jsonv.Array {
		return nil, RuleNotAnArray, -1
	}
	switch {
	case len(v.A) == 0:
		return nil, RuleEmpty, -1
	case len(v.A) > 256:
		return nil, RuleTooMany, -1
	}
	for i, e := range v.A {
		l, rule := parseLink(e)
		if rule != "" {
			return nil, rule, i
		}
		ls = append(ls, l)
	}
	for i := 1; i < len(ls); i++ {
		if !before(ls[i-1], ls[i]) {
			return nil, RuleNotASet, i
		}
	}
	return ls, "", -1
}

// Targets returns the target digests the links of a payload declare as
// inputs (Record §7.5): those of a member that meets the grammar of §8.2,
// and none otherwise.
func Targets(payload *jsonv.Value) []string {
	v := member(payload, "links")
	if v == nil || v.Kind == jsonv.Null {
		return nil
	}
	ls, rule, _ := Parse(v)
	if rule != "" {
		return nil
	}
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.Digest
	}
	return out
}

// Held is a record a verifier holds: its payload, the digest it is held
// under, and the origin of its chain's evidence log.
type Held struct {
	Payload *jsonv.Value
	Digest  string
	Origin  string
}

// Resolver is what a verifier holds besides the record itself. A bundle
// verifier passes none.
type Resolver interface {
	// ByDigest returns the record held under a digest.
	ByDigest(digest string) (*Held, bool)
	// HoldsLog reports whether the verifier holds the log of an origin.
	HoldsLog(origin string) bool
	// At returns the digest of the record at a position of a log it holds,
	// false when the position holds none.
	At(origin string, seq uint64) (string, bool)
	// Open returns the identifier a cmt identifier commits to, when the
	// verifier holds its opening.
	Open(cmt string) (string, bool)
}

// Input is what the rows read.
type Input struct {
	Payload *jsonv.Value
	// Form is the expectation's form ("none", "policy", "session",
	// "mandate"); Malformed, that it breaks the grammar (Record §9.2).
	Form      string
	Malformed bool
	Resolver  Resolver
}

// Result is the rows of one record: the links row, and then links[<i>] and
// links[<i>].edge for each link, in that order.
type Result struct {
	Row   report.Check
	Links []report.Check
}

func str(v *jsonv.Value, key string) string {
	s, _ := member(v, key).Str()
	return s
}

func deciderKind(payload *jsonv.Value) string { return str(member(payload, "decider"), "kind") }

// listRule applies the list-level rules of §8.3, in the order of that
// table, and returns the name of the first that fails. The rules of the
// subject relation over a link record are part of subject_link.
func listRule(in Input, ls []Link) string {
	count := map[string]int{}
	for _, l := range ls {
		count[l.Rel]++
	}
	sys, action := str(in.Payload, "aiSystemId"), str(in.Payload, "action")
	if !in.Malformed {
		mandateForm := in.Form == "mandate"
		if mandateForm && count["mandate"] != 1 || !mandateForm && count["mandate"] != 0 {
			return RuleMandateLink
		}
	}
	revocation := sys == SystemMandate && action == "revoke-mandate"
	if revocation && count["revokes"] != 1 || !revocation && count["revokes"] != 0 {
		return RuleRevokesLink
	}
	if sys == SystemLink {
		if count["subject"] != 1 || !linkRecord(in.Payload, ls) {
			return RuleSubjectLink
		}
	} else if count["subject"] != 0 {
		return RuleSubjectLink
	}
	if count["root"] > 1 || count["closes"] > 1 || count["fanoutOf"] > 1 {
		return RuleAtMostOne
	}
	return ""
}

// linkRecord is the rule of a link record's subject link (§8.3, §8.6):
// action "link", no contributions, at least one other link, none naming
// the subject's digest, and no root, mandate, revokes, closes or fanoutOf
// link.
func linkRecord(payload *jsonv.Value, ls []Link) bool {
	if str(payload, "action") != "link" || !member(payload, "contributions").IsNull() || len(ls) < 2 {
		return false
	}
	subject := ""
	for _, l := range ls {
		if l.Rel == "subject" {
			subject = l.Digest
		}
	}
	for _, l := range ls {
		if l.Rel == "subject" {
			continue
		}
		switch l.Rel {
		case "root", "mandate", "revokes", "closes", "fanoutOf":
			return false
		}
		if l.Digest == subject {
			return false
		}
	}
	return true
}

func fact(name string, v *jsonv.Value) report.Fact { return report.Fact{Name: name, Value: v} }

// Check decides the rows for a payload whose digest holds.
func Check(in Input) Result {
	v := member(in.Payload, "links")
	row := report.Check{ID: ID}
	if v == nil || v.Kind == jsonv.Null {
		if rule := listRule(in, nil); rule != "" {
			row.Outcome, row.Reason, row.Facts = report.Wrong, ReasonRuleViolated, []report.Fact{fact("rule", report.S(rule))}
			return Result{Row: row}
		}
		row.Outcome, row.Reason = report.NotChecked, ReasonAbsent
		return Result{Row: row}
	}
	ls, rule, index := Parse(v)
	perLink := v.Kind == jsonv.Array && len(v.A) >= 1 && len(v.A) <= 256
	blocked := func() Result {
		r := Result{Row: row}
		if perLink {
			for i := range v.A {
				id := linkID(i)
				r.Links = append(r.Links, report.BlockedBy(id, ID), EdgeRow(i))
			}
		}
		return r
	}
	if rule != "" {
		row.Outcome, row.Reason = report.Wrong, ReasonMalformed
		row.Facts = []report.Fact{fact("rule", report.S(rule))}
		if index >= 0 {
			row.Facts = append(row.Facts, fact("failedLink", report.N(uint64(index))))
		}
		return blocked()
	}
	if rule := listRule(in, ls); rule != "" {
		row.Outcome, row.Reason, row.Facts = report.Wrong, ReasonRuleViolated, []report.Fact{fact("rule", report.S(rule))}
		return blocked()
	}
	row.Outcome = report.Correct
	names := map[string]bool{}
	ext := 0
	for _, l := range ls {
		names[l.Rel] = true
		if Extension(l.Rel) {
			ext++
		}
	}
	rels := make([]string, 0, len(names))
	for n := range names {
		rels = append(rels, n)
	}
	sort.Strings(rels)
	relsJSON := report.Arr()
	for _, n := range rels {
		relsJSON.A = append(relsJSON.A, report.S(n))
	}
	row.Facts = []report.Fact{
		fact("count", report.N(uint64(len(ls)))),
		fact("relations", relsJSON),
		fact("extensions", report.N(uint64(ext))),
	}
	r := Result{Row: row}
	for i, l := range ls {
		r.Links = append(r.Links, linkRow(in, ls, i, l), EdgeRow(i))
	}
	return r
}

func linkID(i int) string { return "links[" + itoa(i) + "]" }

// EdgeRow is links[<i>].edge: this version verifies no edge (§8.8), so the
// row abstains whatever the relation and whatever links says, as the
// conformance vectors state it.
func EdgeRow(i int) report.Check {
	return report.Check{ID: linkID(i) + ".edge", Outcome: report.Abstain, Reason: ReasonUnsupportedEdge}
}

// LinkID is the id of the row of the link at index i.
func LinkID(i int) string { return linkID(i) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// profileOK applies a registered relation's closed attribute profile.
func profileOK(rel relation, attrs *jsonv.Value) bool {
	if rel.attrs == nil {
		return attrs == nil
	}
	if attrs == nil || len(attrs.O) != len(rel.attrs) {
		return false
	}
	for name, t := range rel.attrs {
		a, ok := attrs.Get(name)
		if !ok {
			return false
		}
		switch t {
		case attrBareDigest:
			s, ok := a.Str()
			if !ok || !grammar.BareDigest(s) {
				return false
			}
		case attrInteger, attrPositive:
			n, ok := grammar.Integer(a)
			if !ok || t == attrPositive && n < 1 {
				return false
			}
		}
	}
	return true
}

// recomputes reports whether a held record's payload recomputes to the
// digest it is held under.
func recomputes(h *Held) bool {
	d, err := canonical.RecordDigest(h.Payload)
	return err == nil && d == h.Digest
}

// lineageLinks reads the lineage links of a payload, by its raw links
// member; nil when the member does not meet the grammar.
func lineageLinks(payload *jsonv.Value) (lineage []Link, root *Link, ok bool) {
	v := member(payload, "links")
	if v == nil || v.Kind == jsonv.Null {
		return nil, nil, true
	}
	ls, rule, _ := Parse(v)
	if rule != "" {
		return nil, nil, false
	}
	for i := range ls {
		if Registry[ls[i].Rel].lineage {
			lineage = append(lineage, ls[i])
		}
		if ls[i].Rel == "root" {
			root = &ls[i]
		}
	}
	return lineage, root, true
}

// linkRow decides links[<i>] for a link of a well-formed list whose
// list-level rules hold.
func linkRow(in Input, ls []Link, i int, l Link) report.Check {
	c := report.Check{ID: linkID(i)}
	set := func(o report.Outcome, reason string, facts ...report.Fact) report.Check {
		c.Outcome, c.Reason, c.Facts = o, reason, facts
		return c
	}
	if l.Rel == "mandate" && in.Malformed {
		return report.BlockedBy(c.ID, IDExpectation)
	}
	rel, ok := Registry[l.Rel]
	if !ok {
		return set(report.Abstain, ReasonUnsupportedRelation)
	}
	if !profileOK(rel, l.Attrs) {
		return set(report.Wrong, ReasonAttrsInvalid)
	}
	linkRec := str(in.Payload, "aiSystemId") == SystemLink && l.Rel != "subject"

	// Record-local rules, read from this record unless it is a link record,
	// whose rules read the subject (§8.6).
	rootUndecided := false
	if !linkRec {
		switch l.Rel {
		case "ratifies":
			if deciderKind(in.Payload) != "human" {
				return set(report.Wrong, ReasonRuleViolated, fact("rule", report.S(RuleRatifierHuman)))
			}
		case "root":
			lineage, unknown := false, false
			for _, o := range ls {
				if Registry[o.Rel].lineage {
					lineage = true
				}
				if !Registered(o.Rel) && !Extension(o.Rel) {
					unknown = true
				}
			}
			if !lineage {
				if !unknown {
					return set(report.Wrong, ReasonRuleViolated, fact("rule", report.S(RuleRootLineage)))
				}
				rootUndecided = true
			}
		}
	}

	var target *Held
	if in.Resolver != nil {
		if h, ok := in.Resolver.ByDigest(l.Digest); ok {
			target = h
		}
	}
	held := fact("targetHeld", report.B(target != nil))

	// The held target, member by member, resolved by its digest.
	if target != nil {
		switch {
		case !recomputes(target):
			return set(report.Wrong, ReasonTargetMismatch, fact("member", report.S("digest")), held)
		case l.EvidenceID != "" && l.EvidenceID != str(target.Payload, "evidenceId"):
			return set(report.Wrong, ReasonTargetMismatch, fact("member", report.S("evidenceId")), held)
		case l.Origin != "":
			seq, ok := grammar.Integer(member(target.Payload, "sequenceNumber"))
			if !ok || seq != l.Seq || l.Origin != target.Origin {
				return set(report.Wrong, ReasonTargetMismatch, fact("member", report.S("locator")), held)
			}
		}
	}
	// A locator into a log the verifier holds names a position that holds
	// the target, whether or not the target is held.
	if l.Origin != "" && in.Resolver != nil && in.Resolver.HoldsLog(l.Origin) {
		if d, ok := in.Resolver.At(l.Origin, l.Seq); !ok || d != l.Digest {
			return set(report.Wrong, ReasonTargetMismatch, fact("member", report.S("locator")), held)
		}
	}

	if rootUndecided {
		return set(report.Abstain, ReasonUnsupportedRule, held)
	}
	if l.Rel == "root" {
		return rootRow(in, ls, l, target, held, set)
	}

	// The record the rules read in place of this one: the subject, in a
	// link record.
	self := &Held{Payload: in.Payload}
	needsSelf := false
	if linkRec {
		self, needsSelf = nil, true
		for _, o := range ls {
			if o.Rel == "subject" && in.Resolver != nil {
				if h, ok := in.Resolver.ByDigest(o.Digest); ok {
					self = h
				}
			}
		}
	}
	readsSelf := needsSelf && (l.Rel == "ratifies" || l.Rel == "reviews" || l.Rel == "supersedes")
	if !rel.target && !readsSelf {
		return set(report.Correct, "", held)
	}
	if rel.undefined {
		return set(report.Abstain, ReasonUnsupportedRule, held)
	}
	// The subject is named before the target when neither is held.
	switch {
	case readsSelf && self == nil:
		return set(report.NotChecked, ReasonNoTarget, held, fact("missing", report.S("subject")))
	case rel.target && target == nil:
		return set(report.NotChecked, ReasonNoTarget, held, fact("missing", report.S("target")))
	}
	ruleFails := func(name string) report.Check {
		return set(report.Wrong, ReasonRuleViolated, fact("rule", report.S(name)), held)
	}
	switch l.Rel {
	case "ratifies":
		if linkRec && deciderKind(self.Payload) != "human" {
			return ruleFails(RuleRatifierHuman)
		}
		if deciderKind(target.Payload) == "human" {
			return ruleFails(RuleRatifiedNotHuman)
		}
	case "supersedes":
		if str(target.Payload, "aiSystemId") != str(self.Payload, "aiSystemId") {
			return ruleFails(RuleSameSystem)
		}
	case "reviews":
		switch sameDecider(in.Resolver, member(self.Payload, "decider"), member(target.Payload, "decider")) {
		case 1:
			return ruleFails(RuleReviewerDistinct)
		case 0:
			return set(report.NotChecked, ReasonUndetermined, fact("rule", report.S(RuleReviewerDistinct)), held)
		}
	case "mandate":
		want, _ := member(member(in.Payload, "signoffExpectation"), "mandateAssertion").Str()
		got, ok := member(member(target.Payload, "aiOutput"), "assertionDigest").Str()
		if !issuance(target.Payload) || !ok || got != want {
			return ruleFails(RuleMandateTarget)
		}
	case "revokes":
		want, ok1 := member(member(in.Payload, "aiOutput"), "mandateDigest").Str()
		got, ok2 := member(member(target.Payload, "aiOutput"), "mandateDigest").Str()
		if !issuance(target.Payload) || !ok1 || !ok2 || got != want {
			return ruleFails(RuleRevokesTarget)
		}
	}
	return set(report.Correct, "", held)
}

// issuance reports whether a payload is an issuance record (§8.3).
func issuance(p *jsonv.Value) bool {
	return str(p, "aiSystemId") == SystemMandate && str(p, "action") == "issue-mandate"
}

// sameDecider compares two deciders (§8.3): the same when their kind and
// id are equal strings, a cmt identifier first opened when the verifier
// holds its opening. It returns 1 for the same, -1 for different, and 0
// when an unopened commitment leaves it undetermined.
func sameDecider(r Resolver, a, b *jsonv.Value) int {
	ka, ia := str(a, "kind"), str(a, "id")
	kb, ib := str(b, "kind"), str(b, "id")
	if ka == kb && ia == ib {
		return 1
	}
	open := func(id string) (string, bool) {
		if !strings.HasPrefix(id, "cmt:") {
			return id, true
		}
		if r == nil {
			return id, false
		}
		return r.Open(id)
	}
	oa, okA := open(ia)
	ob, okB := open(ib)
	if !okA || !okB {
		return 0
	}
	if ka == kb && oa == ob {
		return 1
	}
	return -1
}

// rootRow decides a root link once its record-local rule holds: its target
// conditions (§8.5) are facts, never a failure.
func rootRow(in Input, ls []Link, l Link, target *Held, held report.Fact, set func(report.Outcome, string, ...report.Fact) report.Check) report.Check {
	facts := []report.Fact{held}
	inconsistent := false
	if target != nil {
		if lineage, _, ok := lineageLinks(target.Payload); ok && len(lineage) > 0 {
			inconsistent = true
		}
	}
	if in.Resolver != nil {
		for _, o := range ls {
			if !Registry[o.Rel].lineage {
				continue
			}
			h, ok := in.Resolver.ByDigest(o.Digest)
			if !ok {
				continue
			}
			lineage, root, ok := lineageLinks(h.Payload)
			if !ok {
				continue
			}
			var r string
			switch {
			case root != nil:
				r = root.Digest
			case len(lineage) == 0:
				r = o.Digest
			default:
				continue // a lineage target with no root gives no fact
			}
			if r != l.Digest {
				inconsistent = true
			}
		}
	}
	if inconsistent {
		facts = append(facts, fact("rootInconsistent", report.B(true)))
	}
	return set(report.Correct, "", facts...)
}
