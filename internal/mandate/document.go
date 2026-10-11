// SPDX-License-Identifier: BSD-3-Clause-Clear

// Package mandate reads the mandate material of Record §9.6 to §9.9: the
// document tzun-mandate/1 and its digest, its predicates, the statement
// tzun-signoff-mandate/1 and its challenge, the assertion digest, and the
// scope, limits and issuance checks behind the mandate rows of
// Verification §4.12. A bare §n in this package's comments is a section of
// Record.
package mandate

import (
	"regexp"
	"sort"
	"time"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/decider"
	"github.com/TzunAI/tzun-verify/internal/grammar"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// DocumentVersion is the document format this version reads.
const DocumentVersion = "tzun-mandate/1"

// MaxDocumentBytes is the grammar limit of a document's canonical bytes.
const MaxDocumentBytes = 16384

// MaxPredicates is the most predicates a document holds, counting scope and
// confirm together.
const MaxPredicates = 64

func member(v *jsonv.Value, key string) *jsonv.Value {
	m, _ := v.Get(key)
	return m
}

// Named is a predicate with its name.
type Named struct {
	Name string
	Predicate
}

// Cap is one cumulative cap.
type Cap struct {
	Name string
	toks []string
	Max  uint64
}

// Document is a well-formed mandate document.
type Document struct {
	Raw           *jsonv.Value
	Digest        string
	Signer        string
	Agents        []string
	SchemaVersion string
	// AISystemIDs, Actions and Models are nil for a null set (no
	// restriction); an empty set permits nothing.
	AISystemIDs, Actions, Models []string
	HasAISystemIDs, HasActions   bool
	HasModels                    bool
	// Scope and Confirm are in byte order of name.
	Scope, Confirm []Named
	MaxRecords     *uint64
	// Caps is nil when limits.cumulative is null; in byte order of name.
	Caps []Cap
}

var (
	uuidRE    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	instantRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)
)

// Instant reads a validity bound (§9.7): the pattern with milliseconds,
// naming a real instant in UTC.
func Instant(s string) (time.Time, bool) {
	if !instantRE.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil || t.Format("2006-01-02T15:04:05.000Z") != s {
		return time.Time{}, false
	}
	return t, true
}

// walk applies the document-wide rules (§9.7): every string printable
// ASCII, every number an integer, every array a set.
func walk(v *jsonv.Value) bool {
	switch v.Kind {
	case jsonv.String:
		s, ok := v.Str()
		return ok && grammar.PrintableASCII(s)
	case jsonv.Number:
		_, ok := grammar.Integer(v)
		return ok
	case jsonv.Array:
		if _, ok := grammar.Set(v, 0, 1<<31, nil); !ok {
			return false
		}
		for _, e := range v.A {
			if !walk(e) {
				return false
			}
		}
	case jsonv.Object:
		for _, m := range v.O {
			if m.KeyLone || !grammar.PrintableASCII(m.Key) || !walk(m.Value) {
				return false
			}
		}
	}
	return true
}

// optSet reads a scope set: null (no restriction) or a set.
func optSet(v *jsonv.Value, elem func(string) bool) ([]string, bool, bool) {
	if grammar.IsNull(v) {
		return nil, false, true
	}
	s, ok := grammar.Set(v, 0, 1<<31, elem)
	return s, true, ok
}

// predicates reads scope.predicates or confirm: null, or an object of one
// or more predicates named by cap names.
func predicates(v *jsonv.Value) ([]Named, bool) {
	if grammar.IsNull(v) {
		return nil, true
	}
	if v == nil || v.Kind != jsonv.Object || len(v.O) == 0 {
		return nil, false
	}
	out := make([]Named, 0, len(v.O))
	for _, m := range v.O {
		if m.KeyLone || !grammar.CapName(m.Key) {
			return nil, false
		}
		p, ok := ParsePredicate(m.Value, true)
		if !ok {
			return nil, false
		}
		out = append(out, Named{Name: m.Key, Predicate: p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, true
}

// agentID is the grammar of an agents element (§9.7): a decider
// identifier of a scheme an agent may use.
func agentID(s string) bool {
	scheme, _, ok := decider.SplitID(s)
	return ok && (scheme == "spiffe" || scheme == "jkt" || scheme == "desc" || scheme == "cmt")
}

// ParseDocument reads a document under the grammar of §9.7, its size
// included. prepare adds the rules a writer applies when it prepares a
// document and a reader does not: no delegation, and a validity window that
// does not end before it begins.
func ParseDocument(v *jsonv.Value, prepare bool) (Document, bool) {
	fields := []string{"v", "mandateId", "principal", "agents", "schemaVersion", "scope", "confirm", "validity",
		"limits", "delegation", "review", "policyDigest", "predecessor", "parent"}
	if !grammar.Exact(v, fields...) || !walk(v) {
		return Document{}, false
	}
	b, err := canonical.Serialize(v)
	if err != nil || len(b) > MaxDocumentBytes {
		return Document{}, false
	}
	d := Document{Raw: v, Digest: canonical.Digest(b)}
	str := func(m *jsonv.Value) string { s, _ := m.Str(); return s }
	if str(member(v, "v")) != DocumentVersion || !uuidRE.MatchString(str(member(v, "mandateId"))) {
		return Document{}, false
	}
	p := member(v, "principal")
	if !grammar.Exact(p, "signer", "credential") {
		return Document{}, false
	}
	d.Signer = str(member(p, "signer"))
	if !grammar.AcctValue(d.Signer) {
		return Document{}, false
	}
	if c := member(p, "credential"); !grammar.IsNull(c) && !grammar.BareDigest(str(c)) {
		return Document{}, false
	}
	var ok bool
	if d.Agents, ok = grammar.Set(member(v, "agents"), 0, 1<<31, agentID); !ok {
		return Document{}, false
	}
	// The restriction: a schema version whose hashed field set holds
	// aiSystemId, action and contributions, which in this version is v1.0.
	if d.SchemaVersion = str(member(v, "schemaVersion")); d.SchemaVersion != "v1.0" {
		return Document{}, false
	}
	sc := member(v, "scope")
	if !grammar.Exact(sc, "aiSystemIds", "actions", "models", "predicates") {
		return Document{}, false
	}
	var ok1, ok2, ok3 bool
	d.AISystemIDs, d.HasAISystemIDs, ok1 = optSet(member(sc, "aiSystemIds"), nil)
	d.Actions, d.HasActions, ok2 = optSet(member(sc, "actions"), nil)
	d.Models, d.HasModels, ok3 = optSet(member(sc, "models"), grammar.PrefixedDigest)
	if !ok1 || !ok2 || !ok3 {
		return Document{}, false
	}
	if d.Scope, ok = predicates(member(sc, "predicates")); !ok {
		return Document{}, false
	}
	if d.Confirm, ok = predicates(member(v, "confirm")); !ok {
		return Document{}, false
	}
	if len(d.Scope)+len(d.Confirm) > MaxPredicates {
		return Document{}, false
	}
	val := member(v, "validity")
	if !grammar.Exact(val, "notBefore", "notAfter") {
		return Document{}, false
	}
	var bounds [2]*time.Time
	for i, k := range []string{"notBefore", "notAfter"} {
		if m := member(val, k); !grammar.IsNull(m) {
			t, ok := Instant(str(m))
			if !ok {
				return Document{}, false
			}
			bounds[i] = &t
		}
	}
	if prepare && bounds[0] != nil && bounds[1] != nil && bounds[1].Before(*bounds[0]) {
		return Document{}, false
	}
	lim := member(v, "limits")
	if !grammar.Exact(lim, "maxRecords", "cumulative") {
		return Document{}, false
	}
	if m := member(lim, "maxRecords"); !grammar.IsNull(m) {
		n, _ := grammar.Integer(m)
		d.MaxRecords = &n
	}
	if cu := member(lim, "cumulative"); !grammar.IsNull(cu) {
		if cu.Kind != jsonv.Object || len(cu.O) < 1 || len(cu.O) > 16 {
			return Document{}, false
		}
		for _, m := range cu.O {
			if m.KeyLone || !grammar.CapName(m.Key) || !grammar.Exact(m.Value, "path", "max") {
				return Document{}, false
			}
			path := str(member(m.Value, "path"))
			toks, ok := Pointer(path)
			if member(m.Value, "path").Kind != jsonv.String || !ok || !restricted(path) {
				return Document{}, false
			}
			max, ok := grammar.Integer(member(m.Value, "max"))
			if !ok {
				return Document{}, false
			}
			d.Caps = append(d.Caps, Cap{Name: m.Key, toks: toks, Max: max})
		}
		sort.Slice(d.Caps, func(i, j int) bool { return d.Caps[i].Name < d.Caps[j].Name })
	}
	del := member(v, "delegation")
	if !grammar.Exact(del, "allowed", "maxDepth", "attenuation") {
		return Document{}, false
	}
	allowed, ok1 := grammar.Bool(member(del, "allowed"))
	depth, ok2 := grammar.Integer(member(del, "maxDepth"))
	if !ok1 || !ok2 || str(member(del, "attenuation")) != "subset" {
		return Document{}, false
	}
	if prepare && (allowed || depth != 0) {
		return Document{}, false
	}
	if r := member(v, "review"); !grammar.IsNull(r) {
		if !grammar.Exact(r, "maxAgeMs") {
			return Document{}, false
		}
	}
	for _, k := range []string{"policyDigest", "predecessor"} {
		if m := member(v, k); !grammar.IsNull(m) && !grammar.BareDigest(str(m)) {
			return Document{}, false
		}
	}
	if !grammar.IsNull(member(v, "parent")) {
		return Document{}, false
	}
	return d, true
}

// DocumentDigest is hex(SHA-256(C(document))) of any document value, false
// when it has no canonical form.
func DocumentDigest(v *jsonv.Value) (string, bool) {
	b, err := canonical.Serialize(v)
	if err != nil {
		return "", false
	}
	return canonical.Digest(b), true
}
