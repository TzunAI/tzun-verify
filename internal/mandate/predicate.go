// SPDX-License-Identifier: BSD-3-Clause-Clear

package mandate

import (
	"strings"
	"unicode/utf8"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/grammar"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// Truth is the value of a predicate: true, false or undeterminable (§9.8).
type Truth int

// The three values of a predicate.
const (
	Undeterminable Truth = iota
	True
	False
)

func (t Truth) String() string {
	switch t {
	case True:
		return "true"
	case False:
		return "false"
	}
	return "undeterminable"
}

// Limits of a predicate's subject (§9.8): a longer string or array is
// undeterminable.
const (
	MaxSubjectCodePoints = 4096
	MaxSubjectElements   = 10000
)

var ops = map[string]bool{"eq": true, "ne": true, "lt": true, "le": true, "gt": true, "ge": true,
	"in": true, "notIn": true, "prefix": true, "glob": true}

// hashed reports whether a name is a member of the v1.0 hashed field set.
func hashed(name string) bool {
	for _, f := range canonical.HashedFieldsV1 {
		if f == name {
			return true
		}
	}
	return false
}

// Pointer reads an RFC 6901 JSON Pointer whose only escapes are ~0 and ~1
// (§9.8): "" or "/" followed by tokens. Any other "~" makes it malformed.
func Pointer(p string) ([]string, bool) {
	if p == "" {
		return nil, true
	}
	if p[0] != '/' {
		return nil, false
	}
	parts := strings.Split(p[1:], "/")
	for i, t := range parts {
		var b strings.Builder
		for j := 0; j < len(t); j++ {
			if t[j] != '~' {
				b.WriteByte(t[j])
				continue
			}
			if j+1 >= len(t) || (t[j+1] != '0' && t[j+1] != '1') {
				return nil, false
			}
			if t[j+1] == '0' {
				b.WriteByte('~')
			} else {
				b.WriteByte('/')
			}
			j++
		}
		parts[i] = b.String()
	}
	return parts, true
}

// restricted reports whether a path meets the restriction of §9.7: at
// least one reference token, the first a member of the hashed field set.
func restricted(path string) bool {
	toks, ok := Pointer(path)
	return ok && len(toks) > 0 && hashed(toks[0])
}

// Resolve follows a pointer's tokens into a value. On an array a token is
// an index, "0" or /[1-9][0-9]*/; "-" and any other token resolve to
// nothing, as does a missing member.
func Resolve(v *jsonv.Value, toks []string) (*jsonv.Value, bool) {
	cur := v
	for _, t := range toks {
		switch {
		case cur == nil:
			return nil, false
		case cur.Kind == jsonv.Object:
			m, ok := cur.Get(t)
			if !ok {
				return nil, false
			}
			cur = m
		case cur.Kind == jsonv.Array:
			i, ok := index(t)
			if !ok || i >= len(cur.A) {
				return nil, false
			}
			cur = cur.A[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

func index(t string) (int, bool) {
	if t == "" || len(t) > 1 && t[0] == '0' || len(t) > 9 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(t); i++ {
		if t[i] < '0' || t[i] > '9' {
			return 0, false
		}
		n = n*10 + int(t[i]-'0')
	}
	return n, true
}

// Predicate is a well-formed predicate.
type Predicate struct {
	Path  string
	toks  []string
	Op    string
	Value *jsonv.Value
	Quant string // "", "all" or "any"
	// set holds the value of in, notIn and glob.
	set []string
}

// docString is a string of the document grammar: printable ASCII.
func docString(v *jsonv.Value) (string, bool) {
	s, ok := v.Str()
	return s, ok && grammar.PrintableASCII(s)
}

// ParsePredicate reads a predicate under §9.8 and the document grammar
// (§9.7): exactly path, op, value and quant; a value that suits the op;
// every string printable ASCII. restrict applies the restriction of §9.7
// to its path.
func ParsePredicate(v *jsonv.Value, restrict bool) (Predicate, bool) {
	if !grammar.Exact(v, "path", "op", "value", "quant") {
		return Predicate{}, false
	}
	var p Predicate
	var ok bool
	if p.Path, ok = docString(member(v, "path")); !ok {
		return Predicate{}, false
	}
	if p.toks, ok = Pointer(p.Path); !ok || restrict && !restricted(p.Path) {
		return Predicate{}, false
	}
	if p.Op, ok = docString(member(v, "op")); !ok || !ops[p.Op] {
		return Predicate{}, false
	}
	switch q := member(v, "quant"); {
	case grammar.IsNull(q):
	default:
		p.Quant, ok = q.Str()
		if !ok || p.Quant != "all" && p.Quant != "any" {
			return Predicate{}, false
		}
	}
	p.Value = member(v, "value")
	switch p.Op {
	case "eq", "ne":
		switch p.Value.Kind {
		case jsonv.String:
			if _, ok := docString(p.Value); !ok {
				return Predicate{}, false
			}
		case jsonv.Number:
			if _, ok := grammar.Integer(p.Value); !ok {
				return Predicate{}, false
			}
		case jsonv.Bool:
		default:
			return Predicate{}, false
		}
	case "lt", "le", "gt", "ge":
		if _, ok := grammar.Integer(p.Value); !ok {
			return Predicate{}, false
		}
	case "in", "notIn":
		if p.set, ok = grammar.Set(p.Value, 1, 64, grammar.PrintableASCII); !ok {
			return Predicate{}, false
		}
	case "prefix":
		if _, ok := docString(p.Value); !ok {
			return Predicate{}, false
		}
	case "glob":
		pat := func(s string) bool {
			n := grammar.UTF16Len(s)
			return n >= 1 && n <= 256 && grammar.PrintableASCII(s)
		}
		if p.set, ok = grammar.Set(p.Value, 1, 64, pat); !ok {
			return Predicate{}, false
		}
	}
	return p, true
}

// Evaluate applies a predicate to a payload (§9.8).
func (p Predicate) Evaluate(payload *jsonv.Value) Truth {
	subject, ok := Resolve(payload, p.toks)
	if !ok || subject.Kind == jsonv.Null {
		return Undeterminable
	}
	if p.Quant == "" {
		if subject.Kind == jsonv.Array {
			return Undeterminable
		}
		return p.apply(subject)
	}
	if subject.Kind != jsonv.Array || len(subject.A) > MaxSubjectElements {
		return Undeterminable
	}
	undet := false
	for _, e := range subject.A {
		t := Undeterminable
		if e.Kind != jsonv.Null && e.Kind != jsonv.Array {
			t = p.apply(e)
		}
		switch {
		case p.Quant == "all" && t == False:
			return False
		case p.Quant == "any" && t == True:
			return True
		case t == Undeterminable:
			undet = true
		}
	}
	switch {
	case undet:
		return Undeterminable
	case p.Quant == "all":
		return True
	}
	return False
}

// subjectType reads a subject as one of the three value types: "string",
// "integer" or "boolean", "" for any other value.
func subjectType(v *jsonv.Value) (string, bool) {
	switch v.Kind {
	case jsonv.String:
		s, ok := v.Str()
		if !ok || utf8.RuneCountInString(s) > MaxSubjectCodePoints {
			return "", false
		}
		return "string", true
	case jsonv.Number:
		if _, ok := grammar.Integer(v); ok {
			return "integer", true
		}
	case jsonv.Bool:
		return "boolean", true
	}
	return "", false
}

func truth(b bool) Truth {
	if b {
		return True
	}
	return False
}

// apply evaluates the operation on one subject that is not an array.
func (p Predicate) apply(s *jsonv.Value) Truth {
	st, ok := subjectType(s)
	if !ok {
		return Undeterminable
	}
	switch p.Op {
	case "eq", "ne":
		vt, _ := subjectType(p.Value)
		same := vt == st && equal(s, p.Value)
		if p.Op == "eq" {
			return truth(same)
		}
		return truth(!same)
	case "lt", "le", "gt", "ge":
		if st != "integer" {
			return Undeterminable
		}
		a, _ := grammar.Integer(s)
		b, _ := grammar.Integer(p.Value)
		switch p.Op {
		case "lt":
			return truth(a < b)
		case "le":
			return truth(a <= b)
		case "gt":
			return truth(a > b)
		}
		return truth(a >= b)
	}
	if st != "string" {
		return Undeterminable
	}
	str, _ := s.Str()
	switch p.Op {
	case "in", "notIn":
		in := false
		for _, x := range p.set {
			if x == str {
				in = true
			}
		}
		return truth(in == (p.Op == "in"))
	case "prefix":
		v, _ := p.Value.Str()
		return truth(strings.HasPrefix(str, v))
	case "glob":
		for _, pat := range p.set {
			if Glob(pat, str) {
				return True
			}
		}
		return False
	}
	return Undeterminable
}

// equal compares two values of one type.
func equal(a, b *jsonv.Value) bool {
	switch a.Kind {
	case jsonv.String:
		x, _ := a.Str()
		y, _ := b.Str()
		return x == y
	case jsonv.Number:
		x, _ := grammar.Integer(a)
		y, _ := grammar.Integer(b)
		return x == y
	case jsonv.Bool:
		return a.B == b.B
	}
	return false
}

// Glob matches a subject against a pattern (§9.8): both read as code
// points and split at "/"; a segment "**" matches any run of whole
// segments, none included; within a segment "*" matches any run of code
// points and "?" one code point. Both levels use the iterative two-pointer
// wildcard algorithm, with no recursion.
func Glob(pattern, subject string) bool {
	ps := strings.Split(pattern, "/")
	ss := strings.Split(subject, "/")
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(ss) {
		switch {
		case pi < len(ps) && ps[pi] == "**":
			star, mark = pi, si
			pi++
		case pi < len(ps) && segment(ps[pi], ss[si]):
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(ps) && ps[pi] == "**" {
		pi++
	}
	return pi == len(ps)
}

// segment matches one segment with "*" and "?" over code points.
func segment(pattern, subject string) bool {
	p, s := []rune(pattern), []rune(subject)
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] != '*' && p[pi] == s[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
