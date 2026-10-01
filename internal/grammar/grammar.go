// Package grammar holds the value rules the record members share
// (Record §1.2): bare and prefixed digests, printable and visible ASCII,
// lengths in UTF-16 code units, sets, integers and booleans, and objects
// whose grammar requires every member. A bare §n in this package's comments
// is a section of Record.
package grammar

import (
	"unicode/utf16"
	"unicode/utf8"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// BareDigest reports whether s is exactly 64 characters of 0-9 and a-f
// (§1.2): uppercase digits, a prefix, whitespace or a trailing newline make
// it malformed.
func BareDigest(s string) bool { return LowerHex(s, 64) }

// LowerHex reports whether s is exactly n characters of 0-9 and a-f.
func LowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// PrefixedDigest reports whether s is "sha256:" followed by a bare digest.
func PrefixedDigest(s string) bool {
	return len(s) == 71 && s[:7] == "sha256:" && BareDigest(s[7:])
}

// PrintableASCII reports whether every character of s is U+0020 to U+007E.
func PrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// VisibleASCII reports whether every character of s is U+0021 to U+007E.
func VisibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// UTF16Len is the length of a well-formed string in UTF-16 code units, the
// length every rule of the record counts (§1.2).
func UTF16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// CodePoints is the number of code points of a well-formed string.
func CodePoints(s string) int { return utf8.RuneCountInString(s) }

// Str reads a well-formed string: a JSON string with no lone surrogate.
func Str(v *jsonv.Value) (string, bool) { return v.Str() }

// Integer applies the integer rule (§1.2): a JSON number whose binary64
// value is integral and in [0, 2^53 − 1]. A string or a boolean never is.
func Integer(v *jsonv.Value) (uint64, bool) { return v.Uint53() }

// Bool reads a JSON boolean: true or false and nothing else.
func Bool(v *jsonv.Value) (bool, bool) {
	if v == nil || v.Kind != jsonv.Bool {
		return false, false
	}
	return v.B, true
}

// IsNull reports whether a member is present with the value null.
func IsNull(v *jsonv.Value) bool { return v != nil && v.Kind == jsonv.Null }

// Exact reports whether v is an object whose members are exactly the names
// given, each present whatever its value: the objects whose grammar requires
// every member, where a missing key and a null one differ (§4.2).
func Exact(v *jsonv.Value, names ...string) bool {
	if v == nil || v.Kind != jsonv.Object || len(v.O) != len(names) {
		return false
	}
	for _, n := range names {
		if !v.Has(n) {
			return false
		}
	}
	return true
}

// Members reports, for an object, whether it has a member outside names
// (unknown) and whether one of names is missing.
func Members(v *jsonv.Value, names ...string) (unknown, missing bool) {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	for _, m := range v.O {
		if m.KeyLone || !want[m.Key] {
			unknown = true
		}
	}
	for _, n := range names {
		if !v.Has(n) {
			missing = true
		}
	}
	return unknown, missing
}

// Set reads a set (§1.2): a JSON array of strings in strictly increasing
// order of their UTF-8 bytes, so with no repeated element, of min to max
// elements, each meeting elem. A reader never sorts one.
func Set(v *jsonv.Value, min, max int, elem func(string) bool) ([]string, bool) {
	if v == nil || v.Kind != jsonv.Array || len(v.A) < min || len(v.A) > max {
		return nil, false
	}
	out := make([]string, 0, len(v.A))
	for i, e := range v.A {
		s, ok := e.Str()
		if !ok || (elem != nil && !elem(s)) {
			return nil, false
		}
		if i > 0 && !(out[i-1] < s) {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// StringArray reads an array of well-formed strings of min to max elements,
// each meeting elem, in any order, for a reader that must tell an unsorted
// set from one with a bad element.
func StringArray(v *jsonv.Value, min, max int, elem func(string) bool) ([]string, bool) {
	if v == nil || v.Kind != jsonv.Array || len(v.A) < min || len(v.A) > max {
		return nil, false
	}
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		s, ok := e.Str()
		if !ok || (elem != nil && !elem(s)) {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// Increasing reports whether a list of strings is strictly increasing by
// bytes.
func Increasing(xs []string) bool {
	for i := 1; i < len(xs); i++ {
		if !(xs[i-1] < xs[i]) {
			return false
		}
	}
	return true
}

// CapName is the grammar of a cap name, and of a predicate's name
// (§9.2, §9.7): /[A-Za-z0-9._-]{1,64}/.
func CapName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	return nameChars(s)
}

// nameChars reports whether every character of s is one of A-Z, a-z, 0-9,
// '.', '_' and '-'.
func nameChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// AcctValue is the value grammar of the acct scheme (§6.3),
// /[A-Za-z0-9._-]{1,128}/, which a mandate's signer and principal follow too.
func AcctValue(s string) bool { return len(s) >= 1 && len(s) <= 128 && nameChars(s) }

// RoleName is the grammar of a step role's name (§7.1),
// /[A-Za-z0-9._-]{1,48}/.
func RoleName(s string) bool { return len(s) >= 1 && len(s) <= 48 && nameChars(s) }
