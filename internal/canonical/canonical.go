// Package canonical is the DEO canonical serializer (schema v1.0), the part
// of it a verifier needs to recompute a record's integrity.canonicalDigest
// and the digests taken over parts of a record (Record §3).
//
// The rules are those of Record §3, which the conformance vectors
// v1.0-canonical-vectors.json and v1.0-integrity-vectors.json pin:
//
//   - UTF-8 JSON with no whitespace, "," and ":" as the only separators;
//   - object keys sorted at every level by UTF-16 code units (so U+1F600,
//     whose first code unit is 0xD83D, sorts before U+FF01);
//   - arrays keep their order;
//   - null stays null; numbers are finite and rendered as ECMAScript
//     Number::toString renders them (1e-7, 1e+21, 100000000000000000000);
//   - strings are escaped as ECMAScript JSON.stringify escapes them (quote,
//     backslash, \b \f \n \r \t, other controls as \u00xx) and otherwise
//     passed through with no Unicode normalisation;
//   - a lone surrogate, a non-finite number and nesting deeper than MaxDepth
//     are refused.
package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// MaxDepth is the deepest nesting of objects and arrays the serializer
// accepts, counting the outermost value as depth 1. The v1.0 rules require a
// maximum without stating it; 64 refuses the conformance vector N03 (66
// levels) and accepts every record the vectors hold.
const MaxDepth = 64

// ErrLoneSurrogate, ErrNonFinite and ErrDepth are the refusals the v1.0
// rules require.
var (
	ErrLoneSurrogate = errors.New("canonical: lone surrogate")
	ErrNonFinite     = errors.New("canonical: non-finite number")
	ErrDepth         = errors.New("canonical: nesting depth exceeded")
)

// HashedFieldsV1 is the hashed field set of a v1.0 payload, the eleven
// names of Record §4.1. A field the payload lacks is hashed as null
// (Record §4.2).
var HashedFieldsV1 = []string{
	"action", "aiOutput", "aiSystemId", "capturedAt", "contributions", "decider", "evidenceId", "links", "reason",
	"sequenceNumber", "signoffExpectation",
}

// FieldSet07 and FieldSetBefore07 are the earlier field sets Record §4.1
// names, "0.7" and "before-0.7". A record is never verified under either:
// they only name the set a mismatching stored digest recomputes under
// (Verification §4.3).
var (
	FieldSet07       = []string{"aiBom", "aiOutput", "aiSystemId", "capturedAt", "evidenceId", "humanAction", "humanReason", "sequenceNumber", "signoffExpectation"}
	FieldSetBefore07 = []string{"aiBom", "aiOutput", "aiSystemId", "capturedAt", "evidenceId", "humanAction", "humanReason", "sequenceNumber"}
)

// PayloadMembers are the twelve payload members of Record §2.2: the
// hashed set and schemaVersion. Any other member is reported, never hashed
// (Verification §4.7).
var PayloadMembers = map[string]bool{"schemaVersion": true}

func init() {
	for _, f := range HashedFieldsV1 {
		PayloadMembers[f] = true
	}
}

// EarlierFieldSet names the earlier field set under which a payload
// recomputes to the stored digest, "0.7" or "before-0.7", or "" when
// neither does.
func EarlierFieldSet(payload *jsonv.Value, stored string) string {
	for _, fs := range []struct {
		name   string
		fields []string
	}{{"0.7", FieldSet07}, {"before-0.7", FieldSetBefore07}} {
		if d, err := DigestOver(payload, fs.fields); err == nil && d == stored {
			return fs.name
		}
	}
	return ""
}

// SignoffExpectationKey is the hashed field that says which signature a
// record owes (Record §9).
const SignoffExpectationKey = "signoffExpectation"

// Serialize renders v in canonical form.
func Serialize(v *jsonv.Value) ([]byte, error) {
	var b strings.Builder
	if err := write(&b, v, 1); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// SelectFields builds the object a digest is taken over: each named field of
// payload, and null for a field the payload lacks.
func SelectFields(payload *jsonv.Value, fields []string) (*jsonv.Value, error) {
	if payload == nil || payload.Kind != jsonv.Object {
		return nil, errors.New("canonical: payload is not an object")
	}
	out := &jsonv.Value{Kind: jsonv.Object}
	for _, f := range fields {
		fv, ok := payload.Get(f)
		if !ok {
			fv = &jsonv.Value{Kind: jsonv.Null}
		}
		out.O = append(out.O, jsonv.Member{Key: f, Value: fv})
	}
	return out, nil
}

// Digest is SHA-256 of the canonical bytes, as 64 lowercase hex characters.
func Digest(canonicalBytes []byte) string {
	sum := sha256.Sum256(canonicalBytes)
	return hex.EncodeToString(sum[:])
}

// RecordDigest recomputes integrity.canonicalDigest from a v1.0 payload
// under the current hashed field set.
func RecordDigest(payload *jsonv.Value) (string, error) {
	return DigestOver(payload, HashedFieldsV1)
}

// ChainLink is a v1.0 record's integrity.chainLink: SHA-256 over the
// predecessor's digest and then the record's own, both as the hex text the
// envelope stores them in (v1.0-integrity-vectors.json).
func ChainLink(previous, current string) string {
	return Digest([]byte(previous + current))
}

// DigestOver is the digest of a payload under a given hashed field set.
func DigestOver(payload *jsonv.Value, fields []string) (string, error) {
	sel, err := SelectFields(payload, fields)
	if err != nil {
		return "", err
	}
	c, err := Serialize(sel)
	if err != nil {
		return "", err
	}
	return Digest(c), nil
}

func write(b *strings.Builder, v *jsonv.Value, depth int) error {
	if v == nil {
		b.WriteString("null")
		return nil
	}
	switch v.Kind {
	case jsonv.Null:
		b.WriteString("null")
	case jsonv.Bool:
		if v.B {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case jsonv.Number:
		s, err := FormatNumber(v.N)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case jsonv.String:
		if v.Lone {
			return ErrLoneSurrogate
		}
		writeString(b, v.S)
	case jsonv.Array:
		if depth > MaxDepth {
			return ErrDepth
		}
		b.WriteByte('[')
		for i, e := range v.A {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, e, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case jsonv.Object:
		if depth > MaxDepth {
			return ErrDepth
		}
		members := make([]jsonv.Member, len(v.O))
		copy(members, v.O)
		for _, m := range members {
			if m.KeyLone {
				return ErrLoneSurrogate
			}
		}
		sort.SliceStable(members, func(i, j int) bool { return LessUTF16(members[i].Key, members[j].Key) })
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, m.Key)
			b.WriteByte(':')
			if err := write(b, m.Value, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unknown kind %d", v.Kind)
	}
	return nil
}

// LessUTF16 orders two well-formed strings by their UTF-16 code units.
func LessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeString(b *strings.Builder, s string) {
	const hexdigits = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexdigits[c>>4])
				b.WriteByte(hexdigits[c&0xF])
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
}

// FormatNumber renders a double as ECMAScript Number::toString (radix 10)
// does, which is also how JSON.stringify writes a finite number.
func FormatNumber(x float64) (string, error) {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return "", ErrNonFinite
	}
	if x == 0 {
		return "0", nil // both +0 and −0
	}
	sign := ""
	if x < 0 {
		sign = "-"
		x = -x
	}
	// The shortest digits that round-trip, as d.ddddde±X.
	e := strconv.FormatFloat(x, 'e', -1, 64)
	mant, expPart, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, err := strconv.Atoi(expPart)
	if err != nil {
		return "", err
	}
	k := len(digits)
	n := exp + 1 // x = 0.digits × 10^n
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		es := "+"
		if n-1 < 0 {
			es = "-"
		}
		ev := n - 1
		if ev < 0 {
			ev = -ev
		}
		if k == 1 {
			out = digits + "e" + es + strconv.Itoa(ev)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + es + strconv.Itoa(ev)
		}
	}
	return sign + out, nil
}
