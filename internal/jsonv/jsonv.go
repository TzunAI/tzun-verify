// SPDX-License-Identifier: BSD-3-Clause-Clear

// Package jsonv reads JSON (RFC 8259) into a tree that keeps what a verifier
// needs and encoding/json loses:
//
//   - numbers keep their source text beside the IEEE-754 double a JavaScript
//     reader would produce, so the integer rule of Tree §4 ("3.0" reads
//     as 3, a boolean is never an integer, 2^53 is refused) is applied to the
//     value, not to the Go type it happened to decode into;
//   - a string escape that names a lone UTF-16 surrogate ("\ud800") is kept as
//     a lone surrogate and flagged, where encoding/json silently substitutes
//     U+FFFD. A chain id or a payload string holding one must be refused, not
//     compared or hashed as a different string;
//   - object members keep their order, and a repeated key keeps its first
//     position and takes its last value, as JavaScript's JSON.parse does.
//
// Every input is treated as hostile: Parse never panics, bounds nesting, and
// refuses bytes that are not UTF-8.
package jsonv

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"
)

// Kind is the JSON type of a Value.
type Kind uint8

// The JSON types.
const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

func (k Kind) String() string {
	switch k {
	case Null:
		return "null"
	case Bool:
		return "boolean"
	case Number:
		return "number"
	case String:
		return "string"
	case Array:
		return "array"
	case Object:
		return "object"
	}
	return "unknown"
}

// MaxDepth bounds the nesting of arrays and objects Parse accepts.
const MaxDepth = 4096

// Member is one member of an object.
type Member struct {
	Key string
	// KeyLone reports that Key holds a lone surrogate (see Value.Lone).
	KeyLone bool
	Value   *Value
}

// Value is one JSON value.
type Value struct {
	Kind Kind
	// B is the value of a Bool.
	B bool
	// N is a Number as a JavaScript reader reads it: the nearest double,
	// ±Inf when the literal overflows.
	N float64
	// Raw is a Number's source text.
	Raw string
	// S is a String. When Lone is true it is WTF-8: each lone surrogate is
	// the three-byte generalized UTF-8 form of its code unit, which no valid
	// UTF-8 string contains, so S then equals no well-formed string.
	S    string
	Lone bool
	// A holds an Array's elements.
	A []*Value
	// O holds an Object's members, each key once.
	O []Member
}

// Get returns the member named key of an object.
func (v *Value) Get(key string) (*Value, bool) {
	if v == nil || v.Kind != Object {
		return nil, false
	}
	for i := range v.O {
		if !v.O[i].KeyLone && v.O[i].Key == key {
			return v.O[i].Value, true
		}
	}
	return nil, false
}

// Has reports whether an object has a member named key.
func (v *Value) Has(key string) bool {
	_, ok := v.Get(key)
	return ok
}

// IsNull reports whether v is absent (nil) or the JSON null.
func (v *Value) IsNull() bool { return v == nil || v.Kind == Null }

// Str returns a well-formed string value.
func (v *Value) Str() (string, bool) {
	if v == nil || v.Kind != String || v.Lone {
		return "", false
	}
	return v.S, true
}

// maxSafe is 2^53 − 1, the largest integer a JavaScript double holds exactly.
const maxSafe = 1<<53 - 1

// Uint53 applies the integer rule of Tree §4: a JSON number with an
// integral value in [0, 2^53 − 1]. "3.0" and "1e0" qualify, "-0" reads as 0;
// a boolean, a string, 2^53 and a fraction do not.
func (v *Value) Uint53() (uint64, bool) {
	if v == nil || v.Kind != Number {
		return 0, false
	}
	f := v.N
	if math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) || f < 0 || f > maxSafe {
		return 0, false
	}
	return uint64(f), true
}

// Int53 is Uint53 for signed values in [−(2^53 − 1), 2^53 − 1].
func (v *Value) Int53() (int64, bool) {
	if v == nil || v.Kind != Number {
		return 0, false
	}
	f := v.N
	if math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) || f < -maxSafe || f > maxSafe {
		return 0, false
	}
	return int64(f), true
}

// Keys returns the keys of an object in document order.
func (v *Value) Keys() []string {
	if v == nil || v.Kind != Object {
		return nil
	}
	out := make([]string, len(v.O))
	for i, m := range v.O {
		out[i] = m.Key
	}
	return out
}

// Parse reads one JSON text. Leading and trailing JSON whitespace is allowed;
// anything else after the value is an error, and so is a byte-order mark.
func Parse(data []byte) (v *Value, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, fmt.Errorf("jsonv: %v", r)
		}
	}()
	if !utf8.Valid(data) {
		return nil, errors.New("jsonv: input is not UTF-8")
	}
	p := &parser{b: data}
	p.ws()
	v, err = p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.b) {
		return nil, p.errf("data after the JSON value")
	}
	return v, nil
}

type parser struct {
	b []byte
	i int
}

func (p *parser) errf(format string, a ...any) error {
	return fmt.Errorf("jsonv: offset %d: %s", p.i, fmt.Sprintf(format, a...))
}

func (p *parser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (*Value, error) {
	if p.i >= len(p.b) {
		return nil, p.errf("unexpected end of input")
	}
	switch c := p.b[p.i]; {
	case c == '{':
		if depth >= MaxDepth {
			return nil, p.errf("nesting deeper than %d", MaxDepth)
		}
		return p.object(depth + 1)
	case c == '[':
		if depth >= MaxDepth {
			return nil, p.errf("nesting deeper than %d", MaxDepth)
		}
		return p.array(depth + 1)
	case c == '"':
		s, lone, err := p.str()
		if err != nil {
			return nil, err
		}
		return &Value{Kind: String, S: s, Lone: lone}, nil
	case c == 't':
		return p.lit("true", &Value{Kind: Bool, B: true})
	case c == 'f':
		return p.lit("false", &Value{Kind: Bool})
	case c == 'n':
		return p.lit("null", &Value{Kind: Null})
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.errf("unexpected character %q", c)
	}
}

func (p *parser) lit(word string, v *Value) (*Value, error) {
	if len(p.b)-p.i < len(word) || string(p.b[p.i:p.i+len(word)]) != word {
		return nil, p.errf("invalid literal")
	}
	p.i += len(word)
	return v, nil
}

func (p *parser) object(depth int) (*Value, error) {
	p.i++ // {
	v := &Value{Kind: Object}
	index := map[string]int{}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return v, nil
	}
	for {
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return nil, p.errf("expected a string key")
		}
		k, lone, err := p.str()
		if err != nil {
			return nil, err
		}
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return nil, p.errf("expected ':'")
		}
		p.i++
		p.ws()
		mv, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		if at, seen := index[k]; seen {
			v.O[at].Value = mv
		} else {
			index[k] = len(v.O)
			v.O = append(v.O, Member{Key: k, KeyLone: lone, Value: mv})
		}
		p.ws()
		if p.i >= len(p.b) {
			return nil, p.errf("unterminated object")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return v, nil
		default:
			return nil, p.errf("expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (*Value, error) {
	p.i++ // [
	v := &Value{Kind: Array, A: []*Value{}}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return v, nil
	}
	for {
		p.ws()
		e, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		v.A = append(v.A, e)
		p.ws()
		if p.i >= len(p.b) {
			return nil, p.errf("unterminated array")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return v, nil
		default:
			return nil, p.errf("expected ',' or ']'")
		}
	}
}

// number reads the RFC 8259 number grammar exactly:
// -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?
func (p *parser) number() (*Value, error) {
	start := p.i
	if p.b[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.b) {
		return nil, p.errf("truncated number")
	}
	switch {
	case p.b[p.i] == '0':
		p.i++
	case p.b[p.i] >= '1' && p.b[p.i] <= '9':
		for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
			p.i++
		}
	default:
		return nil, p.errf("invalid number")
	}
	if p.i < len(p.b) && p.b[p.i] == '.' {
		p.i++
		d := p.i
		for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
			p.i++
		}
		if p.i == d {
			return nil, p.errf("invalid fraction")
		}
	}
	if p.i < len(p.b) && (p.b[p.i] == 'e' || p.b[p.i] == 'E') {
		p.i++
		if p.i < len(p.b) && (p.b[p.i] == '+' || p.b[p.i] == '-') {
			p.i++
		}
		d := p.i
		for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
			p.i++
		}
		if p.i == d {
			return nil, p.errf("invalid exponent")
		}
	}
	raw := string(p.b[start:p.i])
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		var ne *strconv.NumError
		// Overflow reads as ±Inf, underflow as ±0, as in JavaScript.
		if !errors.As(err, &ne) || ne.Err != strconv.ErrRange {
			return nil, p.errf("invalid number %q", raw)
		}
	}
	return &Value{Kind: Number, N: f, Raw: raw}, nil
}

// str reads a string literal. It returns the value, with any lone surrogate
// in WTF-8, and whether one occurred.
func (p *parser) str() (string, bool, error) {
	p.i++ // "
	var out []byte
	lone := false
	for {
		if p.i >= len(p.b) {
			return "", false, p.errf("unterminated string")
		}
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out), lone, nil
		case c < 0x20:
			return "", false, p.errf("control character in string")
		case c == '\\':
			p.i++
			if p.i >= len(p.b) {
				return "", false, p.errf("unterminated escape")
			}
			e := p.b[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				u, err := p.hex4()
				if err != nil {
					return "", false, err
				}
				switch {
				case u >= 0xD800 && u <= 0xDBFF:
					// A high surrogate pairs only with an immediately
					// following escaped low surrogate.
					if p.i+6 <= len(p.b) && p.b[p.i] == '\\' && p.b[p.i+1] == 'u' {
						save := p.i
						p.i += 2
						lo, err := p.hex4()
						if err == nil && lo >= 0xDC00 && lo <= 0xDFFF {
							r := 0x10000 + (rune(u)-0xD800)<<10 + (rune(lo) - 0xDC00)
							out = utf8.AppendRune(out, r)
							continue
						}
						p.i = save
					}
					out = appendWTF8(out, u)
					lone = true
				case u >= 0xDC00 && u <= 0xDFFF:
					out = appendWTF8(out, u)
					lone = true
				default:
					out = utf8.AppendRune(out, rune(u))
				}
			default:
				return "", false, p.errf("invalid escape \\%c", e)
			}
		default:
			// Input is valid UTF-8 (checked in Parse); copy the byte.
			out = append(out, c)
			p.i++
		}
	}
}

func (p *parser) hex4() (uint16, error) {
	if p.i+4 > len(p.b) {
		return 0, p.errf("truncated \\u escape")
	}
	var u uint16
	for k := 0; k < 4; k++ {
		c := p.b[p.i+k]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, p.errf("invalid \\u escape")
		}
		u = u<<4 | uint16(d)
	}
	p.i += 4
	return u, nil
}

// appendWTF8 writes a surrogate code unit as generalized UTF-8.
func appendWTF8(b []byte, u uint16) []byte {
	return append(b, 0xE0|byte(u>>12), 0x80|byte(u>>6)&0x3F, 0x80|byte(u)&0x3F)
}
