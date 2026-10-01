// Package manifest reads the publisher manifest (Anchor §9): the
// verifier's own list of which addresses may publish for which anchor
// origin. It never comes from the artifact. A bare §n in this package's
// comments is a section of Anchor.
package manifest

import (
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// State is what a verifier reads for one anchor origin.
type State int

// The three readings of §9.
const (
	// NoEntries: no manifest, no publishers member, no key for the origin,
	// or no EVM entry left (no_expectation:publisher).
	NoEntries State = iota
	// Unreadable: a value or an EVM entry that breaks a rule
	// (input_not_supplied:publisher_manifest).
	Unreadable
	// OK: one or more well-formed EVM entries.
	OK
)

// Instant is a validFrom or validUntil time at full precision: a whole
// second in Unix time and whether a non-zero fraction follows it.
type Instant struct {
	Sec  int64
	Frac bool
}

// Entry is one well-formed EVM manifest entry.
type Entry struct {
	// Address is 0x and 40 lowercase hex.
	Address string
	// Chain is the CAIP-2 chain as written, eip155:<id>.
	Chain   string
	ChainID *big.Int
	// Namespace is "production" or "test".
	Namespace  string
	ValidFrom  *Instant
	ValidUntil *Instant
}

// ValidAt reports whether a whole-second block time falls in the entry's
// window. Both ends are inclusive and compared at full precision.
func (e Entry) ValidAt(blockTime int64) bool {
	if e.ValidFrom != nil {
		from := e.ValidFrom.Sec
		if e.ValidFrom.Frac {
			from++ // a block time is whole, so it must reach the next second
		}
		if blockTime < from {
			return false
		}
	}
	if e.ValidUntil != nil && blockTime > e.ValidUntil.Sec {
		return false
	}
	return true
}

// Bounded reports whether either end of the window is set.
func (e Entry) Bounded() bool { return e.ValidFrom != nil || e.ValidUntil != nil }

// Lookup is the result of reading the manifest for one anchor origin.
type Lookup struct {
	State   State
	Entries []Entry
}

var (
	addressRE = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	chainRE   = regexp.MustCompile(`^eip155:[1-9][0-9]{0,30}$`)
	timeRE    = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$`)
)

// ForOrigin reads the manifest's entries for anchorOrigin, in the order §9
// gives.
func ForOrigin(m *jsonv.Value, anchorOrigin string) Lookup {
	if m == nil || m.Kind != jsonv.Object {
		return Lookup{State: NoEntries}
	}
	pubs, ok := m.Get("publishers")
	if !ok || pubs.Kind != jsonv.Object {
		return Lookup{State: NoEntries}
	}
	val, ok := pubs.Get(anchorOrigin)
	if !ok {
		return Lookup{State: NoEntries}
	}
	if val.Kind != jsonv.Array {
		return Lookup{State: Unreadable}
	}
	var out []Entry
	for _, el := range val.A {
		if el.Kind != jsonv.Object {
			return Lookup{State: Unreadable}
		}
		cv, ok := el.Get("chain")
		if !ok || cv.Kind != jsonv.String {
			return Lookup{State: Unreadable}
		}
		// A chain holding a lone surrogate is still a string: it is skipped
		// when it does not begin with eip155:, and otherwise breaks the
		// chain rule below and is unreadable.
		if !strings.HasPrefix(cv.S, "eip155:") {
			continue // not an EVM entry: skipped by an EVM verifier
		}
		e, ok := parseEntry(el, cv.S)
		if !ok {
			return Lookup{State: Unreadable}
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return Lookup{State: NoEntries}
	}
	return Lookup{State: OK, Entries: out}
}

func parseEntry(el *jsonv.Value, chain string) (Entry, bool) {
	if !chainRE.MatchString(chain) {
		return Entry{}, false
	}
	id, ok := new(big.Int).SetString(strings.TrimPrefix(chain, "eip155:"), 10)
	if !ok {
		return Entry{}, false
	}
	addr, ok := el.Get("address")
	if !ok {
		return Entry{}, false
	}
	a, ok := addr.Str()
	if !ok || !addressRE.MatchString(a) {
		return Entry{}, false
	}
	nsv, ok := el.Get("namespace")
	if !ok {
		return Entry{}, false
	}
	ns, ok := nsv.Str()
	if !ok || (ns != "production" && ns != "test") {
		return Entry{}, false
	}
	e := Entry{Address: strings.ToLower(a), Chain: chain, ChainID: id, Namespace: ns}
	for _, k := range []string{"validFrom", "validUntil"} {
		v, present := el.Get(k)
		if !present || v.Kind == jsonv.Null {
			continue
		}
		s, ok := v.Str()
		if !ok {
			return Entry{}, false
		}
		in, ok := ParseTime(s)
		if !ok {
			return Entry{}, false
		}
		if k == "validFrom" {
			e.ValidFrom = &in
		} else {
			e.ValidUntil = &in
		}
	}
	return e, true
}

// ParseTime reads the narrowed RFC 3339 form of §9:
// YYYY-MM-DD "T" hh:mm:ss [ "." 1*DIGIT ] ( "Z" / ( "+" / "-" ) hh:mm ),
// uppercase T and Z only, every field range-checked, no leap second and no
// rollover.
func ParseTime(s string) (Instant, bool) {
	m := timeRE.FindStringSubmatch(s)
	if m == nil {
		return Instant{}, false
	}
	num := func(x string) int { n, _ := strconv.Atoi(x); return n }
	year, month, day := num(m[1]), num(m[2]), num(m[3])
	hour, minute, sec := num(m[4]), num(m[5]), num(m[6])
	if month < 1 || month > 12 || day < 1 || day > daysIn(year, month) {
		return Instant{}, false
	}
	if hour > 23 || minute > 59 || sec > 59 {
		return Instant{}, false
	}
	offset := 0
	if m[8] != "Z" {
		oh, om := num(m[8][1:3]), num(m[8][4:6])
		if oh > 23 || om > 59 {
			return Instant{}, false
		}
		offset = oh*3600 + om*60
		if m[8][0] == '-' {
			offset = -offset
		}
	}
	frac := false
	if m[7] != "" {
		frac = strings.Trim(m[7][1:], "0") != ""
	}
	t := time.Date(year, time.Month(month), day, hour, minute, sec, 0, time.UTC)
	return Instant{Sec: t.Unix() - int64(offset), Frac: frac}, true
}

func daysIn(year, month int) int {
	switch month {
	case 4, 6, 9, 11:
		return 30
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	}
	return 31
}

// Network is the verifier's own registry of chains (§9): never from the
// artifact. Ethereum mainnet is mainnet, and the Sepolia and Hoodi test
// networks are testnet. It returns "" for a chain the registry does not
// name.
func Network(chain string) string {
	switch chain {
	case "eip155:1":
		return "mainnet"
	case "eip155:11155111", "eip155:560048":
		return "testnet"
	}
	return ""
}
