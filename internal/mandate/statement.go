// SPDX-License-Identifier: BSD-3-Clause-Clear

package mandate

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/decider"
	"github.com/TzunAI/tzun-verify/internal/grammar"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// StatementVersion is the mandate statement format (§9.6).
const StatementVersion = "tzun-signoff-mandate/1"

// The domains of the challenges of §9.4 and of the assertion digest of
// §9.6.
const (
	StatementDomain    = "tzun-signoff-v1"
	ConfirmationDomain = "tzun-confirm-v1"
	AssertionDomain    = "tzun-assertion-v1"
)

// Challenge is B64URL(SHA-256(UTF-8(domain) ‖ UTF-8(text))), the form of
// every challenge of §9.4.
func Challenge(domain, text string) string {
	s := sha256.Sum256([]byte(domain + text))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

// Statement is a well-formed mandate statement.
type Statement struct {
	Digest        string
	MandateDigest string
	Signer        string
}

// inDomain reports whether a statement lies in the value domain of §9.4: a
// flat object whose member names are printable ASCII and whose values are
// strings of printable ASCII or integers.
func inDomain(st *jsonv.Value) bool {
	if st == nil || st.Kind != jsonv.Object {
		return false
	}
	for _, m := range st.O {
		if m.KeyLone || !grammar.PrintableASCII(m.Key) {
			return false
		}
		switch m.Value.Kind {
		case jsonv.String:
			s, ok := m.Value.Str()
			if !ok || !grammar.PrintableASCII(s) {
				return false
			}
		case jsonv.Number:
			if _, ok := grammar.Integer(m.Value); !ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ParseStatement reads a mandate statement (§9.6): in the value domain,
// with exactly its eight members, each within its rule.
func ParseStatement(st *jsonv.Value) (Statement, bool) {
	if !inDomain(st) || !grammar.Exact(st, "v", "mode", "mandateDigest", "signer", "signerKind", "meaning",
		"policyDigest", "notBefore") {
		return Statement{}, false
	}
	str := func(k string) string { s, _ := member(st, k).Str(); return s }
	s := Statement{MandateDigest: str("mandateDigest"), Signer: str("signer")}
	if str("v") != StatementVersion || str("mode") != "mandate" || !grammar.BareDigest(s.MandateDigest) ||
		!grammar.AcctValue(s.Signer) || str("signerKind") != "human" || str("meaning") != "responsibility" {
		return Statement{}, false
	}
	if pd := str("policyDigest"); pd != "none" && !grammar.BareDigest(pd) {
		return Statement{}, false
	}
	if nb := str("notBefore"); nb != "none" {
		if _, ok := decider.ParseFreshness(nb); !ok {
			return Statement{}, false
		}
	}
	b, err := canonical.Serialize(st)
	if err != nil {
		return Statement{}, false
	}
	s.Digest = canonical.Digest(b)
	return s, true
}

// Decode reads an assertion member as §9.3 states: every "=" at its end
// removed, then unpadded base64url or, failing that, unpadded base64, any
// CR and LF skipped and pad bits that need not be zero.
func Decode(s string) ([]byte, bool) {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, true
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, true
	}
	return nil, false
}

// ClientChallenge is the challenge an assertion presents and its type: the
// challenge and type members of its decoded clientDataJSON, "" when it
// presents none.
func ClientChallenge(assertion *jsonv.Value) (challenge, typ string) {
	if assertion == nil || assertion.Kind != jsonv.Object {
		return "", ""
	}
	s, ok := member(assertion, "clientDataJSON").Str()
	if !ok {
		return "", ""
	}
	raw, ok := Decode(s)
	if !ok {
		return "", ""
	}
	cd, err := jsonv.Parse(raw)
	if err != nil || cd.Kind != jsonv.Object {
		return "", ""
	}
	challenge, _ = member(cd, "challenge").Str()
	typ, _ = member(cd, "type").Str()
	return challenge, typ
}

// Presents reports whether an assertion presents a challenge (§9.3).
func Presents(assertion *jsonv.Value, challenge string) bool {
	c, _ := ClientChallenge(assertion)
	return c != "" && c == challenge
}

// p256N is the order of the P-256 group.
var p256N = elliptic.P256().Params().N

// derLength reads a definite length at b[i:], short or long form.
func derLength(b []byte, i int) (n, next int, ok bool) {
	if i >= len(b) {
		return 0, 0, false
	}
	if b[i] < 0x80 {
		return int(b[i]), i + 1, true
	}
	k := int(b[i] & 0x7f)
	if k == 0 || k > 4 || i+1+k > len(b) {
		return 0, 0, false
	}
	for j := 0; j < k; j++ {
		n = n<<8 | int(b[i+1+j])
	}
	return n, i + 1 + k, true
}

// derInteger reads an INTEGER at b[i:] as a non-negative value.
func derInteger(b []byte, i int) (*big.Int, int, bool) {
	if i >= len(b) || b[i] != 0x02 {
		return nil, 0, false
	}
	n, j, ok := derLength(b, i+1)
	if !ok || n < 1 || j+n > len(b) {
		return nil, 0, false
	}
	content := b[j : j+n]
	if content[0]&0x80 != 0 {
		return nil, 0, false // negative
	}
	return new(big.Int).SetBytes(content), j + n, true
}

// ecdsaSig reads an ES256 signature, SEQUENCE { r INTEGER, s INTEGER } with
// nothing after it, as the conformance vectors read it: a length in long
// form and an INTEGER with leading zero octets are read for their value, and
// 1 ≤ r, s ≤ n − 1.
func ecdsaSig(b []byte) (r, s *big.Int, ok bool) {
	if len(b) < 2 || b[0] != 0x30 {
		return nil, nil, false
	}
	n, i, ok := derLength(b, 1)
	if !ok || i+n != len(b) {
		return nil, nil, false
	}
	r, i, ok = derInteger(b, i)
	if !ok {
		return nil, nil, false
	}
	s, i, ok = derInteger(b, i)
	if !ok || i != len(b) {
		return nil, nil, false
	}
	one := big.NewInt(1)
	nm1 := new(big.Int).Sub(p256N, one)
	if r.Cmp(one) < 0 || r.Cmp(nm1) > 0 || s.Cmp(one) < 0 || s.Cmp(nm1) > 0 {
		return nil, nil, false
	}
	return r, s, true
}

// minimalDER encodes (r, s) as DER: shortest lengths, fewest octets.
func minimalDER(r, s *big.Int) []byte {
	enc := func(x *big.Int) []byte {
		v := x.Bytes()
		if len(v) == 0 || v[0]&0x80 != 0 {
			v = append([]byte{0}, v...)
		}
		return append([]byte{0x02, byte(len(v))}, v...)
	}
	body := append(enc(r), enc(s)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// AssertionDigest is the digest of an assertion (§9.6):
// hex(SHA-256(UTF-8("tzun-assertion-v1") ‖ SHA-256(authenticatorData) ‖
// SHA-256(clientDataJSON) ‖ SHA-256(signature'))), over the decoded bytes.
// For ES256 signature' is the minimal DER of (r, s') with s' the low-S
// form; for Ed25519 it is the signature as decoded. An assertion with
// another algorithm, or a member missing or not decoding, has none.
func AssertionDigest(a *jsonv.Value) (string, bool) {
	if a == nil || a.Kind != jsonv.Object {
		return "", false
	}
	var parts [3][]byte
	for i, k := range []string{"authenticatorData", "clientDataJSON", "signature"} {
		s, ok := member(a, k).Str()
		if !ok {
			return "", false
		}
		if parts[i], ok = Decode(s); !ok {
			return "", false
		}
	}
	alg, _ := member(a, "algorithm").Str()
	switch alg {
	case "Ed25519":
	case "ES256":
		r, s, ok := ecdsaSig(parts[2])
		if !ok {
			return "", false
		}
		half := new(big.Int).Rsh(new(big.Int).Sub(p256N, big.NewInt(1)), 1)
		if s.Cmp(half) > 0 {
			s = new(big.Int).Sub(p256N, s)
		}
		parts[2] = minimalDER(r, s)
	default:
		return "", false
	}
	h := sha256.New()
	h.Write([]byte(AssertionDomain))
	for _, p := range parts {
		s := sha256.Sum256(p)
		h.Write(s[:])
	}
	return hex.EncodeToString(h.Sum(nil)), true
}
