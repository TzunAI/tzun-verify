// Package checkpoint reads Tzun checkpoint bodies and origins
// (Anchor §4). A bare §n in this package's comments is a section of
// Anchor.
//
// A body is the body of a C2SP tlog-checkpoint, restricted: exactly three
// LF-terminated lines, a size in [1, 2^53 − 1] with no leading zero, and a root
// in canonical base64. Parse applies the §4.2 grammar and then requires the
// stock C2SP body parser, transparency-dev/formats log.Checkpoint.Unmarshal
// at v0.1.1, to read the same origin, size and root.
//
// Parsing does not apply Tzun's origin scheme. ParseOrigin and Bind do, for
// step 2b of §10.3.
package checkpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/transparency-dev/formats/log"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// MaxSize is 2^53 − 1, the largest size a body may state.
const MaxSize = 1<<53 - 1

// bodyRE is the §4.2 grammar. In Go's RE2, ^ and $ match only at the ends
// of the text, so the match covers the whole body and a trailing newline
// after the third LF is refused.
var bodyRE = regexp.MustCompile(`^([\x21-\x2A\x2C-\x7E]+)\n([1-9][0-9]{0,15})\n([A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=)\n$`)

// Body is a parsed checkpoint body.
type Body struct {
	Origin string
	Size   uint64
	Root   []byte
	// Raw is the body's bytes.
	Raw string
}

// Parse reads a JSON value as a checkpoint body. A value that is not a
// string is not a body.
func Parse(v *jsonv.Value) (*Body, bool) {
	s, ok := v.Str()
	if !ok {
		return nil, false
	}
	return ParseString(s)
}

// ParseString reads a body under §4.2.
func ParseString(s string) (*Body, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\n' && (c < 0x21 || c > 0x7E) {
			return nil, false
		}
	}
	m := bodyRE.FindStringSubmatch(s)
	if m == nil {
		return nil, false
	}
	size, err := strconv.ParseUint(m[2], 10, 64)
	if err != nil || size > MaxSize {
		return nil, false
	}
	var cp log.Checkpoint
	rest, err := cp.Unmarshal([]byte(s))
	if err != nil || len(rest) != 0 || cp.Origin != m[1] || cp.Size != size || len(cp.Hash) != 32 {
		return nil, false
	}
	return &Body{Origin: cp.Origin, Size: cp.Size, Root: cp.Hash, Raw: s}, true
}

// Digest is checkpointDigest(body) = SHA-256(body bytes) (§4.4).
func Digest(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// DigestHex is Digest as 64 lowercase hex characters.
func DigestHex(raw string) string { return hex.EncodeToString(Digest(raw)) }

// Kind of log an origin names.
type Kind int

// The kinds of §4.3.1.
const (
	KindAnchors  Kind = iota + 1 // <prefix>/anchors
	KindEvidence                 // <prefix>/evidence/<chain segment>
	KindOther                    // <prefix>/<one other segment>
)

// Origin is a Tzun origin (§4.3.1).
type Origin struct {
	Raw string
	// Prefix is the domain prefix: the first two segments.
	Prefix string
	// Namespace is the first segment.
	Namespace string
	Kind      Kind
	// Segment is the third segment for KindOther, and the chain segment for
	// KindEvidence.
	Segment string
	// ChainID is the chain id an evidence origin's chain segment spells.
	ChainID string
}

func segmentOK(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7E || c == '/' || c == '+' {
			return false
		}
	}
	return true
}

// ParseOrigin reads a Tzun origin: three or four segments, the chain
// segment rule of §4.3.2 for an evidence log. Anything else is not a Tzun
// origin.
func ParseOrigin(s string) (*Origin, bool) {
	segs := strings.Split(s, "/")
	if len(segs) != 3 && len(segs) != 4 {
		return nil, false
	}
	for _, g := range segs {
		if !segmentOK(g) {
			return nil, false
		}
	}
	o := &Origin{Raw: s, Prefix: segs[0] + "/" + segs[1], Namespace: segs[0]}
	switch {
	case len(segs) == 3 && segs[2] == "anchors":
		o.Kind = KindAnchors
	case len(segs) == 3 && segs[2] == "evidence":
		return nil, false
	case len(segs) == 3:
		o.Kind = KindOther
		o.Segment = segs[2]
	case segs[2] == "evidence":
		chain, ok := DecodeChainSegment(segs[3])
		if !ok {
			return nil, false
		}
		o.Kind = KindEvidence
		o.Segment = segs[3]
		o.ChainID = chain
	default:
		return nil, false
	}
	return o, true
}

// DecodeChainSegment applies the reader's chain segment rule (§4.3.2): pairs
// of lowercase hex digits, no 0x00 byte, strict UTF-8 that re-encodes to the
// same segment.
func DecodeChainSegment(seg string) (string, bool) {
	if seg == "" || len(seg)%2 != 0 {
		return "", false
	}
	b, err := hex.DecodeString(seg)
	if err != nil || bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) {
		return "", false
	}
	// Re-encoding refuses uppercase digits: only the lowercase spelling of
	// the bytes is a chain segment.
	if hex.EncodeToString(b) != seg {
		return "", false
	}
	return string(b), true
}

// EncodeChainSegment is the writer's rule: the lowercase hex of the chain
// id's UTF-8 bytes. A chain id that is empty or holds U+0000 has none.
// Callers holding a string with a lone surrogate must refuse it first.
func EncodeChainSegment(chainID string) (string, bool) {
	if chainID == "" || strings.IndexByte(chainID, 0) >= 0 || !utf8.ValidString(chainID) {
		return "", false
	}
	return hex.EncodeToString([]byte(chainID)), true
}

// IsTestOrigin reports whether an origin begins with the five bytes "test."
// (§4.3.4).
func IsTestOrigin(origin string) bool { return strings.HasPrefix(origin, "test.") }

// PlatformNamespace is the namespace whose source-log origins are opaque
// (§4.3.3), and TestPlatformNamespace the one a platform deployment that
// anchors in the test namespace uses (§4.3.4). Nothing but these two exact
// names counts: test.log.tzun.ai.example and staging.log.tzun.ai do not.
const (
	PlatformNamespace     = "log.tzun.ai"
	TestPlatformNamespace = "test.log.tzun.ai"
)

// IsPlatformNamespace reports whether a namespace is exactly one of the
// platform's.
func IsPlatformNamespace(ns string) bool {
	return ns == PlatformNamespace || ns == TestPlatformNamespace
}

// Binding reasons of step 2b.
const (
	BindOK              = "ok"
	BindNotInDomain     = "origin_not_in_domain"
	BindChainIDMismatch = "chain_id_mismatch"
)

// BindResult is the outcome of step 2b.
type BindResult struct {
	Result       string
	Namespace    string
	ChainChecked bool
}

// Bind is step 2b of §10.3 (§4.3.5): both origins are Tzun origins, the
// anchor origin's rest is "anchors" and the log origin's is not, the two
// share a domain prefix, and, with a chain id supplied, the log is that
// chain's evidence log (an opaque platform origin, namespace exactly
// log.tzun.ai or exactly test.log.tzun.ai, leaves the chain unchecked). chainID nil means not supplied;
// chainOK false means the supplied chain id holds a lone surrogate.
func Bind(anchorOrigin, logOrigin string, chainID *string, chainOK bool) BindResult {
	ao, ok1 := ParseOrigin(anchorOrigin)
	lo, ok2 := ParseOrigin(logOrigin)
	if !ok1 || !ok2 || ao.Kind != KindAnchors || lo.Kind == KindAnchors || ao.Prefix != lo.Prefix {
		return BindResult{Result: BindNotInDomain}
	}
	r := BindResult{Result: BindOK, Namespace: lo.Namespace}
	if chainID == nil {
		return r
	}
	switch lo.Kind {
	case KindEvidence:
		if !chainOK || lo.ChainID != *chainID {
			return BindResult{Result: BindChainIDMismatch}
		}
		r.ChainChecked = true
	default:
		if !IsPlatformNamespace(lo.Namespace) {
			return BindResult{Result: BindChainIDMismatch}
		}
	}
	return r
}

// BindRecord is step 2b for a record's own artifact (§10.3). On top of
// Bind, a log origin of a kind other than evidence is chain_id_mismatch
// whether or not a chain id is supplied, since a record has a leaf in its
// own chain's evidence log and nowhere else; an opaque hosted log, whose
// kind cannot be read (§4.3.3), is the one exception.
func BindRecord(anchorOrigin, logOrigin string, chainID *string, chainOK bool) BindResult {
	r := Bind(anchorOrigin, logOrigin, chainID, chainOK)
	if r.Result != BindOK {
		return r
	}
	if lo, _ := ParseOrigin(logOrigin); lo.Kind != KindEvidence && !IsPlatformNamespace(lo.Namespace) {
		return BindResult{Result: BindChainIDMismatch}
	}
	return r
}

// ValidNamespace applies the writer's grammar for a store's ns
// (§4.3.2): lowercase DNS-style labels of [a-z0-9] with interior "-",
// separated by ".", at most 63 characters a label and 253 in all. A reader
// never applies it: step 2b takes any origin segment.
func ValidNamespace(ns string) bool {
	if ns == "" || len(ns) > 253 {
		return false
	}
	for _, label := range strings.Split(ns, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
