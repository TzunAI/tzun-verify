// Package anchor is the anchor verification of Anchor §10.3 to
// §10.7: the record artifact nonRepudiation.anchor, checked in six steps,
// with the anchor fields of §10.6 and the check catalogue of §10.7. A bare
// §n in this package's comments is a section of Anchor.
package anchor

import (
	"fmt"
	"strings"
	"time"

	"github.com/TzunAI/tzun-verify/internal/checkpoint"
	"github.com/TzunAI/tzun-verify/internal/evm"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/merkle"
	"github.com/TzunAI/tzun-verify/internal/report"
	"github.com/TzunAI/tzun-verify/internal/rfc3161"
)

// Tags of step 1.
const (
	AnchorSpec = "tzun-anchor/1"
	MerkleSpec = "rfc6962"
)

// Check ids of §10.7.
const (
	IDAnchor          = "anchor"
	IDSpec            = "anchor.spec"
	IDCheckpoint      = "anchor.checkpoint"
	IDOrigin          = "anchor.origin"
	IDLeafIndex       = "anchor.leafIndex"
	IDInclusion       = "anchor.inclusion"
	IDAnchorInclusion = "anchor.anchorInclusion"
)

// Reasons of §10.1 used here.
const (
	ReasonUnsupportedAnchorSpec = "unsupported_anchor_spec"
	ReasonUnsupportedMerkleSpec = "unsupported_merkle_spec"
	ReasonLegacy                = "legacy_blockchain_anchor"
	ReasonMalformedAnchor       = "malformed_anchor"
	ReasonMalformedCheckpoint   = "malformed_checkpoint"
	ReasonMalformedPath         = "malformed_merkle_path"
	ReasonLeafIndexMismatch     = "leaf_index_mismatch"
	ReasonMerkleProofInvalid    = "merkle_proof_invalid"
	ReasonAnchorProofInvalid    = "anchor_proof_invalid"
	ReasonMalformedPublication  = "malformed_publication"
	ReasonUnsupportedKind       = "unsupported_publication_kind"
	ReasonNoSequenceNumber      = "input_not_supplied:sequence_number"
	ReasonPublicationNotChecked = "publication_not_checked"
	ReasonVerifierError         = "anchor_verifier_error"
	ReasonAbsent                = "absent"
)

// members are exactly the members of §8.1.
var members = []string{
	"anchorSpec", "merkleSpec", "leafIndex", "logCheckpoint", "logPath",
	"anchorLeafIndex", "anchorCheckpoint", "anchorPath", "publications",
}

// DefaultTimeout is the default timeoutMs of §10.4.
const DefaultTimeout = 30 * time.Second

// Input is what the anchor verification reads (§10.2).
type Input struct {
	// Anchor is nonRepudiation.anchor, nil when the record has none. A
	// member whose value is null is absent too: an empty slot.
	Anchor *jsonv.Value
	// Legacy is true when the record carries a blockchainAnchor that is not
	// null.
	Legacy bool
	// Digest is the record's canonicalDigest, 32 bytes. When it is nil,
	// DigestBlockedBy names the check that could not produce it.
	Digest          []byte
	DigestBlockedBy string
	// SequenceNumber is the record's payload.sequenceNumber, nil when not
	// supplied.
	SequenceNumber *jsonv.Value
	// ChainID is the caller's chain id, nil when not supplied. ChainOK is
	// false when it holds a lone surrogate.
	ChainID *string
	ChainOK bool
	// Manifest is the publisher manifest (§9).
	Manifest *jsonv.Value
	Sources  evm.Sources
	Trust    rfc3161.Trust
	// Deadline bounds every header-source call. When it is zero, the
	// deadline is Timeout (default DefaultTimeout) after the call starts. A
	// caller verifying more than one anchor in one verification passes one
	// deadline to all of them.
	Deadline time.Time
	Timeout  time.Duration
	// Join returns publication i joined with the bundle's heavy material.
	Join func(i int, entry *jsonv.Value) *jsonv.Value
}

// Position is anchorPosition (§10.6).
type Position struct {
	Origin           string
	LeafIndex        uint64
	TreeSize         uint64
	AnchorOrigin     string
	AnchorLeafIndex  uint64
	AnchorSize       uint64
	LeafIndexChecked bool
	ChainChecked     bool
	Authenticated    bool
}

// JSON renders the position.
func (p *Position) JSON() *jsonv.Value {
	if p == nil {
		return report.Null()
	}
	return report.Obj(
		"origin", report.S(p.Origin),
		"leafIndex", report.N(p.LeafIndex),
		"treeSize", report.N(p.TreeSize),
		"anchorOrigin", report.S(p.AnchorOrigin),
		"anchorLeafIndex", report.N(p.AnchorLeafIndex),
		"anchorSize", report.N(p.AnchorSize),
		"leafIndexChecked", report.B(p.LeafIndexChecked),
		"chainChecked", report.B(p.ChainChecked),
		"authenticated", report.B(p.Authenticated),
	)
}

// ExistedBy is the earliest proven bound, with its source.
type ExistedBy struct {
	At     time.Time
	Source string
}

// boundAt is a bound's instant as a report writes it, to the millisecond
// with the digits beyond dropped (Verification §6.5). A block time is a
// whole second already; a genTime may carry a finer fraction.
func boundAt(t time.Time) time.Time {
	return t.UTC().Truncate(time.Millisecond)
}

// replacesBound reports whether a true publication's bound at `at`, from
// source, replaces cur, the bound kept from the publications before it in
// array order (§10.6): it is earlier, or it is at the same instant from an
// EVM publication, which also authenticates the origin, and cur is not.
// Otherwise the first in array order stays. Bounds are instants to the
// millisecond (boundAt), so two that differ only below it are the same
// instant.
func replacesBound(cur *ExistedBy, at time.Time, source string) bool {
	if cur == nil || at.Before(cur.At) {
		return true
	}
	return at.Equal(cur.At) && source == "evm-calldata" && cur.Source != "evm-calldata"
}

// Verdict is the result of the anchor verification: the checks and the
// §10.6 fields.
type Verdict struct {
	Checks []report.Check

	// Present is false when the record carries no anchor and no legacy
	// blockchainAnchor.
	Present bool

	// Valid is anchorValid: true, false or nil (null).
	Valid  *bool
	Reason string
	// MerkleProofValid is steps 4 and 5 together; nil when they did not run.
	MerkleProofValid *bool
	// P is SHA-256 of the anchor checkpoint, nil until step 2 holds.
	P                   []byte
	Publication         string
	OriginAuthenticated bool
	Position            *Position
	Network             string
	Finality            *evm.Finality
	Namespace           *string
	ExistedBy           *ExistedBy

	// Parsed bodies, for §10.8.
	LogBody    *checkpoint.Body
	AnchorBody *checkpoint.Body
}

// IsAbstention reports whether a reason is an abstention (§10.1).
func IsAbstention(reason string) bool {
	return strings.HasPrefix(reason, "unsupported_") || strings.HasPrefix(reason, "legacy_")
}

func boolp(b bool) *bool { return &b }

type builder struct {
	checks []report.Check
}

func (b *builder) add(c report.Check) { b.checks = append(b.checks, c) }

func (b *builder) get(id string) *report.Check {
	for i := range b.checks {
		if b.checks[i].ID == id {
			return &b.checks[i]
		}
	}
	return nil
}

// Verify runs the anchor verification. It never panics: an unforeseen failure is
// anchor_verifier_error on the anchor and on every step check.
func Verify(in Input) (v Verdict) {
	defer func() {
		if r := recover(); r != nil {
			v = errorVerdict()
		}
	}()
	return verify(in)
}

func errorVerdict() Verdict {
	v := Verdict{Present: true, Reason: ReasonVerifierError}
	for _, id := range []string{IDAnchor, IDSpec, IDCheckpoint, IDOrigin, IDLeafIndex, IDInclusion, IDAnchorInclusion} {
		v.Checks = append(v.Checks, report.Check{ID: id, Outcome: report.NotChecked, Reason: ReasonVerifierError})
	}
	return v
}

// Steps is every step check, in order (§10.7).
var Steps = []string{IDSpec, IDCheckpoint, IDOrigin, IDLeafIndex, IDInclusion, IDAnchorInclusion}

func verify(in Input) Verdict {
	var b builder
	var v Verdict
	deadline := in.Deadline
	if deadline.IsZero() {
		timeout := in.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		deadline = time.Now().Add(timeout)
	}
	later := Steps[1:]
	blockRest := func(from string, ids []string) {
		for _, id := range ids {
			b.add(report.BlockedBy(id, from))
		}
	}
	finish := func() Verdict {
		v.Checks = append([]report.Check{anchorCheck(&v)}, b.checks...)
		return v
	}

	// Step 1.
	a := in.Anchor
	if a != nil && a.Kind == jsonv.Null {
		a = nil
	}
	if a == nil {
		if in.Legacy {
			v.Present = true
			v.Reason = ReasonLegacy
			b.add(report.Check{ID: IDSpec, Outcome: report.Abstain, Reason: ReasonLegacy})
			blockRest(IDSpec, later)
			return finish()
		}
		// No artifact: the anchor and every step are absent (§10.9).
		v.Reason = ReasonAbsent
		for _, id := range Steps {
			b.add(report.Check{ID: id, Outcome: report.NotChecked, Reason: ReasonAbsent})
		}
		return finish()
	}
	v.Present = true
	tag := func(k, want string) bool {
		t, ok := a.Get(k)
		return ok && t.Kind == jsonv.String && !t.Lone && t.S == want
	}
	if a.Kind != jsonv.Object || !tag("anchorSpec", AnchorSpec) {
		v.Reason = ReasonUnsupportedAnchorSpec
	} else if !tag("merkleSpec", MerkleSpec) {
		v.Reason = ReasonUnsupportedMerkleSpec
	}
	if v.Reason != "" {
		b.add(report.Check{ID: IDSpec, Outcome: report.Abstain, Reason: v.Reason})
		blockRest(IDSpec, later)
		return finish()
	}
	b.add(report.Check{ID: IDSpec, Outcome: report.Correct})

	// Step 2: the shape of §8.1, then both bodies, then both paths.
	fail := func(id, reason string, rest []string) Verdict {
		v.Valid, v.Reason = boolp(false), reason
		b.add(report.Check{ID: id, Outcome: report.Wrong, Reason: reason})
		blockRest(id, rest)
		return finish()
	}
	shapeOK := len(a.O) == len(members)
	for _, m := range members {
		if !a.Has(m) {
			shapeOK = false
		}
	}
	leafV, _ := a.Get("leafIndex")
	aleafV, _ := a.Get("anchorLeafIndex")
	pubsV, _ := a.Get("publications")
	leafIndex, ok1 := leafV.Uint53()
	anchorLeafIndex, ok2 := aleafV.Uint53()
	if !shapeOK || !ok1 || !ok2 || pubsV == nil || pubsV.Kind != jsonv.Array || len(pubsV.A) == 0 {
		return fail(IDCheckpoint, ReasonMalformedAnchor, later[1:])
	}
	lcV, _ := a.Get("logCheckpoint")
	acV, _ := a.Get("anchorCheckpoint")
	logBody, okL := checkpoint.Parse(lcV)
	anchorBody, okA := checkpoint.Parse(acV)
	if okA && checkpoint.IsTestOrigin(anchorBody.Origin) {
		test := "test"
		v.Namespace = &test
	}
	if !okL || !okA {
		return fail(IDCheckpoint, ReasonMalformedCheckpoint, later[1:])
	}
	lpV, _ := a.Get("logPath")
	apV, _ := a.Get("anchorPath")
	logPath, okLP := merkle.ParsePath(lpV)
	anchorPath, okAP := merkle.ParsePath(apV)
	if !okLP || !okAP {
		return fail(IDCheckpoint, ReasonMalformedPath, later[1:])
	}
	v.P = checkpoint.Digest(anchorBody.Raw)
	v.LogBody, v.AnchorBody = logBody, anchorBody
	b.add(report.Check{ID: IDCheckpoint, Outcome: report.Correct})

	// Step 2b.
	bind := checkpoint.Bind(anchorBody.Origin, logBody.Origin, in.ChainID, in.ChainOK)
	if bind.Result != checkpoint.BindOK {
		v.Valid, v.Reason = boolp(false), bind.Result
		c := report.Check{ID: IDOrigin, Outcome: report.Wrong, Reason: bind.Result}
		b.add(c)
		blockRest(IDOrigin, later[2:])
		return finishOrigin(&v, &b, false, finish)
	}
	b.add(report.Check{ID: IDOrigin, Outcome: report.Correct})

	leafIndexChecked := false
	checkedFact := func(b bool) []report.Fact { return []report.Fact{{Name: "leafIndexChecked", Value: report.B(b)}} }

	// Step 3.
	if in.SequenceNumber != nil && in.SequenceNumber.Kind != jsonv.Null {
		s := in.SequenceNumber
		if s.Kind != jsonv.Number || float64(leafIndex) != s.N-1 {
			v.Valid, v.Reason = boolp(false), ReasonLeafIndexMismatch
			b.add(report.Check{ID: IDLeafIndex, Outcome: report.Wrong, Reason: ReasonLeafIndexMismatch, Facts: checkedFact(true)})
			blockRest(IDLeafIndex, later[3:])
			return finishOrigin(&v, &b, bind.ChainChecked, finish)
		}
		leafIndexChecked = true
		b.add(report.Check{ID: IDLeafIndex, Outcome: report.Correct, Facts: checkedFact(true)})
	} else {
		// With no sequence number to compare, the fact is stated as false
		// (§10.7 reports leafIndexChecked on each outcome step 3 reaches).
		b.add(report.Check{ID: IDLeafIndex, Outcome: report.NotChecked, Reason: ReasonNoSequenceNumber, Facts: checkedFact(false)})
	}

	// Step 4.
	if in.Digest == nil {
		v.Reason = "blocked_by:" + in.DigestBlockedBy
		b.add(report.BlockedBy(IDInclusion, in.DigestBlockedBy))
		b.add(report.BlockedBy(IDAnchorInclusion, IDInclusion))
		return finishOrigin(&v, &b, bind.ChainChecked, finish)
	}
	if !merkle.VerifyInclusion(in.Digest, leafIndex, logBody.Size, logPath, logBody.Root) {
		v.Valid, v.Reason, v.MerkleProofValid = boolp(false), ReasonMerkleProofInvalid, boolp(false)
		b.add(report.Check{ID: IDInclusion, Outcome: report.Wrong, Reason: ReasonMerkleProofInvalid})
		b.add(report.BlockedBy(IDAnchorInclusion, IDInclusion))
		return finishOrigin(&v, &b, bind.ChainChecked, finish)
	}
	b.add(report.Check{ID: IDInclusion, Outcome: report.Correct})

	// Step 5.
	if !merkle.VerifyInclusion(checkpoint.Digest(logBody.Raw), anchorLeafIndex, anchorBody.Size, anchorPath, anchorBody.Root) {
		v.Valid, v.Reason, v.MerkleProofValid = boolp(false), ReasonAnchorProofInvalid, boolp(false)
		b.add(report.Check{ID: IDAnchorInclusion, Outcome: report.Wrong, Reason: ReasonAnchorProofInvalid})
		return finishOrigin(&v, &b, bind.ChainChecked, finish)
	}
	b.add(report.Check{ID: IDAnchorInclusion, Outcome: report.Correct})
	v.MerkleProofValid = boolp(true)

	// Step 6.
	type pubResult struct {
		valid  *bool
		reason string
		kind   string
		evm    *evm.Result
		tsa    *rfc3161.Result
	}
	var results []pubResult
	for i, e := range pubsV.A {
		id := fmt.Sprintf("anchor.publication[%d]", i)
		if e == nil || e.Kind != jsonv.Object {
			b.add(report.Check{ID: id, Outcome: report.Wrong, Reason: ReasonMalformedPublication})
			results = append(results, pubResult{valid: boolp(false), reason: ReasonMalformedPublication})
			continue
		}
		k, ok := e.Get("kind")
		kind := ""
		if ok && k.Kind == jsonv.String && !k.Lone {
			kind = k.S
		}
		switch kind {
		case evm.Kind:
			b.add(report.Check{ID: id, Outcome: report.Correct})
			entry := e
			if in.Join != nil {
				entry = in.Join(i, e)
			}
			r := evm.Verify(evm.Input{Index: i, Entry: entry, P: v.P, AnchorOrigin: anchorBody.Origin,
				Manifest: in.Manifest, Sources: in.Sources, Deadline: deadline})
			b.add(r.Tx)
			b.add(r.Canonical)
			results = append(results, pubResult{valid: r.Valid, reason: r.Reason, kind: kind, evm: &r})
		case rfc3161.Kind:
			b.add(report.Check{ID: id, Outcome: report.Correct})
			r := rfc3161.Verify(i, e, v.P, in.Trust)
			b.add(r.Token)
			b.add(r.Trust)
			results = append(results, pubResult{valid: r.Valid, reason: r.Reason, kind: kind, tsa: &r})
		default:
			b.add(report.Check{ID: id, Outcome: report.Abstain, Reason: ReasonUnsupportedKind})
			results = append(results, pubResult{reason: ReasonUnsupportedKind})
		}
	}

	// §10.6.
	anyFalse, anyTrue, anyNotChecked := false, false, false
	firstAbstain := ""
	for _, r := range results {
		switch {
		case r.valid != nil && !*r.valid:
			if !anyFalse {
				v.Reason = r.reason
			}
			anyFalse = true
		case r.valid != nil && *r.valid:
			anyTrue = true
		case IsAbstention(r.reason):
			if firstAbstain == "" {
				firstAbstain = r.reason
			}
		default:
			anyNotChecked = true
		}
	}
	switch {
	case anyFalse:
		v.Valid = boolp(false)
	case anyTrue:
		v.Valid, v.Reason = boolp(true), ""
	case anyNotChecked:
		v.Reason = ReasonPublicationNotChecked
	default:
		v.Reason = firstAbstain
	}
	if anyFalse {
		return finishOrigin(&v, &b, bind.ChainChecked, finish)
	}
	if v.Valid != nil && *v.Valid {
		var finality *evm.Finality
		finalityAgree := true
		var namespace *string
		nsSet, nsAgree := false, true
		for _, r := range results {
			if r.valid == nil || !*r.valid {
				continue
			}
			switch r.kind {
			case evm.Kind:
				v.Publication = "evm-calldata"
				v.OriginAuthenticated = true
				if v.Network == "" {
					v.Network = r.evm.Network
				}
				f := r.evm.Finality
				if !f.Declared {
					finalityAgree = false
				} else if finality == nil {
					finality = &f
				} else if *finality != f {
					finalityAgree = false
				}
				if !nsSet {
					namespace, nsSet = r.evm.Namespace, true
				} else if !samePtr(namespace, r.evm.Namespace) {
					nsAgree = false
				}
				at := boundAt(time.Unix(int64(r.evm.BlockTime), 0))
				if replacesBound(v.ExistedBy, at, "evm-calldata") {
					v.ExistedBy = &ExistedBy{At: at, Source: "evm-calldata"}
				}
			case rfc3161.Kind:
				if v.Publication == "" {
					v.Publication = "rfc3161"
				}
				at := boundAt(r.tsa.GenTime)
				if replacesBound(v.ExistedBy, at, "rfc3161") {
					v.ExistedBy = &ExistedBy{At: at, Source: "rfc3161"}
				}
			}
		}
		if finalityAgree && finality != nil {
			v.Finality = finality
		}
		if v.Namespace == nil && v.OriginAuthenticated && nsAgree {
			v.Namespace = namespace
		}
	}
	v.Position = &Position{
		Origin: logBody.Origin, LeafIndex: leafIndex, TreeSize: logBody.Size,
		AnchorOrigin: anchorBody.Origin, AnchorLeafIndex: anchorLeafIndex, AnchorSize: anchorBody.Size,
		LeafIndexChecked: leafIndexChecked, ChainChecked: bind.ChainChecked, Authenticated: v.OriginAuthenticated,
	}
	return finishOrigin(&v, &b, bind.ChainChecked, finish)
}

func samePtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// finishOrigin sets the facts of anchor.origin when it holds; they are
// known only once the verdict is. No fact of §10.6 is set on a path that
// ends false: they are assigned only once the anchor holds, and
// anchorNamespace is set earlier only to "test". A step that fails ends the
// anchor before step 6, so no publication is reported: step 6 never ran.
func finishOrigin(v *Verdict, b *builder, chainChecked bool, finish func() Verdict) Verdict {
	if c := b.get(IDOrigin); c != nil && c.Outcome == report.Correct {
		c.SetFact("originAuthenticated", report.B(v.OriginAuthenticated))
		c.SetFact("namespace", report.SOrNull(v.Namespace))
		c.SetFact("chainChecked", report.B(chainChecked))
	}
	return finish()
}

// anchorCheck is check "anchor" (§10.7).
func anchorCheck(v *Verdict) report.Check {
	c := report.Check{ID: IDAnchor, Reason: v.Reason}
	switch {
	case v.Valid != nil && *v.Valid:
		c.Outcome, c.Reason = report.Correct, ""
	case v.Valid != nil:
		c.Outcome = report.Wrong
	case IsAbstention(v.Reason):
		c.Outcome = report.Abstain
	default:
		c.Outcome = report.NotChecked
	}
	return c
}
