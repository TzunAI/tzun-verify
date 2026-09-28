package bundle

import (
	"sort"
	"strings"

	"github.com/TzunAI/tzun-verify/internal/anchor"
	"github.com/TzunAI/tzun-verify/internal/checkpoint"
	"github.com/TzunAI/tzun-verify/internal/evm"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// anchorRows are the record's own anchor (Anchor §10.3 to §10.7),
// then anchor.newer and anchor.consistency[<origin>] (Anchor §10.8).
func (v *verification) anchorRows() {
	art := member(v.nr, "anchor")
	legacy := member(v.nr, "blockchainAnchor") != nil
	switch {
	case art == nil && !legacy:
		// No artifact: every row is absent, whatever the digest
		// (Anchor §10.9).
		v.add(anchor.Verify(anchor.Input{}).Checks...)
	case v.digest == nil:
		v.add(report.BlockedBy(anchor.IDAnchor, IDDigest))
		for _, id := range anchor.Steps {
			v.add(report.BlockedBy(id, IDDigest))
		}
	default:
		verdict := anchor.Verify(v.anchorInput(art, legacy))
		v.res.Anchor = &verdict
		v.add(verdict.Checks...)
	}
	v.newerRows()
}

// chainInput is the bundle's chain id for step 2b: nil when the bundle
// names none, and ok false when it holds a lone surrogate.
func (v *verification) chainInput() (*string, bool) {
	c := member(member(v.root, "chain"), "chainId")
	if c == nil || c.Kind != jsonv.String {
		return nil, true
	}
	s := c.S
	return &s, !c.Lone
}

func (v *verification) anchorInput(art *jsonv.Value, legacy bool) anchor.Input {
	chain, chainOK := v.chainInput()
	return anchor.Input{
		Anchor: art, Legacy: legacy, Digest: v.digest,
		SequenceNumber: member(v.payload, "sequenceNumber"),
		ChainID:        chain, ChainOK: chainOK,
		Manifest: v.opts.Manifest, Sources: v.opts.Sources, Trust: v.opts.Trust,
		Deadline: v.deadline,
		Join:     v.joinFor(),
	}
}

// logEntry is one origin of the anchoring slot.
type logEntry struct {
	origin      string
	parsed      *checkpoint.Origin // nil when the origin is not a Tzun origin
	checkpoints []*jsonv.Value
	consistency []*jsonv.Value
}

func (l logEntry) isAnchorLog() bool {
	return l.parsed != nil && l.parsed.Kind == checkpoint.KindAnchors
}

// logs lists the anchoring slot's origins in byte order.
func (v *verification) logs() []logEntry {
	var out []logEntry
	for _, m := range sortedMembers(v.anchoring) {
		e := logEntry{origin: m.Key}
		e.parsed, _ = checkpoint.ParseOrigin(m.Key)
		if cps, ok := m.Value.Get("checkpoints"); ok {
			e.checkpoints = cps.A
		}
		if cons := member(m.Value, "consistency"); cons != nil {
			e.consistency = cons.A
		}
		out = append(out, e)
	}
	return out
}

func bodyOf(cp *jsonv.Value) string {
	s, _ := member(cp, "body").Str()
	return s
}

// carriedPublications returns every publication entry the bundle carries
// on its anchor-log checkpoints, in origin order and then checkpoint order.
func (v *verification) carriedPublications() []*jsonv.Value {
	var out []*jsonv.Value
	for _, l := range v.logs() {
		if !l.isAnchorLog() {
			continue
		}
		for _, cp := range l.checkpoints {
			if pubs := member(cp, "publications"); pubs != nil && pubs.Kind == jsonv.Array {
				out = append(out, pubs.A...)
			}
		}
	}
	return out
}

// heavyMembers are what an export bundle adds to an envelope's
// evm-calldata/1 entry (Anchor §8.2).
var heavyMembers = []string{"rawTransaction", "blockHeader", "txIndex", "txProof"}

func isHeavy(name string) bool {
	for _, h := range heavyMembers {
		if h == name {
			return true
		}
	}
	return false
}

// joinFor pairs each evm-calldata/1 entry of the artifact with the heavy
// material of the same transaction, from the publications of any anchor
// checkpoint the bundle carries (Bundle §7.4). A bundle entry
// pairs when the keccak256 of its rawTransaction equals the envelope
// entry's transactionId and no two stated block hashes differ, so two
// transactions of one block are never confused. The envelope entry keeps
// its own members and gains only the heavy material; an entry nothing
// pairs with is verified as written.
func (v *verification) joinFor() func(int, *jsonv.Value) *jsonv.Value {
	bundled := v.carriedPublications()
	return func(_ int, entry *jsonv.Value) *jsonv.Value {
		id, ok := member(entry, "transactionId").Str()
		if !ok {
			return entry
		}
		for _, h := range bundled {
			if k, _ := member(h, "kind").Str(); k != evm.Kind {
				continue
			}
			raw, _ := member(h, "rawTransaction").Str()
			if tx := evm.TxID(raw); tx == "" || tx != strings.ToLower(id) {
				continue
			}
			eh, okE := member(entry, "blockHash").Str()
			hh, okH := member(h, "blockHash").Str()
			if okE && okH && !strings.EqualFold(eh, hh) {
				continue
			}
			// A member whose value is null reads as absent (Bundle §3.2), on
			// either side: the envelope's null gives way to the bundle's value,
			// and a null in the bundle adds nothing.
			var kept []jsonv.Member
			for _, m := range entry.O {
				if m.Value.Kind == jsonv.Null && isHeavy(m.Key) && member(h, m.Key) != nil {
					continue
				}
				kept = append(kept, m)
			}
			joined := &jsonv.Value{Kind: jsonv.Object, O: kept}
			for _, name := range heavyMembers {
				if hv := member(h, name); hv != nil && member(joined, name) == nil {
					joined.O = append(joined.O, jsonv.Member{Key: name, Value: hv})
				}
			}
			return joined
		}
		return entry
	}
}

// Members an evidence-log checkpoint carries when it is not the one the
// record's artifact names: the record's path in it, and its own place in
// an anchor checkpoint of the bundle (Bundle §7.2, §7.5).
var newerMembers = []string{"logPath", "anchorLeafIndex", "anchorSize", "anchorPath"}

// carriesNewerAnchor reports whether a checkpoint entry carries any of
// newerMembers; a member whose value is null is not carried
// (Bundle §3.2).
func carriesNewerAnchor(cp *jsonv.Value) bool {
	for _, name := range newerMembers {
		if member(cp, name) != nil {
			return true
		}
	}
	return false
}

// newerTarget finds the evidence-log checkpoint whose anchor anchor.newer
// verifies: the largest one that carries the composed members, preferring
// the log the record's artifact names (Bundle §7.5). ok is
// false when no checkpoint carries them, and there is then no anchor.newer
// row.
func (v *verification) newerTarget() (log logEntry, cp *jsonv.Value, ok bool) {
	var artLog string
	if b, okB := checkpoint.Parse(member(member(v.nr, "anchor"), "logCheckpoint")); okB {
		artLog = b.Origin
	}
	var bestSize uint64
	pick := func(onlyOrigin string) {
		for _, l := range v.logs() {
			if l.isAnchorLog() || (onlyOrigin != "" && l.origin != onlyOrigin) {
				continue
			}
			for _, c := range l.checkpoints {
				if !carriesNewerAnchor(c) {
					continue
				}
				size := uint64(0)
				if b, okB := checkpoint.ParseString(bodyOf(c)); okB {
					size = b.Size
				}
				if cp == nil || size > bestSize {
					log, cp, bestSize = l, c, size
				}
			}
		}
	}
	if artLog != "" {
		pick(artLog)
	}
	if cp == nil {
		pick("")
	}
	return log, cp, cp != nil
}

// composeNewer builds the anchor of the newer checkpoint as a tzun-anchor/1
// artifact: its body in place of logCheckpoint, the record's path in it,
// and the anchor checkpoint of the stated size with its place in it and its
// publications. A member the bundle does not carry is left out, and the
// artifact then fails step 2's shape (malformed_anchor).
func (v *verification) composeNewer(log logEntry, cp *jsonv.Value) *jsonv.Value {
	art := &jsonv.Value{Kind: jsonv.Object}
	put := func(k string, x *jsonv.Value) {
		if x != nil {
			art.O = append(art.O, jsonv.Member{Key: k, Value: x})
		}
	}
	put("anchorSpec", report.S(anchor.AnchorSpec))
	put("merkleSpec", report.S(anchor.MerkleSpec))
	if seq, ok := member(v.payload, "sequenceNumber").Uint53(); ok && seq >= 1 {
		put("leafIndex", report.N(seq-1))
	}
	put("logCheckpoint", member(cp, "body"))
	put("logPath", member(cp, "logPath"))
	put("anchorLeafIndex", member(cp, "anchorLeafIndex"))
	size, okSize := member(cp, "anchorSize").Uint53()
	if okSize {
		for _, l := range v.logs() {
			if !l.isAnchorLog() || (log.parsed != nil && l.parsed.Prefix != log.parsed.Prefix) {
				continue
			}
			for _, a := range l.checkpoints {
				if b, ok := checkpoint.ParseString(bodyOf(a)); ok && b.Size == size {
					put("anchorCheckpoint", member(a, "body"))
					put("anchorPath", member(cp, "anchorPath"))
					put("publications", member(a, "publications"))
					return art
				}
			}
		}
	}
	return art
}

// newerRows are anchor.newer and the consistency rows of Anchor §10.8.
func (v *verification) newerRows() {
	log, cp, ok := v.newerTarget()
	if !ok {
		v.add(v.consistencyRows(nil)...)
		return
	}
	var newer report.Check
	switch {
	case v.digest == nil:
		newer = report.BlockedBy(anchor.IDNewer, IDDigest)
	default:
		chain, chainOK := v.chainInput()
		verdict := anchor.Verify(anchor.Input{
			Anchor: v.composeNewer(log, cp), Digest: v.digest,
			SequenceNumber: member(v.payload, "sequenceNumber"),
			ChainID:        chain, ChainOK: chainOK,
			Manifest: v.opts.Manifest, Sources: v.opts.Sources, Trust: v.opts.Trust,
			Deadline: v.deadline,
		})
		v.res.Newer = &verdict
		newer = verdict.Checks[0]
		newer.ID = anchor.IDNewer
		if newer.Outcome == report.Correct && verdict.Position != nil {
			newer.Facts = []report.Fact{
				{Name: "treeSize", Value: report.N(verdict.Position.TreeSize)},
				{Name: "anchorSize", Value: report.N(verdict.Position.AnchorSize)},
			}
		}
	}
	v.add(newer)
	v.add(v.consistencyRows(&newer)...)
}

// consistencyRows are the rows of Anchor §10.8, read from the
// bundle as Bundle §7.6 states: one per origin whose bodies the
// bundle carries or an authenticated anchor names, in origin order. Every
// carried body must be authenticated first: the record's own through
// anchor, any other through anchor.newer. A carried body neither
// authenticates, with one checkpoint per log as with two, leaves the row
// blocked: by anchor until the record's own anchor holds, then by
// anchor.newer. An origin with fewer than two authenticated bodies and none
// unauthenticated has nothing to compare and no row.
func (v *verification) consistencyRows(newer *report.Check) []report.Check {
	type origin struct {
		carried []*checkpoint.Body
		// authentic are the origin's authenticated bodies, each once.
		authentic []*checkpoint.Body
		log       logEntry
	}
	origins := map[string]*origin{}
	at := func(name string) *origin {
		if origins[name] == nil {
			origins[name] = &origin{}
		}
		return origins[name]
	}
	authentic := map[string]bool{}
	authenticate := func(bodies ...*checkpoint.Body) {
		for _, b := range bodies {
			if b != nil && !authentic[b.Raw] {
				authentic[b.Raw] = true
				o := at(b.Origin)
				o.authentic = append(o.authentic, b)
			}
		}
	}
	anchorOK := false
	if a := v.res.Anchor; a != nil && a.Valid != nil && *a.Valid {
		anchorOK = true
		authenticate(a.LogBody, a.AnchorBody)
	}
	if n := v.res.Newer; newer != nil && newer.Outcome == report.Correct && n != nil {
		authenticate(n.LogBody, n.AnchorBody)
	}
	for _, l := range v.logs() {
		o := at(l.origin)
		o.log = l
		for _, cp := range l.checkpoints {
			if b, ok := checkpoint.ParseString(bodyOf(cp)); ok {
				o.carried = append(o.carried, b)
			}
		}
	}
	names := make([]string, 0, len(origins))
	for name := range origins {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []report.Check
	for _, name := range names {
		o := origins[name]
		id := anchor.ConsistencyID(name)
		unauthenticated := false
		for _, b := range o.carried {
			if !authentic[b.Raw] {
				unauthenticated = true
			}
		}
		switch {
		case unauthenticated && !anchorOK:
			out = append(out, report.BlockedBy(id, anchor.IDAnchor))
		case unauthenticated:
			out = append(out, report.BlockedBy(id, anchor.IDNewer))
		case len(o.authentic) >= 2:
			a, b := o.authentic[0], o.authentic[1]
			out = append(out, anchor.Consistency(id, a, b, proofBetween(o.log, a.Size, b.Size)))
		}
	}
	return out
}

// proofBetween returns the path of the first consistency entry of a log
// whose fromSize and toSize are the two sizes, smaller first, and nil when
// the log carries no such entry (Bundle §7.6). An entry whose
// path is missing or null gives a null proof, which is not an array of
// hashes and so fails Anchor §10.8.
func proofBetween(l logEntry, x, y uint64) *jsonv.Value {
	lo, hi := x, y
	if lo > hi {
		lo, hi = hi, lo
	}
	for _, c := range l.consistency {
		from, ok1 := member(c, "fromSize").Uint53()
		to, ok2 := member(c, "toSize").Uint53()
		if ok1 && ok2 && from == lo && to == hi {
			if p := member(c, "path"); p != nil {
				return p
			}
			return &jsonv.Value{Kind: jsonv.Null}
		}
	}
	return nil
}
