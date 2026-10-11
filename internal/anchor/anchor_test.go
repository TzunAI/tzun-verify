// SPDX-License-Identifier: BSD-3-Clause-Clear

package anchor

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"

	"github.com/TzunAI/tzun-verify/internal/checkpoint"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
	"github.com/TzunAI/tzun-verify/internal/rfc3161"
	"github.com/TzunAI/tzun-verify/internal/testpki"
)

const (
	prefix    = "local.invalid/0123456789abcdef0123456789abcdef"
	logOrigin = prefix + "/evidence/64656661756c74" // chain "default"
	ancOrigin = prefix + "/anchors"
)

func digestOf(i int) []byte {
	s := sha256.Sum256([]byte(fmt.Sprintf("record %d", i)))
	return s[:]
}

// synth is a synthetic domain: one evidence log and one anchor log.
type synth struct {
	logTree    *testonly.Tree
	anchorTree *testonly.Tree
}

func newSynth() *synth {
	return &synth{logTree: testonly.New(rfc6962.DefaultHasher), anchorTree: testonly.New(rfc6962.DefaultHasher)}
}

func body(origin string, size uint64, root []byte) string {
	return fmt.Sprintf("%s\n%d\n%s\n", origin, size, base64.StdEncoding.EncodeToString(root))
}

func hexPath(p [][]byte) *jsonv.Value {
	a := report.Arr()
	for _, h := range p {
		a.A = append(a.A, report.S(fmt.Sprintf("%x", h)))
	}
	return a
}

// epoch appends n records to the log, cuts its checkpoint, appends that
// checkpoint to the anchor log (after pad other leaves) and returns the
// anchor checkpoint body, the log body and the paths for record index.
type epochOut struct {
	logBody, anchorBody string
	logPath, anchorPath *jsonv.Value
	anchorLeafIndex     uint64
	p                   []byte
}

func (s *synth) epoch(t *testing.T, records int, recordIndex uint64) epochOut {
	t.Helper()
	for i := 0; i < records; i++ {
		s.logTree.AppendData(digestOf(int(s.logTree.Size())))
	}
	size := s.logTree.Size()
	lb := body(logOrigin, size, s.logTree.Hash())
	lp, err := s.logTree.InclusionProof(recordIndex, size)
	if err != nil {
		t.Fatal(err)
	}
	ali := s.anchorTree.Size()
	s.anchorTree.AppendData(checkpoint.Digest(lb))
	asize := s.anchorTree.Size()
	ab := body(ancOrigin, asize, s.anchorTree.Hash())
	ap, err := s.anchorTree.InclusionProof(ali, asize)
	if err != nil {
		t.Fatal(err)
	}
	return epochOut{logBody: lb, anchorBody: ab, logPath: hexPath(lp), anchorPath: hexPath(ap), anchorLeafIndex: ali, p: checkpoint.Digest(ab)}
}

func artifact(e epochOut, leafIndex uint64, pubs ...*jsonv.Value) *jsonv.Value {
	return report.Obj(
		"anchorSpec", report.S(AnchorSpec), "merkleSpec", report.S(MerkleSpec),
		"leafIndex", report.N(leafIndex), "logCheckpoint", report.S(e.logBody), "logPath", e.logPath,
		"anchorLeafIndex", report.N(e.anchorLeafIndex), "anchorCheckpoint", report.S(e.anchorBody), "anchorPath", e.anchorPath,
		"publications", report.Arr(pubs...),
	)
}

type pki struct {
	trust   rfc3161.Trust
	signerA *testpki.Cert
	signerB *testpki.Cert
	chain   []*x509.Certificate
}

func newPKI() *pki {
	root := testpki.Root("Root")
	inter := testpki.Intermediate("TSA CA", root, true)
	return &pki{
		trust:   rfc3161.Trust{Roots: []*x509.Certificate{root.Cert}},
		signerA: testpki.TSASigner("Authority A", inter),
		signerB: testpki.TSASigner("Authority B", inter),
		chain:   []*x509.Certificate{inter.Cert},
	}
}

func (k *pki) token(p []byte, signer *testpki.Cert, gen time.Time) *jsonv.Value {
	return report.Obj("kind", report.S(rfc3161.Kind), "token", report.S(testpki.Token(p, signer, k.chain, gen, true)))
}

func find(checks []report.Check, id string) *report.Check {
	for i := range checks {
		if checks[i].ID == id {
			return &checks[i]
		}
	}
	return nil
}

func expectCheck(t *testing.T, v Verdict, id string, o report.Outcome, reason string) {
	t.Helper()
	c := find(v.Checks, id)
	if c == nil {
		t.Errorf("no check %s", id)
		return
	}
	if c.Outcome != o || c.Reason != reason {
		t.Errorf("%s: %s %q, want %s %q", id, c.Outcome, c.Reason, o, reason)
	}
}

func TestRFC3161OnlyAnchor(t *testing.T) {
	k := newPKI()
	s := newSynth()
	e := s.epoch(t, 5, 3)
	gen := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	seq := report.N(4)
	chain := "default"
	in := Input{Anchor: artifact(e, 3, k.token(e.p, k.signerA, gen)), Digest: digestOf(3),
		SequenceNumber: seq, ChainID: &chain, ChainOK: true, Trust: k.trust}
	v := Verify(in)
	if v.Valid == nil || !*v.Valid || v.Publication != "rfc3161" || v.OriginAuthenticated || v.Namespace != nil ||
		v.ExistedBy == nil || v.ExistedBy.Source != "rfc3161" || !v.ExistedBy.At.Equal(gen) || v.Network != "" || v.Finality != nil {
		t.Fatalf("RFC 3161-only anchor: %+v", v)
	}
	if v.Position == nil || v.Position.Authenticated || !v.Position.LeafIndexChecked || !v.Position.ChainChecked {
		t.Errorf("position %+v", v.Position)
	}
	expectCheck(t, v, IDAnchor, report.Correct, "")
	expectCheck(t, v, "anchor.tsa.trust[0]", report.Correct, "")
	origin := find(v.Checks, IDOrigin)
	if f, _ := origin.Fact("originAuthenticated"); f == nil || f.B {
		t.Errorf("originAuthenticated fact")
	}

	// Two authorities: told apart by index; the earliest genTime wins.
	earlier := gen.Add(-time.Minute)
	in.Anchor = artifact(e, 3, k.token(e.p, k.signerA, gen), k.token(e.p, k.signerB, earlier))
	v = Verify(in)
	expectCheck(t, v, "anchor.tsa.token[0]", report.Correct, "")
	expectCheck(t, v, "anchor.tsa.token[1]", report.Correct, "")
	if v.ExistedBy == nil || !v.ExistedBy.At.Equal(earlier) {
		t.Errorf("existedBy %+v", v.ExistedBy)
	}

	// [null, a true token]: a lying element makes the anchor false.
	in.Anchor = artifact(e, 3, report.Null(), k.token(e.p, k.signerA, gen))
	v = Verify(in)
	if v.Valid == nil || *v.Valid || v.Reason != ReasonMalformedPublication || v.Publication != "" || v.ExistedBy != nil || v.Position != nil {
		t.Errorf("[null, token]: %+v", v)
	}
	expectCheck(t, v, "anchor.publication[0]", report.Wrong, ReasonMalformedPublication)
	expectCheck(t, v, "anchor.tsa.token[1]", report.Correct, "")

	// [{"token": …}, a true token]: the unknown kind abstains; the anchor
	// holds on the other.
	in.Anchor = artifact(e, 3, report.Obj("token", report.S("AA==")), k.token(e.p, k.signerA, gen))
	v = Verify(in)
	if v.Valid == nil || !*v.Valid {
		t.Errorf("[{token}, token]: %+v", v)
	}
	expectCheck(t, v, "anchor.publication[0]", report.Abstain, ReasonUnsupportedKind)
	if find(v.Checks, "anchor.tsa.token[0]") != nil {
		t.Errorf("no check is reported for an element whose dispatch did not hold")
	}

	// A token over another P: false even though it chains to a trusted root.
	other := sha256.Sum256([]byte("another P"))
	in.Anchor = artifact(e, 3, k.token(other[:], k.signerA, gen))
	v = Verify(in)
	if v.Valid == nil || *v.Valid || v.Reason != "imprint_mismatch" {
		t.Errorf("imprint mismatch: %+v", v)
	}

	// A token under no supplied root: null, publication_not_checked.
	in.Anchor = artifact(e, 3, k.token(e.p, k.signerA, gen))
	in.Trust = rfc3161.Trust{}
	v = Verify(in)
	if v.Valid != nil || v.Reason != ReasonPublicationNotChecked || v.Position == nil {
		t.Errorf("untrusted root: %+v", v)
	}
	expectCheck(t, v, "anchor.tsa.trust[0]", report.NotChecked, "no_matching_trust_anchor")
	expectCheck(t, v, IDAnchor, report.NotChecked, ReasonPublicationNotChecked)
}

func TestStepOrderAndBlocking(t *testing.T) {
	k := newPKI()
	s := newSynth()
	e := s.epoch(t, 4, 1)
	gen := time.Now().Add(-time.Hour)
	art := artifact(e, 1, k.token(e.p, k.signerA, gen))

	// Absent, and legacy. A member whose value is null is an empty slot:
	// absent.
	for _, in := range []Input{{}, {Anchor: report.Null()}} {
		v := Verify(in)
		if len(v.Checks) != 1+len(Steps) || v.Present {
			t.Errorf("absent: the anchor and every step, got %+v", v)
		}
		for _, c := range v.Checks {
			if c.Outcome != report.NotChecked || c.Reason != ReasonAbsent {
				t.Errorf("absent: %+v", c)
			}
		}
	}
	v := Verify(Input{Legacy: true})
	expectCheck(t, v, IDAnchor, report.Abstain, ReasonLegacy)
	expectCheck(t, v, IDInclusion, report.NotChecked, "blocked_by:"+IDSpec)
	if !v.Present {
		t.Errorf("legacy is present")
	}

	// Step 3 not supplied blocks nothing.
	v = Verify(Input{Anchor: art, Digest: digestOf(1), Trust: k.trust})
	expectCheck(t, v, IDLeafIndex, report.NotChecked, ReasonNoSequenceNumber)
	expectCheck(t, v, IDInclusion, report.Correct, "")
	if v.Valid == nil || !*v.Valid || v.Position.LeafIndexChecked {
		t.Errorf("no sequence number: %+v", v)
	}
	if c := find(v.Checks, IDLeafIndex); len(c.Facts) != 1 || c.Facts[0].Value.B {
		t.Errorf("no sequence number states leafIndexChecked false: %+v", c)
	}

	// Step 3 failing blocks everything after it.
	v = Verify(Input{Anchor: art, Digest: digestOf(1), SequenceNumber: report.N(5), Trust: k.trust})
	expectCheck(t, v, IDLeafIndex, report.Wrong, ReasonLeafIndexMismatch)
	expectCheck(t, v, IDInclusion, report.NotChecked, "blocked_by:"+IDLeafIndex)
	if find(v.Checks, "anchor.publication[0]") != nil || find(v.Checks, "anchor.tsa.token[0]") != nil {
		t.Errorf("step 6 never ran, so no publication is reported")
	}
	if c := find(v.Checks, IDLeafIndex); len(c.Facts) != 1 || c.Facts[0].Name != "leafIndexChecked" || !c.Facts[0].Value.B {
		t.Errorf("a failing step 3 states leafIndexChecked true: %+v", c)
	}
	if c := find(v.Checks, IDOrigin); c.Outcome != report.Correct || len(c.Facts) != 3 {
		t.Errorf("origin facts: %+v", c)
	}

	// Step 4 with a digest that could not be computed.
	v = Verify(Input{Anchor: art, DigestBlockedBy: "record.digest", Trust: k.trust})
	expectCheck(t, v, IDInclusion, report.NotChecked, "blocked_by:record.digest")
	expectCheck(t, v, IDAnchor, report.NotChecked, "blocked_by:record.digest")

	// An unforeseen failure is anchor_verifier_error on every step check.
	v = Verify(Input{Anchor: art, Digest: digestOf(1), Join: func(int, *jsonv.Value) *jsonv.Value { panic("boom") },
		Trust: k.trust})
	// The join only runs for EVM entries; this artifact has none, so it holds.
	if v.Valid == nil || !*v.Valid {
		t.Errorf("join not called for rfc3161: %+v", v)
	}
	evmArt := artifact(e, 1, report.Obj("kind", report.S("evm-calldata/1")))
	v = Verify(Input{Anchor: evmArt, Digest: digestOf(1), Join: func(int, *jsonv.Value) *jsonv.Value { panic("boom") }})
	expectCheck(t, v, IDAnchor, report.NotChecked, ReasonVerifierError)
	expectCheck(t, v, IDInclusion, report.NotChecked, ReasonVerifierError)
}

func TestConsistency(t *testing.T) {
	s := newSynth()
	e1 := s.epoch(t, 3, 1)
	e2 := s.epoch(t, 4, 1)
	a, _ := checkpoint.ParseString(e1.logBody)
	b, _ := checkpoint.ParseString(e2.logBody)
	id := ConsistencyID(logOrigin)
	proof, err := s.logTree.ConsistencyProof(3, 7)
	if err != nil {
		t.Fatal(err)
	}
	c := Consistency(id, a, b, hexPath(proof))
	if c.Outcome != report.Correct || c.ID != id {
		t.Errorf("consistency: %+v", c)
	}
	if from, _ := c.Fact("fromSize"); from == nil || from.N != 3 {
		t.Errorf("fromSize: %+v", c)
	}
	// Either order: sizes and roots come from the bodies.
	if c := Consistency(id, b, a, hexPath(proof)); c.Outcome != report.Correct {
		t.Errorf("reversed: %+v", c)
	}
	bad := append([][]byte{}, proof...)
	bad[0] = digestOf(99)
	if c := Consistency(id, a, b, hexPath(bad)); c.Outcome != report.Wrong || c.Reason != ReasonInconsistent {
		t.Errorf("bad proof: %+v", c)
	}
	if c := Consistency(id, a, b, report.Null()); c.Outcome != report.Wrong || c.Reason != ReasonInconsistent {
		t.Errorf("unreadable proof: %+v", c)
	}
	if c := Consistency(id, a, b, nil); c.Outcome != report.NotChecked || c.Reason != ReasonNoConsistency {
		t.Errorf("no proof: %+v", c)
	}
	// The same size with another root: a split view.
	fork := newSynth()
	for i := 0; i < 3; i++ {
		fork.logTree.AppendData(digestOf(100 + i))
	}
	f, _ := checkpoint.ParseString(body(logOrigin, 3, fork.logTree.Hash()))
	if c := Consistency(id, a, f, nil); c.Outcome != report.Wrong || c.Reason != ReasonSplitView {
		t.Errorf("split view: %+v", c)
	}
	if c := Consistency(id, a, a, nil); c.Outcome != report.Correct {
		t.Errorf("same body: %+v", c)
	}
}
