// SPDX-License-Identifier: BSD-3-Clause-Clear

package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"

	"github.com/TzunAI/tzun-verify/internal/anchor"
	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/checkpoint"
	"github.com/TzunAI/tzun-verify/internal/evm"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/merkle"
	"github.com/TzunAI/tzun-verify/internal/report"
)

var vectorDir = filepath.Join("..", "..", "testdata", "vectors")

// knownFiles is every vector file this runner checks. A file in
// testdata/vectors that is not listed fails the run, so a new vector file
// lands with a decision about how it is checked.
var knownFiles = map[string]bool{
	"SOURCE.json":                      true,
	"merkle-rfc6962-vectors.json":      true,
	"merkle-consistency-vectors.json":  true,
	"checkpoint-vectors.json":          true,
	"evidence-log-origin-vectors.json": true,
	"anchor-e2e-vectors.json":          true,
	"v1.0-canonical-vectors.json":      true,
	"v1.0-integrity-vectors.json":      true,
	"signoff-expectation-vectors.json": true,
	"bundle-b1":                        true,
	"v1.0-worked-example-vectors.json": true,
	"decider-vectors.json":             true,
	"contributions-vectors.json":       true,
	"links-vectors.json":               true,
	"mandate-vectors.json":             true,
	"agent-descriptor-vectors.json":    true,
	"store-generation-vectors.json":    true,
	"cross-sdk-parity-vectors.json":    true,
	"evm-anchor-vectors.json":          true,
}

func load(t *testing.T, name string) *jsonv.Value {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	v, err := jsonv.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return v
}

func get(t *testing.T, v *jsonv.Value, path ...string) *jsonv.Value {
	t.Helper()
	cur := v
	for _, p := range path {
		n, ok := cur.Get(p)
		if !ok {
			t.Fatalf("missing %s", strings.Join(path, "."))
		}
		cur = n
	}
	return cur
}

func str(t *testing.T, v *jsonv.Value, path ...string) string {
	t.Helper()
	s, ok := get(t, v, path...).Str()
	if !ok {
		t.Fatalf("%s is not a string", strings.Join(path, "."))
	}
	return s
}

func u64(t *testing.T, v *jsonv.Value, path ...string) uint64 {
	t.Helper()
	n, ok := get(t, v, path...).Uint53()
	if !ok {
		t.Fatalf("%s is not an integer", strings.Join(path, "."))
	}
	return n
}

func hexb(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("bad hex %q", s)
	}
	return b
}

func flip(b []byte, i int) []byte {
	c := append([]byte{}, b...)
	c[i] ^= 0x01
	return c
}

// TestSourcePins checks that every vector file, and every file of the
// bundle corpus, is the one SOURCE.json records, and that no unknown file
// sits beside them.
func TestSourcePins(t *testing.T) {
	src := load(t, "SOURCE.json")
	pin := func(rel, want string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(vectorDir, rel))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != want {
			t.Errorf("%s: sha256 %x, SOURCE.json says %s", rel, sum, want)
		}
	}
	pinned := map[string]bool{}
	for _, m := range get(t, src, "entries").O {
		if m.Value.Kind == jsonv.Null {
			continue
		}
		if files, ok := m.Value.Get("files"); ok {
			for _, f := range files.O {
				rel := filepath.Join(m.Key, f.Key)
				pin(rel, str(t, f.Value, "sha256"))
				pinned[rel] = true
			}
			continue
		}
		pin(m.Key, str(t, m.Value, "sha256"))
	}
	entries, err := os.ReadDir(vectorDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !knownFiles[e.Name()] {
			t.Errorf("unknown vector file %s: decide how the runner checks it, then list it", e.Name())
		}
	}
	// Every file of the bundle corpus is pinned.
	_ = filepath.WalkDir(filepath.Join(vectorDir, "bundle-b1"), func(path string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(vectorDir, path)
		if !pinned[rel] {
			t.Errorf("%s is not pinned in SOURCE.json", rel)
		}
		return nil
	})
}

// merkle-rfc6962-vectors.json, Tree §9 items 1 to 6.
func TestMerkleRFC6962Vectors(t *testing.T) {
	d := load(t, "merkle-rfc6962-vectors.json")
	if got := hex.EncodeToString(merkle.Root(nil)); got != str(t, d, "emptyTreeRoot", "root") {
		t.Errorf("MTH({}) = %s", got)
	}
	trees := get(t, d, "trees")
	nproofs := 0
	for _, tr := range trees.A {
		size := u64(t, tr, "treeSize")
		var leaves [][]byte
		for _, l := range get(t, tr, "leafDigests").A {
			leaves = append(leaves, hexb(t, l.S))
		}
		if uint64(len(leaves)) != size {
			t.Fatalf("tree %d: %d leaves", size, len(leaves))
		}
		root := hexb(t, str(t, tr, "root"))
		if !bytes.Equal(merkle.Root(leaves), root) {
			t.Errorf("tree %d: root mismatch", size)
		}
		for i, lh := range get(t, tr, "leafHashes").A {
			if !bytes.Equal(merkle.LeafHash(leaves[i]), hexb(t, lh.S)) {
				t.Errorf("tree %d: leaf hash %d", size, i)
			}
		}
		ref := testonly.New(rfc6962.DefaultHasher)
		for _, l := range leaves {
			ref.AppendData(l)
		}
		for _, p := range get(t, tr, "proofs").A {
			idx := u64(t, p, "leafIndex")
			leaf := hexb(t, str(t, p, "leafDigest"))
			path, ok := merkle.ParsePath(get(t, p, "auditPath"))
			if !ok {
				t.Fatalf("tree %d leaf %d: path does not parse", size, idx)
			}
			gen, err := ref.InclusionProof(idx, size)
			if err != nil || len(gen) != len(path) {
				t.Errorf("tree %d leaf %d: generated PATH differs", size, idx)
			}
			for k := range gen {
				if k < len(path) && !bytes.Equal(gen[k], path[k]) {
					t.Errorf("tree %d leaf %d: PATH element %d differs", size, idx, k)
				}
			}
			if !merkle.VerifyInclusion(leaf, idx, size, path, root) {
				t.Errorf("tree %d leaf %d: honest proof refused", size, idx)
			}
			for b := 0; b < 32; b++ {
				if merkle.VerifyInclusion(flip(leaf, b), idx, size, path, root) ||
					merkle.VerifyInclusion(leaf, idx, size, path, flip(root, b)) {
					t.Errorf("tree %d leaf %d: tampered leaf or root accepted (byte %d)", size, idx, b)
				}
				for k := range path {
					tp := append([][]byte{}, path...)
					tp[k] = flip(path[k], b)
					if merkle.VerifyInclusion(leaf, idx, size, tp, root) {
						t.Errorf("tree %d leaf %d: tampered path element %d accepted", size, idx, k)
					}
				}
			}
			nproofs++
		}
	}
	dv := get(t, d, "distinctnessVectors").A[0]
	var la, lb [][]byte
	for _, l := range get(t, dv, "a", "leafDigests").A {
		la = append(la, hexb(t, l.S))
	}
	for _, l := range get(t, dv, "b", "leafDigests").A {
		lb = append(lb, hexb(t, l.S))
	}
	ra, rb := merkle.Root(la), merkle.Root(lb)
	if bytes.Equal(ra, rb) || hex.EncodeToString(ra) != str(t, dv, "a", "root") || hex.EncodeToString(rb) != str(t, dv, "b", "root") {
		t.Errorf("distinctness vectors do not reproduce")
	}
	t.Logf("%d trees, %d inclusion proofs", len(trees.A), nproofs)
}

func consistencyInput(t *testing.T, e *jsonv.Value) (uint64, uint64, [][]byte, []byte, []byte, bool) {
	t.Helper()
	f, ok1 := get(t, e, "first").Uint53()
	s, ok2 := get(t, e, "second").Uint53()
	fr, ok3 := merkle.ParseHash(get(t, e, "firstRoot"))
	sr, ok4 := merkle.ParseHash(get(t, e, "secondRoot"))
	p, ok5 := merkle.ParsePath(get(t, e, "proof"))
	return f, s, p, fr, sr, ok1 && ok2 && ok3 && ok4 && ok5
}

// merkle-consistency-vectors.json, Tree §9 items 7 to 9.
func TestMerkleConsistencyVectors(t *testing.T) {
	d := load(t, "merkle-consistency-vectors.json")
	var leaves [][]byte
	for _, l := range get(t, d, "leafDigests").A {
		leaves = append(leaves, hexb(t, l.S))
	}
	ref := testonly.New(rfc6962.DefaultHasher)
	for _, l := range leaves {
		ref.AppendData(l)
	}
	valid := get(t, d, "valid").A
	for _, e := range valid {
		f, s, p, fr, sr, ok := consistencyInput(t, e)
		if !ok || !merkle.VerifyConsistency(f, s, p, fr, sr) {
			t.Errorf("valid (%d, %d) refused", f, s)
			continue
		}
		gen, err := ref.ConsistencyProof(f, s)
		if err != nil || len(gen) != len(p) {
			t.Errorf("(%d, %d): generated PROOF differs", f, s)
			continue
		}
		for k := range gen {
			if !bytes.Equal(gen[k], p[k]) {
				t.Errorf("(%d, %d): PROOF element %d differs", f, s, k)
			}
		}
	}
	invalid := get(t, d, "invalid").A
	for _, e := range invalid {
		f, s, p, fr, sr, ok := consistencyInput(t, e)
		if ok && merkle.VerifyConsistency(f, s, p, fr, sr) {
			t.Errorf("invalid accepted: %s (%d, %d)", str(t, e, "mutation"), f, s)
		}
	}
	enc := get(t, d, "encoding").A
	for _, e := range enc {
		want := get(t, e, "verifies").B
		f, s, p, fr, sr, ok := consistencyInput(t, e)
		got := ok && merkle.VerifyConsistency(f, s, p, fr, sr)
		if got != want {
			t.Errorf("encoding %q: verifies %v, want %v", str(t, e, "case"), got, want)
		}
	}
	t.Logf("%d valid, %d invalid, %d encoding", len(valid), len(invalid), len(enc))
}

func stockAccepts(body string) bool {
	var cp log.Checkpoint
	_, err := cp.Unmarshal([]byte(body))
	return err == nil
}

// checkpoint-vectors.json: bodies, chain segments, domain cases, the anchor
// log and the record artifacts.
func TestCheckpointVectors(t *testing.T) {
	d := load(t, "checkpoint-vectors.json")
	for _, c := range get(t, d, "bodies", "valid").A {
		name := str(t, c, "case")
		b, ok := checkpoint.Parse(get(t, c, "body"))
		if !ok {
			t.Errorf("valid body refused: %s", name)
			continue
		}
		if b.Origin != str(t, c, "origin") || b.Size != u64(t, c, "size") ||
			hex.EncodeToString(b.Root) != str(t, c, "root") ||
			checkpoint.DigestHex(b.Raw) != str(t, c, "checkpointDigest") {
			t.Errorf("valid body misread: %s", name)
		}
		if !stockAccepts(b.Raw) {
			t.Errorf("stock parser refuses valid body %s", name)
		}
	}
	for _, c := range get(t, d, "bodies", "invalid").A {
		name := str(t, c, "case")
		body := get(t, c, "body")
		if _, ok := checkpoint.Parse(body); ok {
			t.Errorf("invalid body accepted: %s", name)
		}
		if got, want := stockAccepts(body.S), get(t, c, "stockParserAccepts").B; got != want {
			t.Errorf("%s: stock parser accepts %v, vectors say %v (formats pin drifted?)", name, got, want)
		}
	}
	for i, c := range get(t, d, "bodies", "nonString").A {
		if _, ok := checkpoint.Parse(c); ok {
			t.Errorf("nonString body %d accepted", i)
		}
	}
	for _, c := range get(t, d, "chainSegments", "valid").A {
		id := str(t, c, "chainId")
		seg := str(t, c, "segment")
		if got, ok := checkpoint.EncodeChainSegment(id); !ok || got != seg {
			t.Errorf("chain %q: segment %q", id, got)
		}
		if got, ok := checkpoint.DecodeChainSegment(seg); !ok || got != id {
			t.Errorf("segment %q: chain %q", seg, got)
		}
	}
	for _, c := range get(t, d, "chainSegments", "invalid").A {
		if _, ok := checkpoint.DecodeChainSegment(str(t, c, "segment")); ok {
			t.Errorf("invalid segment accepted: %s", str(t, c, "case"))
		}
	}
	for _, c := range get(t, d, "chainSegments", "unencodable").A {
		v := get(t, c, "chainId")
		if !v.Lone {
			if _, ok := checkpoint.EncodeChainSegment(v.S); ok {
				t.Errorf("unencodable chain id encoded: %s", str(t, c, "case"))
			}
		}
	}
	domainCases(t, d)
	anchorLog(t, d)
	artifacts(t, d)
}

func chainArg(v *jsonv.Value) (*string, bool) {
	if v == nil || v.Kind != jsonv.String {
		return nil, true
	}
	s := v.S
	return &s, !v.Lone
}

func domainCases(t *testing.T, d *jsonv.Value) {
	for _, c := range get(t, d, "domain").A {
		name := str(t, c, "case")
		cid, _ := c.Get("chainId")
		chain, ok := chainArg(cid)
		r := checkpoint.Bind(str(t, c, "anchorOrigin"), str(t, c, "logOrigin"), chain, ok)
		want := str(t, c, "expect", "result")
		if r.Result != want {
			t.Errorf("domain %q: %s, want %s", name, r.Result, want)
			continue
		}
		if want == "ok" {
			if r.Namespace != str(t, c, "expect", "namespace") || r.ChainChecked != get(t, c, "expect", "chainChecked").B {
				t.Errorf("domain %q: namespace %q chainChecked %v", name, r.Namespace, r.ChainChecked)
			}
		}
	}
}

func anchorLog(t *testing.T, d *jsonv.Value) {
	al := get(t, d, "anchorLog")
	sources := get(t, al, "sourceLogs")
	var anchorLeaves [][]byte
	for _, ep := range get(t, al, "epochs").A {
		members := get(t, ep, "members").A
		var origins []string
		for _, m := range members {
			origin := str(t, m, "origin")
			origins = append(origins, origin)
			size := u64(t, m, "size")
			var leaves [][]byte
			for _, l := range get(t, sources, origin, "leaves").A[:size] {
				leaves = append(leaves, hexb(t, l.S))
			}
			root := merkle.Root(leaves)
			body := fmt.Sprintf("%s\n%d\n%s\n", origin, size, base64.StdEncoding.EncodeToString(root))
			if body != str(t, m, "body") || hex.EncodeToString(root) != str(t, m, "root") {
				t.Errorf("epoch member %s: body or root does not reproduce", origin)
			}
			if u64(t, m, "anchorLeafIndex") != uint64(len(anchorLeaves)) {
				t.Errorf("epoch member %s: anchor leaf index", origin)
			}
			anchorLeaves = append(anchorLeaves, checkpoint.Digest(body))
		}
		if !sort.StringsAreSorted(origins) {
			t.Errorf("epoch %s: members not in bytewise origin order", str(t, ep, "epoch"))
		}
		size := u64(t, ep, "anchorSize")
		root := merkle.Root(anchorLeaves[:size])
		body := fmt.Sprintf("%s\n%d\n%s\n", str(t, ep, "anchorOrigin"), size, base64.StdEncoding.EncodeToString(root))
		if body != str(t, ep, "anchorCheckpoint") || hex.EncodeToString(root) != str(t, ep, "anchorRoot") ||
			checkpoint.DigestHex(body) != str(t, ep, "p") {
			t.Errorf("epoch %s: anchor checkpoint or P does not reproduce", str(t, ep, "epoch"))
		}
	}
	for i, l := range get(t, al, "anchorLeaves").A {
		if !bytes.Equal(anchorLeaves[i], hexb(t, l.S)) {
			t.Errorf("anchor leaf %d", i)
		}
	}
	f, s, p, fr, sr, ok := consistencyInput(t, get(t, al, "anchorConsistency"))
	if !ok || !merkle.VerifyConsistency(f, s, p, fr, sr) {
		t.Errorf("anchor log consistency refused")
	}
}

func nullableBool(v *bool) *jsonv.Value {
	if v == nil {
		return report.Null()
	}
	return report.B(*v)
}

func sameJSON(t *testing.T, a, b *jsonv.Value) bool {
	t.Helper()
	x, err1 := canonical.Serialize(a)
	y, err2 := canonical.Serialize(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func artifacts(t *testing.T, d *jsonv.Value) {
	cases := get(t, d, "artifacts").A
	for _, c := range cases {
		name := str(t, c, "case")
		arts := get(t, c, "artifacts")
		in := anchor.Input{ChainOK: true}
		in.Anchor, _ = arts.Get("anchor")
		in.Legacy = arts.Has("blockchainAnchor")
		in.Digest = hexb(t, str(t, c, "digest"))
		if s, ok := c.Get("sequenceNumber"); ok && s.Kind != jsonv.Null {
			in.SequenceNumber = s
		}
		if cid, ok := c.Get("chainId"); ok {
			in.ChainID, in.ChainOK = chainArg(cid)
		}
		v := anchor.Verify(in)
		exp := get(t, c, "expect")
		if !sameJSON(t, nullableBool(v.Valid), get(t, exp, "anchorValid")) {
			t.Errorf("%q: anchorValid %v", name, fmtBool(v.Valid))
		}
		wantReason := ""
		if r, ok := exp.Get("reason"); ok {
			wantReason = r.S
		}
		gotReason := v.Reason
		if gotReason == anchor.ReasonAbsent && wantReason == "" {
			gotReason = "" // the vectors state absence by leaving the reason out
		}
		if gotReason != wantReason {
			t.Errorf("%q: reason %q, want %q", name, gotReason, wantReason)
		}
		if !sameJSON(t, nullableBool(v.MerkleProofValid), get(t, exp, "merkleProofValid")) {
			t.Errorf("%q: merkleProofValid %v", name, fmtBool(v.MerkleProofValid))
		}
		wantP := get(t, exp, "p")
		gotP := report.Null()
		if v.P != nil {
			gotP = report.S(hex.EncodeToString(v.P))
		}
		if !sameJSON(t, gotP, wantP) {
			t.Errorf("%q: p %v", name, v.P)
		}
		if !sameJSON(t, report.SOrNull(v.Namespace), get(t, exp, "anchorNamespace")) {
			t.Errorf("%q: anchorNamespace %v", name, v.Namespace)
		}
		wantPos, hasPos := exp.Get("anchorPosition")
		if hasPos != (v.Position != nil) || (hasPos && !sameJSON(t, v.Position.JSON(), wantPos)) {
			t.Errorf("%q: anchorPosition differs", name)
		}
		// The checks of Anchor §10.7, in report order, with their
		// reasons and facts.
		got := report.Arr()
		for _, c := range v.Checks {
			got.A = append(got.A, report.CheckJSON(c))
		}
		if !sameJSON(t, got, get(t, exp, "checks")) {
			a, _ := canonical.Serialize(got)
			b, _ := canonical.Serialize(get(t, exp, "checks"))
			t.Errorf("%q: checks\n     got %s\n    want %s", name, a, b)
		}
	}
	t.Logf("%d artifact cases", len(cases))
}

func fmtBool(b *bool) string {
	if b == nil {
		return "null"
	}
	return fmt.Sprint(*b)
}

// evidence-log-origin-vectors.json (Anchor §4.3.2).
func TestEvidenceLogOriginVectors(t *testing.T) {
	d := load(t, "evidence-log-origin-vectors.json")
	ns, store := str(t, d, "ns"), str(t, d, "storeId")
	for _, c := range get(t, d, "vectors").A {
		id := str(t, c, "chainId")
		seg, ok := checkpoint.EncodeChainSegment(id)
		if !ok || seg != str(t, c, "chainSegment") {
			t.Errorf("%s: segment %q", str(t, c, "name"), seg)
		}
		origin := ns + "/" + store + "/evidence/" + seg
		if origin != str(t, c, "origin") {
			t.Errorf("%s: origin %q", str(t, c, "name"), origin)
		}
		o, ok := checkpoint.ParseOrigin(origin)
		if !ok || o.Kind != checkpoint.KindEvidence || o.ChainID != id {
			t.Errorf("%s: origin does not read back", str(t, c, "name"))
		}
	}
	for _, c := range get(t, d, "storeLogs").A {
		kind := str(t, c, "kind")
		if ns+"/"+store+"/"+kind != str(t, c, "origin") {
			t.Errorf("store log %s: origin", kind)
		}
		if _, ok := checkpoint.ParseOrigin(str(t, c, "origin")); !ok {
			t.Errorf("store log %s: not a Tzun origin", kind)
		}
	}
	for _, c := range get(t, d, "invalidChainIds").A {
		v := get(t, c, "chainId")
		if v.Lone {
			continue // a lone surrogate is refused before any encoding
		}
		if _, ok := checkpoint.EncodeChainSegment(v.S); ok {
			t.Errorf("invalid chain id encoded: %s", str(t, c, "name"))
		}
	}
	for _, c := range get(t, d, "namespaces", "valid").A {
		if !checkpoint.ValidNamespace(str(t, c, "ns")) {
			t.Errorf("valid ns refused: %s", str(t, c, "name"))
		}
	}
	for _, c := range get(t, d, "namespaces", "invalid").A {
		if checkpoint.ValidNamespace(str(t, c, "ns")) {
			t.Errorf("invalid ns accepted: %s", str(t, c, "name"))
		}
	}
}

// v1.0-canonical-vectors.json and v1.0-integrity-vectors.json.
func TestCanonicalVectors(t *testing.T) {
	d := load(t, "v1.0-canonical-vectors.json")
	ran := 0
	for _, c := range get(t, d, "vectors").A {
		id := str(t, c, "id")
		in := substitute(get(t, c, "input"))
		got, err := canonical.Serialize(in)
		if err != nil || string(got) != str(t, c, "canonical") {
			t.Errorf("%s: %s", id, got)
		}
		ran++
	}
	for _, c := range get(t, d, "negativeVectors").A {
		in := substitute(get(t, c, "input"))
		if _, err := canonical.Serialize(in); err == nil {
			t.Errorf("%s: serialised, must be refused", str(t, c, "id"))
		}
		if _, err := canonical.RecordDigest(in); err == nil {
			t.Errorf("%s: digest computed, must be refused", str(t, c, "id"))
		}
	}
	t.Logf("%d canonical vectors", ran)

	iv := load(t, "v1.0-integrity-vectors.json")
	for _, c := range get(t, iv, "vectors").A {
		id := str(t, c, "id")
		switch str(t, c, "kind") {
		case "digest":
			var canon []byte
			if in, ok := c.Get("input"); ok {
				var fields []string
				for _, f := range get(t, c, "hashedFields").A {
					fields = append(fields, f.S)
				}
				sel, err := canonical.SelectFields(in, fields)
				if err != nil {
					t.Fatalf("%s: %v", id, err)
				}
				if canon, err = canonical.Serialize(sel); err != nil || string(canon) != str(t, c, "expectedCanonical") {
					t.Errorf("%s: canonical %s", id, canon)
				}
			} else {
				canon = []byte(str(t, c, "canonical"))
			}
			if canonical.Digest(canon) != str(t, c, "expectedDigest") {
				t.Errorf("%s: digest", id)
			}
		case "chain-link":
			prev := get(t, c, "previousDigest")
			want := get(t, c, "expectedChainLink")
			if prev.Kind == jsonv.Null {
				if want.Kind != jsonv.Null {
					t.Errorf("%s: a first record has no chain link", id)
				}
				continue
			}
			if canonical.ChainLink(prev.S, str(t, c, "currentDigest")) != want.S {
				t.Errorf("%s: chain link", id)
			}
		}
	}
}

// substitute replaces the harness sentinels of the canonical vectors: an
// undefined value (serialised as null), a lone surrogate and NaN.
func substitute(v *jsonv.Value) *jsonv.Value {
	switch v.Kind {
	case jsonv.String:
		switch {
		case v.S == "UNDEFINED_MARKER":
			return &jsonv.Value{Kind: jsonv.Null}
		case v.S == "NAN_MARKER":
			return &jsonv.Value{Kind: jsonv.Number, N: math.NaN()}
		case strings.Contains(v.S, "LONE_SURROGATE_D800"):
			return &jsonv.Value{Kind: jsonv.String, S: strings.ReplaceAll(v.S, "LONE_SURROGATE_D800", "\xed\xa0\x80"), Lone: true}
		}
	case jsonv.Array:
		out := &jsonv.Value{Kind: jsonv.Array}
		for _, e := range v.A {
			out.A = append(out.A, substitute(e))
		}
		return out
	case jsonv.Object:
		out := &jsonv.Value{Kind: jsonv.Object}
		for _, m := range v.O {
			out.O = append(out.O, jsonv.Member{Key: m.Key, KeyLone: m.KeyLone, Value: substitute(m.Value)})
		}
		return out
	}
	return v
}

// e2e holds anchor-e2e-vectors.json read once.
type e2e struct {
	d        *jsonv.Value
	manifest *jsonv.Value
	source   *evm.StaticSource
}

func loadE2E(t *testing.T) *e2e {
	d := load(t, "anchor-e2e-vectors.json")
	hs := get(t, d, "headerSource")
	src := &evm.StaticSource{
		Chain:     new(big.Int).SetUint64(u64(t, hs, "chainId")),
		Finalized: u64(t, hs, "finalizedBlockNumber"),
		Blocks:    map[uint64]evm.Block{},
	}
	if str(t, hs, "finality") == "finalized" {
		src.Mode = evm.Finality{Declared: true, Finalized: true}
	}
	for _, ep := range get(t, d, "epochs").A {
		cb := get(t, ep, "canonicalBlock")
		src.Blocks[u64(t, cb, "number")] = evm.Block{
			Hash: common.HexToHash(str(t, cb, "hash")), Time: u64(t, cb, "timestamp"),
		}
	}
	return &e2e{d: d, manifest: get(t, d, "manifest"), source: src}
}

// joinedPublication joins a record's envelope entry with its epoch's heavy
// material, as an export bundle does.
func (x *e2e) joinedPublication(t *testing.T, env *jsonv.Value, epoch *jsonv.Value) func(int, *jsonv.Value) *jsonv.Value {
	heavy := get(t, epoch, "publication")
	return func(_ int, e *jsonv.Value) *jsonv.Value {
		j := &jsonv.Value{Kind: jsonv.Object, O: append([]jsonv.Member{}, e.O...)}
		for _, k := range []string{"rawTransaction", "blockHeader", "txIndex", "txProof"} {
			j.O = append(j.O, jsonv.Member{Key: k, Value: get(t, heavy, k)})
		}
		return j
	}
}

func checkByID(checks []report.Check, id string) *report.Check {
	for i := range checks {
		if checks[i].ID == id {
			return &checks[i]
		}
	}
	return nil
}

// anchor-e2e-vectors.json: each record's digest recomputes, and its anchor
// verifies bundle-only and with the stated header source.
func TestAnchorE2EVectors(t *testing.T) {
	x := loadE2E(t)
	epochs := get(t, x.d, "epochs").A
	for _, ep := range epochs {
		p := str(t, ep, "p")
		if checkpoint.DigestHex(str(t, ep, "anchorCheckpoint")) != p {
			t.Errorf("epoch P does not reproduce")
		}
		if data := evmData(t, str(t, ep, "publication", "rawTransaction")); hex.EncodeToString(data) != p {
			t.Errorf("epoch calldata is not P")
		}
		for _, m := range get(t, ep, "members").A {
			prev := get(t, m, "previousLogCheckpoint")
			if prev.Kind == jsonv.Null {
				continue
			}
			a, _ := checkpoint.ParseString(prev.S)
			b, _ := checkpoint.ParseString(str(t, m, "logCheckpoint"))
			path, _ := merkle.ParsePath(get(t, m, "consistencyProof"))
			if a == nil || b == nil || !merkle.VerifyConsistency(a.Size, b.Size, path, a.Root, b.Root) {
				t.Errorf("member consistency proof refused")
			}
		}
		if pa := get(t, ep, "previousAnchorSize"); pa.Kind != jsonv.Null {
			prevBody := str(t, epochs[0], "anchorCheckpoint")
			a, _ := checkpoint.ParseString(prevBody)
			b, _ := checkpoint.ParseString(str(t, ep, "anchorCheckpoint"))
			path, _ := merkle.ParsePath(get(t, ep, "anchorConsistencyProof"))
			if a == nil || b == nil || a.Size != u64(t, ep, "previousAnchorSize") ||
				!merkle.VerifyConsistency(a.Size, b.Size, path, a.Root, b.Root) {
				t.Errorf("anchor consistency proof refused")
			}
		}
	}
	for _, r := range get(t, x.d, "records").A {
		name := str(t, r, "case")
		env := get(t, r, "envelope")
		payload := get(t, env, "payload")
		digest, err := canonical.RecordDigest(payload)
		if err != nil || digest != str(t, env, "integrity", "canonicalDigest") {
			t.Errorf("%s: digest %s does not recompute", name, digest)
			continue
		}
		epoch := epochs[u64(t, r, "epoch")]
		chainID := str(t, r, "chainId")
		in := anchor.Input{
			Anchor: get(t, env, "nonRepudiation", "anchor"), Digest: hexb(t, digest),
			SequenceNumber: get(t, payload, "sequenceNumber"), ChainID: &chainID, ChainOK: true,
			Manifest: x.manifest, Join: x.joinedPublication(t, env, epoch),
		}
		bo := anchor.Verify(in)
		exp := get(t, r, "expect", "bundleOnly")
		if bo.Valid != nil || bo.Reason != str(t, exp, "anchorReason") || bo.MerkleProofValid == nil || !*bo.MerkleProofValid {
			t.Errorf("%s bundle-only: valid %s reason %s", name, fmtBool(bo.Valid), bo.Reason)
		}
		if c := checkByID(bo.Checks, "anchor.evm.tx[0]"); c == nil || string(c.Outcome) != str(t, exp, "evmTx") {
			t.Errorf("%s bundle-only: anchor.evm.tx[0] %+v", name, c)
		}
		if c := checkByID(bo.Checks, "anchor.evm.canonical[0]"); c == nil || c.Reason != str(t, exp, "evmCanonical") {
			t.Errorf("%s bundle-only: anchor.evm.canonical[0] %+v", name, c)
		}

		in.Sources = evm.Sources{ByChain: map[string]evm.HeaderSource{str(t, x.d, "chain"): x.source}}
		hs := anchor.Verify(in)
		w := get(t, r, "expect", "withHeaderSource")
		if hs.Valid == nil || !*hs.Valid {
			t.Errorf("%s with header source: valid %s reason %s", name, fmtBool(hs.Valid), hs.Reason)
			continue
		}
		if hs.Publication != str(t, w, "anchorPublication") || hs.OriginAuthenticated != get(t, w, "anchorOriginAuthenticated").B ||
			!sameJSON(t, report.SOrNull(hs.Namespace), get(t, w, "anchorNamespace")) ||
			!sameJSON(t, networkJSON(hs.Network), get(t, w, "anchorNetwork")) ||
			hs.Finality == nil || !sameJSON(t, hs.Finality.JSON(), get(t, w, "anchorFinality")) ||
			!sameJSON(t, hs.Position.JSON(), get(t, w, "anchorPosition")) {
			t.Errorf("%s with header source: anchor fields differ", name)
		}
		if hs.ExistedBy == nil || hs.ExistedBy.Source != str(t, w, "existedBy", "source") ||
			hs.ExistedBy.At.UTC().Format("2006-01-02T15:04:05.000Z") != str(t, w, "existedBy", "at") {
			t.Errorf("%s with header source: existedBy %+v", name, hs.ExistedBy)
		}
		if c := checkByID(hs.Checks, "anchor.evm.canonical[0]"); c == nil {
			t.Errorf("%s: no canonical check", name)
		} else if inc, _ := c.Fact("inclusion"); inc == nil || inc.S != str(t, w, "inclusion") {
			t.Errorf("%s: inclusion fact", name)
		}
	}
}

func networkJSON(n string) *jsonv.Value {
	if n == "" {
		return report.Null()
	}
	return report.S(n)
}

func evmData(t *testing.T, raw string) []byte {
	t.Helper()
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(hexb(t, raw)); err != nil {
		t.Fatalf("raw transaction: %v", err)
	}
	return tx.Data()
}
