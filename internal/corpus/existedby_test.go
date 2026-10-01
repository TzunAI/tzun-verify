package corpus

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/TzunAI/tzun-verify/internal/anchor"
	"github.com/TzunAI/tzun-verify/internal/evm"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
	"github.com/TzunAI/tzun-verify/internal/rfc3161"
	"github.com/TzunAI/tzun-verify/internal/testpki"
)

// withPublications is the anchor artifact a with its publications replaced.
func withPublications(a *jsonv.Value, pubs ...*jsonv.Value) *jsonv.Value {
	out := &jsonv.Value{Kind: jsonv.Object}
	for _, m := range a.O {
		if m.Key == "publications" {
			m.Value = &jsonv.Value{Kind: jsonv.Array, A: pubs}
		}
		out.O = append(out.O, m)
	}
	return out
}

// TestExistedByTie: the first anchor-e2e record's EVM publication beside an
// RFC 3161 token over the same P. At the same instant, existedBy names the
// EVM publication wherever it sits in the array (Anchor §10.6); a token one
// second earlier is the bound.
func TestExistedByTie(t *testing.T) {
	x := loadE2E(t)
	r := get(t, x.d, "records").A[0]
	env := get(t, r, "envelope")
	epoch := get(t, x.d, "epochs").A[u64(t, r, "epoch")]
	p := hexb(t, str(t, epoch, "p"))
	block := time.Unix(int64(u64(t, epoch, "canonicalBlock", "timestamp")), 0).UTC()
	art := get(t, env, "nonRepudiation", "anchor")
	evmEntry := get(t, art, "publications").A[0]

	root := testpki.Root("Root")
	inter := testpki.Intermediate("TSA CA", root, true)
	signer := testpki.TSASigner("Authority", inter)
	token := func(at time.Time) *jsonv.Value {
		return report.Obj("kind", report.S(rfc3161.Kind),
			"token", report.S(testpki.Token(p, signer, []*x509.Certificate{inter.Cert}, at, true)))
	}
	chainID := str(t, r, "chainId")
	verify := func(pubs ...*jsonv.Value) anchor.Verdict {
		return anchor.Verify(anchor.Input{
			Anchor: withPublications(art, pubs...), Digest: hexb(t, str(t, env, "integrity", "canonicalDigest")),
			SequenceNumber: get(t, env, "payload", "sequenceNumber"), ChainID: &chainID, ChainOK: true,
			Manifest: x.manifest, Join: x.joinedPublication(t, env, epoch),
			Sources: evm.Sources{ByChain: map[string]evm.HeaderSource{str(t, x.d, "chain"): x.source}},
			Trust:   rfc3161.Trust{Roots: []*x509.Certificate{root.Cert}},
		})
	}
	earlier := block.Add(-time.Second)
	for _, c := range []struct {
		name   string
		pubs   []*jsonv.Value
		source string
		at     time.Time
	}{
		{"token first, same instant", []*jsonv.Value{token(block), evmEntry}, "evm-calldata", block},
		{"EVM first, same instant", []*jsonv.Value{evmEntry, token(block)}, "evm-calldata", block},
		{"token first, a second earlier", []*jsonv.Value{token(earlier), evmEntry}, "rfc3161", earlier},
		{"EVM first, token a second earlier", []*jsonv.Value{evmEntry, token(earlier)}, "rfc3161", earlier},
	} {
		v := verify(c.pubs...)
		if v.Valid == nil || !*v.Valid || v.Publication != "evm-calldata" || !v.OriginAuthenticated {
			t.Errorf("%s: valid %s, publication %q, reason %q", c.name, fmtBool(v.Valid), v.Publication, v.Reason)
			continue
		}
		if v.ExistedBy == nil || v.ExistedBy.Source != c.source || !v.ExistedBy.At.Equal(c.at) {
			t.Errorf("%s: existedBy %+v, want %s at %s", c.name, v.ExistedBy, c.source, c.at)
		}
	}
}
