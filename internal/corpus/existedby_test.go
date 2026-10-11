// SPDX-License-Identifier: BSD-3-Clause-Clear

package corpus

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TzunAI/tzun-verify/internal/anchor"
	"github.com/TzunAI/tzun-verify/internal/cli"
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
// second earlier is the bound. A genTime half a millisecond before the
// block's time is the bound to the millisecond, as the report writes it
// (Verification §6.5): the millisecond before the block, not the block's.
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
	// built carries a genTime finer than a second, which Token cannot write.
	built := func(at time.Time) *jsonv.Value {
		return report.Obj("kind", report.S(rfc3161.Kind), "token", report.S(testpki.BuildToken(testpki.TokenOptions{
			Digest: p, GenTime: at, Signer: signer, Certs: []*x509.Certificate{inter.Cert},
		})))
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
		{"EVM first, token half a millisecond earlier", []*jsonv.Value{evmEntry, built(block.Add(-500 * time.Microsecond))},
			"rfc3161", block.Add(-time.Millisecond)},
		{"token first, half a millisecond later", []*jsonv.Value{built(block.Add(500 * time.Microsecond)), evmEntry},
			"evm-calldata", block},
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

// TestBundleExistedByTie: the summary's existedBy (Verification §6.4) with
// the record's RFC 3161 token replaced by one from a test authority at
// chosen instants. Of equal instants, the record's anchor is named before
// the record timestamp; when only the newer anchor holds
// (fabricated-header-with-source), the newer anchor is. Instants compare to
// the millisecond (Verification §6.5), so a token half a millisecond after
// the anchor's block time ties with it, and one half a millisecond before
// is the bound at the millisecond before.
func TestBundleExistedByTie(t *testing.T) {
	root := testpki.Root("Root")
	inter := testpki.Intermediate("TSA CA", root, true)
	signer := testpki.TSASigner("Authority", inter)
	rootFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(name string, at time.Time) *jsonv.Value {
		t.Helper()
		dir := filepath.Join(vectorDir, "bundle-b1", name)
		in, err := jsonv.Parse(readCase(t, dir, "inputs.json"))
		if err != nil {
			t.Fatal(err)
		}
		var flags []string
		all := args(t, in, t.TempDir())
		for i := 0; i < len(all); i++ {
			if all[i] == "--tsa-roots" {
				i++
				continue
			}
			flags = append(flags, all[i])
		}
		b := loadDoc(t, filepath.Join(dir, "bundle.json"))
		digest := hexb(t, sub(b, "subject")["canonicalDigest"].(string))
		sub(b, "envelope", "nonRepudiation")["rfc3161Token"] = testpki.BuildToken(testpki.TokenOptions{
			Digest: digest, GenTime: at, Signer: signer, Certs: []*x509.Certificate{inter.Cert},
		})
		enc, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(t.TempDir(), "bundle.json")
		if err := os.WriteFile(f, enc, 0o600); err != nil {
			t.Fatal(err)
		}
		flags = append(flags, "--tsa-roots", rootFile, "--json", f)
		var stdout, stderr bytes.Buffer
		cli.Run(flags, &stdout, &stderr)
		if stderr.Len() > 0 {
			t.Fatalf("tzun-verify %v: %s", flags, stderr.String())
		}
		rep, err := jsonv.Parse(stdout.Bytes())
		if err != nil {
			t.Fatalf("report: %v", err)
		}
		return rep
	}
	ms := func(at time.Time) string { return at.UTC().Format("2006-01-02T15:04:05.000Z") }
	// blockOf is the anchor's block time: the existedBy the case's report
	// states, named by check, since its corpus token is later.
	blockOf := func(name, check string) time.Time {
		t.Helper()
		want, err := jsonv.Parse(readCase(t, filepath.Join(vectorDir, "bundle-b1", name), "expected-report.json"))
		if err != nil {
			t.Fatal(err)
		}
		e := get(t, want, "summary", "existedBy")
		if str(t, e, "source") != "evm-calldata" || str(t, e, "check") != check {
			t.Fatalf("%s: existedBy %s, want %s from evm-calldata", name, canonicalOf(t, e), check)
		}
		at, err := time.Parse(time.RFC3339Nano, str(t, e, "at"))
		if err != nil {
			t.Fatal(err)
		}
		return at
	}
	const half = 500 * time.Microsecond
	for _, c := range []struct {
		name, bundle, named string        // named: the check the case's report names
		token, at           time.Duration // from the block's time
		source, check       string
	}{
		{"the block's time", "anchored-with-newer", "anchor", 0, 0, "evm-calldata", "anchor"},
		{"half a millisecond after the block", "anchored-with-newer", "anchor", half, 0, "evm-calldata", "anchor"},
		{"the block's time, only the newer anchor holding", "fabricated-header-with-source", "anchor.newer", 0, 0, "evm-calldata", "anchor.newer"},
		{"a millisecond before the block", "anchored-with-newer", "anchor", -time.Millisecond, -time.Millisecond, "record-timestamp", "ts.record.trust"},
		{"half a millisecond before the block", "anchored-with-newer", "anchor", -half, -time.Millisecond, "record-timestamp", "ts.record.trust"},
	} {
		block := blockOf(c.bundle, c.named)
		token, at := block.Add(c.token), block.Add(c.at)
		rep := run(c.bundle, token)
		trust := rowOf(t, rep, "ts.record.trust")
		if rowLine(t, trust) != "checked-correct" {
			t.Errorf("%s: ts.record.trust %s", c.name, rowLine(t, trust))
			continue
		}
		if g := str(t, trust, "facts", "genTime"); g != ms(token) {
			t.Errorf("%s: ts.record.trust genTime %s, want %s", c.name, g, ms(token))
		}
		e := get(t, rep, "summary", "existedBy")
		if str(t, e, "at") != ms(at) || str(t, e, "source") != c.source || str(t, e, "check") != c.check {
			t.Errorf("%s: existedBy %s, want %s %s at %s", c.name, canonicalOf(t, e), c.check, c.source, ms(at))
		}
	}
}
