// SPDX-License-Identifier: BSD-3-Clause-Clear

package rfc3161

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
	"github.com/TzunAI/tzun-verify/internal/testpki"
)

var p = func() []byte { s := sha256.Sum256([]byte("P")); return s[:] }()

func entry(token string) *jsonv.Value {
	return report.Obj("kind", report.S(Kind), "token", report.S(token))
}

type want struct {
	valid       string
	reason      string
	token       report.Outcome
	tokenReason string
	trust       report.Outcome
	trustReason string
}

func check(t *testing.T, name string, r Result, w want) {
	t.Helper()
	valid := "null"
	if r.Valid != nil {
		valid = fmt.Sprint(*r.Valid)
	}
	if valid != w.valid || r.Reason != w.reason {
		t.Errorf("%s: publication %s %q, want %s %q", name, valid, r.Reason, w.valid, w.reason)
	}
	if r.Token.Outcome != w.token || r.Token.Reason != w.tokenReason {
		t.Errorf("%s: token %s %q, want %s %q", name, r.Token.Outcome, r.Token.Reason, w.token, w.tokenReason)
	}
	if r.Trust.Outcome != w.trust || r.Trust.Reason != w.trustReason {
		t.Errorf("%s: trust %s %q, want %s %q", name, r.Trust.Outcome, r.Trust.Reason, w.trust, w.trustReason)
	}
}

func blocked() (report.Outcome, string) { return report.NotChecked, "blocked_by:anchor.tsa.token[0]" }

func tokenFail(reason string) want {
	o, r := blocked()
	return want{valid: "false", reason: reason, token: report.Wrong, tokenReason: reason, trust: o, trustReason: r}
}

func TestTokens(t *testing.T) {
	root := testpki.Root("Test Root")
	inter := testpki.Intermediate("Test TSA CA", root, true)
	signer := testpki.TSASigner("Test TSA", inter)
	chain := []*x509.Certificate{inter.Cert}
	gen := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	trusted := Trust{Roots: []*x509.Certificate{root.Cert}}

	good := testpki.Token(p, signer, chain, gen, true)
	r := Verify(0, entry(good), p, trusted)
	check(t, "positive, through the intermediate", r, want{valid: "true", token: report.Correct, trust: report.Correct})
	if !r.GenTime.Equal(gen) || r.Authority != "Test TSA" {
		t.Errorf("facts: genTime %v authority %q", r.GenTime, r.Authority)
	}
	if v, _ := r.Trust.Fact("authority"); v == nil || v.S != "Test TSA" {
		t.Errorf("authority fact")
	}
	// The intermediate supplied by configuration instead of the token.
	noChain := testpki.Token(p, signer, nil, gen, true)
	check(t, "intermediate from configuration", Verify(0, entry(noChain), p, Trust{Roots: trusted.Roots, Intermediates: chain}),
		want{valid: "true", token: report.Correct, trust: report.Correct})
	check(t, "intermediate missing", Verify(0, entry(noChain), p, trusted),
		want{valid: "null", reason: ReasonNotChecked, token: report.Correct, trust: report.NotChecked, trustReason: ReasonNoTrustAnchor})

	now := time.Now()
	vf := tokenFail(ReasonVerificationFailed)
	tls := testpki.Signer("TLS", inter, now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), testpki.EKU(false, testpki.ServerAuth))
	check(t, "TLS server certificate", Verify(0, entry(testpki.Token(p, tls, chain, gen, true)), p, trusted), vf)
	nonCrit := testpki.Signer("TSA", inter, now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), testpki.EKU(false, testpki.TimeStamping))
	check(t, "timestamping EKU not critical", Verify(0, entry(testpki.Token(p, nonCrit, chain, gen, true)), p, trusted), vf)
	two := testpki.Signer("TSA", inter, now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), testpki.EKU(true, testpki.TimeStamping, testpki.ServerAuth))
	check(t, "a second purpose", Verify(0, entry(testpki.Token(p, two, chain, gen, true)), p, trusted), vf)
	noEKU := testpki.Signer("TSA", inter, now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0))
	check(t, "no EKU", Verify(0, entry(testpki.Token(p, noEKU, chain, gen, true)), p, trusted), vf)

	notCA := testpki.Intermediate("Not a CA", root, false)
	underNotCA := testpki.TSASigner("TSA", notCA)
	// The signing library refuses to embed a chain through a non-CA, so the
	// configuration supplies it.
	check(t, "intermediate without cA",
		Verify(0, entry(testpki.Token(p, underNotCA, nil, gen, true)), p,
			Trust{Roots: trusted.Roots, Intermediates: []*x509.Certificate{notCA.Cert}}),
		want{valid: "false", reason: ReasonVerificationFailed, token: report.Correct, trust: report.Wrong, trustReason: ReasonVerificationFailed})

	late := testpki.Signer("TSA", inter, now.Add(-time.Minute), now.AddDate(1, 0, 0), testpki.EKU(true, testpki.TimeStamping))
	check(t, "signer not valid at genTime",
		Verify(0, entry(testpki.Token(p, late, chain, gen, true)), p, trusted),
		want{valid: "false", reason: ReasonVerificationFailed, token: report.Correct, trust: report.Wrong, trustReason: ReasonVerificationFailed})

	// A certHash naming another certificate: the attribute is under the
	// signature, so the patched token fails as a forgery.
	der, _ := base64.StdEncoding.DecodeString(good)
	signerHash := sha256.Sum256(signer.Cert.Raw)
	other := sha256.Sum256(inter.Cert.Raw)
	patched := bytes.Replace(der, signerHash[:], other[:], 1)
	if bytes.Equal(patched, der) {
		t.Fatal("certHash not found in the token")
	}
	check(t, "certHash names another certificate", Verify(0, entry(base64.StdEncoding.EncodeToString(patched)), p, trusted), vf)

	sig := append([]byte{}, der...)
	sig[len(sig)-5] ^= 0x01 // inside the signature, the token's last field
	check(t, "a signature byte flipped", Verify(0, entry(base64.StdEncoding.EncodeToString(sig)), p, trusted), vf)

	im := tokenFail(ReasonImprintMismatch)
	otherP := sha256.Sum256([]byte("not P"))
	overOther := testpki.Token(otherP[:], signer, chain, gen, true)
	check(t, "another value, trusted root", Verify(0, entry(overOther), p, trusted), im)
	check(t, "another value, no roots", Verify(0, entry(overOther), p, Trust{}), im)

	mf := tokenFail(ReasonMalformed)
	check(t, "not base64", Verify(0, entry("not base64!"), p, trusted), mf)
	check(t, "not a TimeStampResp", Verify(0, entry(base64.StdEncoding.EncodeToString([]byte("hello"))), p, trusted), mf)
	check(t, "rejection", Verify(0, entry(testpki.Rejection()), p, trusted), mf)
	check(t, "no signer certificate", Verify(0, entry(testpki.Token(p, signer, chain, gen, false)), p, trusted), mf)
	check(t, "token not a string", Verify(0, report.Obj("kind", report.S(Kind), "token", report.N(1)), p, trusted), mf)
	check(t, "not an object", Verify(0, report.Arr(), p, trusted), mf)

	check(t, "roots without its root", Verify(0, entry(good), p, Trust{Roots: []*x509.Certificate{testpki.Root("Other").Cert}}),
		want{valid: "null", reason: ReasonNotChecked, token: report.Correct, trust: report.NotChecked, trustReason: ReasonNoTrustAnchor})
	check(t, "no roots", Verify(0, entry(good), p, Trust{}),
		want{valid: "null", reason: ReasonNotChecked, token: report.Correct, trust: report.NotChecked, trustReason: ReasonNoTrustAnchor})

	// A root that shares the real root's name but not its key: the path
	// reaches a supplied root and fails there.
	impostor := testpki.Root("Test Root")
	check(t, "a root of the same name", Verify(0, entry(good), p, Trust{Roots: []*x509.Certificate{impostor.Cert}}),
		want{valid: "false", reason: ReasonVerificationFailed, token: report.Correct, trust: report.Wrong, trustReason: ReasonVerificationFailed})

	// Tokens built field by field: the signer binding and the content-type
	// attribute, which a signing library always writes correctly.
	build := func(o testpki.TokenOptions) string {
		if o.Digest == nil {
			o.Digest = p
		}
		if o.Signer == nil {
			o.Signer = signer
		}
		if o.GenTime.IsZero() {
			o.GenTime = gen
		}
		if o.Certs == nil {
			o.Certs = chain
		}
		return testpki.BuildToken(o)
	}
	okw := want{valid: "true", token: report.Correct, trust: report.Correct}
	check(t, "built, v2 binding", Verify(0, entry(build(testpki.TokenOptions{})), p, trusted), okw)
	check(t, "built, v1 binding (SHA-1 certHash)", Verify(0, entry(build(testpki.TokenOptions{Binding: "v1"})), p, trusted), okw)
	check(t, "built, v2 binding with SHA-384", Verify(0, entry(build(testpki.TokenOptions{Binding: "v2-sha384"})), p, trusted), okw)
	check(t, "no signingCertificate", Verify(0, entry(build(testpki.TokenOptions{Binding: "none"})), p, trusted), vf)
	check(t, "certHash of another certificate, validly signed",
		Verify(0, entry(build(testpki.TokenOptions{CertHashOf: inter.Cert})), p, trusted), vf)
	check(t, "v1 certHash of another certificate",
		Verify(0, entry(build(testpki.TokenOptions{Binding: "v1", CertHashOf: inter.Cert})), p, trusted), vf)
	check(t, "issuerSerial names another serial",
		Verify(0, entry(build(testpki.TokenOptions{Serial: big.NewInt(7)})), p, trusted), vf)
	check(t, "content-type attribute names another type",
		Verify(0, entry(build(testpki.TokenOptions{ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}})), p, trusted), vf)
	check(t, "no content-type attribute", Verify(0, entry(build(testpki.TokenOptions{OmitContentType: true})), p, trusted), vf)
	check(t, "built without the signer's certificate",
		Verify(0, entry(build(testpki.TokenOptions{OmitSignerCert: true})), p, trusted), mf)

	// A signer named by subjectKeyIdentifier (RFC 5652 §5.3), which §10.5
	// step 1 requires a verifier to read: the certificate whose
	// subjectKeyIdentifier extension holds the sid's key identifier, byte
	// for byte. Naming a key no carried certificate has is malformed.
	now = time.Now()
	ski := func(name string, id ...byte) *testpki.Cert {
		v, err := asn1.Marshal(id)
		if err != nil {
			t.Fatal(err)
		}
		return testpki.Signer(name, inter, now.AddDate(-5, 0, 0), now.AddDate(5, 0, 0), testpki.EKU(true, testpki.TimeStamping),
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: v})
	}
	skiSigner := ski("SKI TSA", 1, 2, 3, 4)
	check(t, "signer named by subjectKeyIdentifier",
		Verify(0, entry(build(testpki.TokenOptions{Signer: skiSigner, SKISid: true})), p, trusted), okw)
	noSKI := testpki.TSASigner("No SKI", inter)
	check(t, "subjectKeyIdentifier naming no carried certificate",
		Verify(0, entry(build(testpki.TokenOptions{Signer: noSKI, SKISid: true})), p, trusted), mf)
	// The sid names the carried certificate that holds its key identifier,
	// whose key did not sign: the signature fails at step 3.
	skiImpostor := ski("SKI TSA", 1, 2, 3, 4)
	check(t, "subjectKeyIdentifier naming a certificate whose key did not sign",
		Verify(0, entry(build(testpki.TokenOptions{Signer: skiImpostor, SKISid: true, OmitSignerCert: true,
			Certs: []*x509.Certificate{skiSigner.Cert, inter.Cert}})), p, trusted), vf)
	// Byte for byte: a key identifier one octet longer or shorter is
	// another one.
	check(t, "a carried certificate whose key identifier is a prefix of the sid's",
		Verify(0, entry(build(testpki.TokenOptions{Signer: ski("SKI TSA", 1, 2, 3, 4, 5), SKISid: true,
			Certs: []*x509.Certificate{inter.Cert, ski("Prefix", 1, 2, 3, 4).Cert}})), p, trusted), okw)
	check(t, "a sid whose key identifier is a prefix of the carried certificate's",
		Verify(0, entry(build(testpki.TokenOptions{Signer: ski("SKI TSA", 1, 2, 3, 4), SKISid: true, OmitSignerCert: true,
			Certs: []*x509.Certificate{inter.Cert, ski("Longer", 1, 2, 3, 4, 5).Cert}})), p, trusted), mf)
}

func TestPathRules(t *testing.T) {
	root := testpki.Root("Root")
	gen := time.Now().Add(-time.Hour)
	trusted := Trust{Roots: []*x509.Certificate{root.Cert}}
	pathFail := want{valid: "false", reason: ReasonVerificationFailed, token: report.Correct, trust: report.Wrong, trustReason: ReasonVerificationFailed}
	okw := want{valid: "true", token: report.Correct, trust: report.Correct}
	token := func(signer *testpki.Cert, inters ...*x509.Certificate) (*jsonv.Value, Trust) {
		return entry(testpki.BuildToken(testpki.TokenOptions{Digest: p, GenTime: gen, Signer: signer})),
			Trust{Roots: trusted.Roots, Intermediates: inters}
	}

	// basicConstraints absent, keyUsage absent: only cA can refuse it.
	noBC := testpki.CA("No basicConstraints", root, false, false, 0, -1)
	e, tr := token(testpki.TSASigner("TSA", noBC), noBC.Cert)
	check(t, "intermediate without basicConstraints", Verify(0, e, p, tr), pathFail)

	// A CA whose keyUsage lacks keyCertSign.
	noCertSign := testpki.CA("No keyCertSign", root, true, true, x509.KeyUsageDigitalSignature, -1)
	e, tr = token(testpki.TSASigner("TSA", noCertSign), noCertSign.Cert)
	check(t, "intermediate without keyCertSign", Verify(0, e, p, tr), pathFail)

	// pathLenConstraint 0 with an intermediate below it.
	top := testpki.CA("Top", root, true, true, x509.KeyUsageCertSign, 0)
	below := testpki.CA("Below", top, true, true, x509.KeyUsageCertSign, -1)
	e, tr = token(testpki.TSASigner("TSA", below), below.Cert, top.Cert)
	check(t, "pathLenConstraint 0 exceeded", Verify(0, e, p, tr), pathFail)

	// pathLenConstraint 1 allows it.
	top1 := testpki.CA("Top1", root, true, true, x509.KeyUsageCertSign, 1)
	below1 := testpki.CA("Below1", top1, true, true, x509.KeyUsageCertSign, -1)
	e, tr = token(testpki.TSASigner("TSA", below1), below1.Cert, top1.Cert)
	check(t, "pathLenConstraint 1 met", Verify(0, e, p, tr), okw)

	// An intermediate that had expired by genTime: its path reaches the
	// root, and is not valid.
	expired := testpki.CAValid("Expired CA", root, time.Now().AddDate(-10, 0, 0), time.Now().AddDate(-5, 0, 0))
	e, tr = token(testpki.TSASigner("TSA", expired), expired.Cert)
	check(t, "an intermediate not valid at genTime", Verify(0, e, p, tr), pathFail)
	// Beside the expired certificate, its renewal: the same name and key,
	// still valid. The valid path decides, whichever the search meets first.
	renewed := testpki.CAValid("Expired CA", root, time.Now().AddDate(-10, 0, 0), time.Now().AddDate(5, 0, 0), expired.Key)
	signer := testpki.TSASigner("TSA", expired)
	for _, order := range [][]*x509.Certificate{{expired.Cert, renewed.Cert}, {renewed.Cert, expired.Cert}} {
		e, tr = token(signer, order...)
		check(t, "a valid path beside an expired one", Verify(0, e, p, tr), okw)
	}

	// A signer that is itself a supplied root needs no path.
	selfRoot := testpki.Signer("Self", nil, time.Now().AddDate(-1, 0, 0), time.Now().AddDate(1, 0, 0), testpki.EKU(true, testpki.TimeStamping))
	e = entry(testpki.BuildToken(testpki.TokenOptions{Digest: p, GenTime: gen, Signer: selfRoot}))
	check(t, "the signer is a supplied root", Verify(0, e, p, Trust{Roots: []*x509.Certificate{selfRoot.Cert}}), okw)
}

func TestHostileCertificateSetIsBounded(t *testing.T) {
	// A token whose signer sits under "Loop CA", carrying many self-signed
	// certificates that share that name: every one issues every other by
	// name. An unbounded path search grows about N^10 here; the bounded
	// breadth-first search visits each certificate once.
	gen := time.Now().Add(-time.Hour)
	loop := testpki.Root("Loop CA")
	signer := testpki.TSASigner("TSA", loop)
	certs := []*x509.Certificate{loop.Cert}
	for i := 0; i < 20; i++ {
		certs = append(certs, testpki.Root("Loop CA").Cert)
	}
	tok := entry(testpki.BuildToken(testpki.TokenOptions{Digest: p, GenTime: gen, Signer: signer, Certs: certs}))

	for name, c := range map[string]struct {
		trust Trust
		w     want
	}{
		"no roots": {Trust{}, want{valid: "null", reason: ReasonNotChecked, token: report.Correct, trust: report.NotChecked, trustReason: ReasonNoTrustAnchor}},
		"a root of that name and another key": {Trust{Roots: []*x509.Certificate{testpki.Root("Loop CA").Cert}},
			want{valid: "false", reason: ReasonVerificationFailed, token: report.Correct, trust: report.Wrong, trustReason: ReasonVerificationFailed}},
		"the real root among them": {Trust{Roots: []*x509.Certificate{loop.Cert}},
			want{valid: "true", token: report.Correct, trust: report.Correct}},
	} {
		start := time.Now()
		r := Verify(0, tok, p, c.trust)
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s: %v", name, d)
		}
		check(t, name, r, c.w)
	}

	// Past the bound on certificates the search stops, and says nothing
	// against the token.
	many := append([]*x509.Certificate{}, certs...)
	for len(many) <= maxCandidates {
		many = append(many, testpki.Root(fmt.Sprintf("Filler %d", len(many))).Cert)
	}
	tok = entry(testpki.BuildToken(testpki.TokenOptions{Digest: p, GenTime: gen, Signer: signer, Certs: many}))
	check(t, "past the bound", Verify(0, tok, p, Trust{Roots: []*x509.Certificate{loop.Cert}}),
		want{valid: "null", reason: ReasonNotChecked, token: report.Correct, trust: report.NotChecked, trustReason: ReasonNoTrustAnchor})
}

// TestRealAuthorityTokens runs the record's own token path on timestamps
// that two public authorities issued, over one record digest of the b1
// conformance corpus: FreeTSA and Sectigo. Each response is kept as the
// authority sent
// it (testdata/*.tsr), with the authority's root. §10.5 holds for both:
// DER, a signingCertificate(V2) binding, a timestamping-only critical EKU,
// and a path to the root valid at genTime. Under the other authority's root
// alone neither reaches a supplied root.
func TestRealAuthorityTokens(t *testing.T) {
	digest, _ := hex.DecodeString("9739ebd76cc45223ccc88920802c9032208f3c09f67fc129a41a769109dead6a")
	readRoot := func(name string) *x509.Certificate {
		raw, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(raw)
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	free, sectigo := readRoot("freetsa-root.pem"), readRoot("sectigo-root-r46.pem")
	for _, c := range []struct {
		file, authority, genTime string
		root, other              *x509.Certificate
	}{
		{"freetsa.tsr", "www.freetsa.org", "2026-10-01T19:40:02.", free, sectigo},
		{"sectigo.tsr", "Sectigo Public Time Stamping Signer R37", "2026-10-01T19:40:03.", sectigo, free},
	} {
		raw, err := os.ReadFile(filepath.Join("testdata", c.file))
		if err != nil {
			t.Fatal(err)
		}
		tok := report.S(base64.StdEncoding.EncodeToString(raw))
		r := VerifyRecordToken(tok, digest, Trust{Roots: []*x509.Certificate{c.root}})
		if r.Token.Outcome != report.Correct || r.Trust.Outcome != report.Correct || r.Authority != c.authority {
			t.Errorf("%s: token %s %q, trust %s %q, authority %q", c.file, r.Token.Outcome, r.Token.Reason, r.Trust.Outcome, r.Trust.Reason, r.Authority)
		}
		if g, ok := r.Trust.Fact("genTime"); !ok || !strings.HasPrefix(g.S, c.genTime) {
			t.Errorf("%s: genTime %v", c.file, g)
		}
		r = VerifyRecordToken(tok, digest, Trust{Roots: []*x509.Certificate{c.other}})
		if r.Token.Outcome != report.Correct || r.Trust.Outcome != report.NotChecked || r.Trust.Reason != ReasonNoTrustAnchor {
			t.Errorf("%s under another root: trust %s %q", c.file, r.Trust.Outcome, r.Trust.Reason)
		}
		other := append([]byte(nil), digest...)
		other[0] ^= 1
		if r = VerifyRecordToken(tok, other, Trust{Roots: []*x509.Certificate{c.root}}); r.Token.Reason != ReasonImprintMismatch {
			t.Errorf("%s over another digest: %s %q", c.file, r.Token.Outcome, r.Token.Reason)
		}
	}
}

// opensslTokens reads testdata/openssl-tokens.json: responses OpenSSL made
// over one record digest, for keys this build does not implement.
type opensslTokens struct {
	Digest       string            `json:"digest"`
	Roots        map[string]string `json:"roots"`
	Certificates map[string]string `json:"certificates"`
	Tokens       map[string]string `json:"tokens"`
}

func readOpenSSLTokens(t *testing.T) opensslTokens {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "openssl-tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	var o opensslTokens
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func pemCert(t *testing.T, s string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestUnimplementedKeysInRealTokens: a key on a curve this build does not
// implement is not a decoding failure (§10.5 step 1). A step that needs it
// is not-checked, missing_dependency (step 5): the signer's at step 3, an
// intermediate's at step 4. A certificate no step needs is not examined.
// A DSA signature is an algorithm this build does not implement, never a
// failed signature.
func TestUnimplementedKeysInRealTokens(t *testing.T) {
	o := readOpenSSLTokens(t)
	digest, _ := hex.DecodeString(o.Digest)
	trusted := Trust{Roots: []*x509.Certificate{pemCert(t, o.Roots["p256"])}}
	const tok, tru = IDRecordToken, IDRecordTrust
	blockedTrust := "blocked_by:" + tok
	for name, w := range map[string]want{
		"p256":                     {valid: "true", token: report.Correct, trust: report.Correct},
		"brainpoolP256r1":          {valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency, trust: report.NotChecked, trustReason: blockedTrust},
		"secp256k1":                {valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency, trust: report.NotChecked, trustReason: blockedTrust},
		"prime192v1":               {valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency, trust: report.NotChecked, trustReason: blockedTrust},
		"sect283k1":                {valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency, trust: report.NotChecked, trustReason: blockedTrust},
		"explicitP256":             {valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency, trust: report.NotChecked, trustReason: blockedTrust},
		"unknownCurve":             {valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency, trust: report.NotChecked, trustReason: blockedTrust},
		"gostParamSet":             {valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency, trust: report.NotChecked, trustReason: blockedTrust},
		"sm2WithP256Point":         {valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency, trust: report.NotChecked, trustReason: blockedTrust},
		"unknownAlgorithm":         {valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency, trust: report.NotChecked, trustReason: blockedTrust},
		"dsaWithSHA256":            {valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency, trust: report.NotChecked, trustReason: blockedTrust},
		"extraBrainpool":           {valid: "true", token: report.Correct, trust: report.Correct},
		"extraUnknownCurve":        {valid: "true", token: report.Correct, trust: report.Correct},
		"brainpoolIntermediate":    {valid: "null", reason: ReasonNotChecked, token: report.Correct, trust: report.NotChecked, trustReason: ReasonMissingDependency},
		"unknownCurveIntermediate": {valid: "null", reason: ReasonNotChecked, token: report.Correct, trust: report.NotChecked, trustReason: ReasonMissingDependency},
	} {
		s, ok := o.Tokens[name]
		if !ok {
			t.Fatalf("no token %s", name)
		}
		r := VerifyRecordToken(report.S(s), digest, trusted)
		if r.Token.ID != tok || r.Trust.ID != tru {
			t.Fatalf("%s: ids %s %s", name, r.Token.ID, r.Trust.ID)
		}
		check(t, name, r, w)
	}
}

// TestUnimplementedKeys builds the cases of TestUnimplementedKeysInRealTokens
// field by field, with the ones OpenSSL does not make.
func TestUnimplementedKeys(t *testing.T) {
	root := testpki.Root("Root")
	gen := time.Now().Add(-time.Hour)
	trusted := Trust{Roots: []*x509.Certificate{root.Cert}}
	build := func(signer *testpki.Cert, certs ...*x509.Certificate) *jsonv.Value {
		return entry(testpki.BuildToken(testpki.TokenOptions{Digest: p, GenTime: gen, Signer: signer, Certs: certs}))
	}
	okw := want{valid: "true", token: report.Correct, trust: report.Correct}
	tokenMissing := want{valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency,
		trust: report.NotChecked, trustReason: "blocked_by:anchor.tsa.token[0]"}
	trustMissing := want{valid: "null", reason: ReasonNotChecked, token: report.Correct, trust: report.NotChecked, trustReason: ReasonMissingDependency}
	pathFail := want{valid: "false", reason: ReasonVerificationFailed, token: report.Correct, trust: report.Wrong, trustReason: ReasonVerificationFailed}

	// The signer's key: a curve this build lacks, a curve OID assigned to
	// none, explicit parameters and implicitCurve are not decoding
	// failures; a point off a curve it implements is.
	for name, params := range map[string][]byte{
		"brainpoolP256r1":     testpki.OID(testpki.CurveBrainpoolP256r1),
		"an unassigned curve": testpki.OID(testpki.CurveUnassigned),
		"explicit parameters": {0x30, 0x03, 0x02, 0x01, 0x01},
		"implicitCurve":       {0x05, 0x00},
	} {
		signer := testpki.TSASigner("TSA", root)
		signer.Cert = testpki.Reissue(signer, root, testpki.ECKey(signer, params), nil)
		check(t, "signer on "+name, Verify(0, build(signer), p, trusted), tokenMissing)
		// Beside a signer on P-256, the same certificate is examined by no
		// step.
		check(t, "extra certificate on "+name, Verify(0, build(testpki.TSASigner("TSA", root), signer.Cert), p, trusted), okw)
	}
	offCurve := testpki.TSASigner("TSA", root)
	offCurve.Cert = testpki.Reissue(offCurve, root, testpki.OffCurve(offCurve), nil)
	check(t, "signer's point off P-256", Verify(0, build(offCurve), p, trusted), tokenFail(ReasonMalformed))
	check(t, "extra certificate's point off P-256", Verify(0, build(testpki.TSASigner("TSA", root), offCurve.Cert), p, trusted), tokenFail(ReasonMalformed))
	noParams := testpki.TSASigner("TSA", root)
	noParams.Cert = testpki.Reissue(noParams, root, testpki.ECKey(noParams, nil), nil)
	check(t, "an EC key without parameters", Verify(0, build(noParams), p, trusted), tokenFail(ReasonMalformed))

	// An intermediate whose key this build does not implement: its
	// signature on the signer cannot be checked.
	inter := testpki.Intermediate("Unread CA", root, true)
	unread := testpki.Reissue(inter, root, testpki.ECKey(inter, testpki.OID(testpki.CurveBrainpoolP256r1)), nil)
	signer := testpki.TSASigner("TSA", inter)
	check(t, "an intermediate on brainpoolP256r1", Verify(0, build(signer, unread), p, trusted), trustMissing)
	// A valid path decides, whatever other candidates hold (step 5).
	check(t, "a valid path beside an unchecked one", Verify(0, build(signer, unread, inter.Cert), p, trusted), okw)
	check(t, "a valid path beside an unchecked one, the other order", Verify(0, build(signer, inter.Cert, unread), p, trusted), okw)
	// A path that fails a rule step 4 checks without the key is no reason
	// to abstain: the unread intermediate is not a CA.
	notCA := testpki.Intermediate("Unread non-CA", root, false)
	unreadNotCA := testpki.Reissue(notCA, root, testpki.ECKey(notCA, testpki.OID(testpki.CurveBrainpoolP256r1)), nil)
	check(t, "an unread intermediate that is not a CA", Verify(0, build(testpki.TSASigner("TSA", notCA), unreadNotCA), p, trusted), pathFail)
	// A certificate signed with MD5, which crypto/x509 refuses to check:
	// the same, for an intermediate and for the signer.
	md5 := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	md5Inter := testpki.Reissue(inter, root, nil, md5)
	check(t, "an intermediate signed with MD5", Verify(0, build(signer, md5Inter), p, trusted), trustMissing)
	md5Signer := testpki.TSASigner("TSA", root)
	md5Signer.Cert = testpki.Reissue(md5Signer, root, nil, md5)
	check(t, "a signer certificate signed with MD5", Verify(0, build(md5Signer), p, trusted), trustMissing)

	// The CMS signature: an algorithm this build does not implement cannot
	// be checked.
	tsa := testpki.TSASigner("TSA", root)
	for name, oid := range map[string]asn1.ObjectIdentifier{
		"RSASSA-PSS":           {1, 2, 840, 113549, 1, 1, 10},
		"dsa-with-SHA256":      {2, 16, 840, 1, 101, 3, 4, 3, 2},
		"md5WithRSAEncryption": md5,
	} {
		tokn := testpki.BuildToken(testpki.TokenOptions{Digest: p, GenTime: gen, Signer: tsa, SignatureAlgorithm: oid})
		check(t, "a CMS signature by "+name, Verify(0, entry(tokn), p, trusted), tokenMissing)
	}
}

// TestAuthority: the value of the first commonName in encoded order, as the
// attribute holds it, and "" when the subject has none (§10.5 step 4).
func TestAuthority(t *testing.T) {
	root := testpki.Root("Root")
	gen := time.Now().Add(-time.Hour)
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	org := asn1.ObjectIdentifier{2, 5, 4, 10}
	atv := func(typ asn1.ObjectIdentifier, v any) pkix.AttributeTypeAndValue {
		return pkix.AttributeTypeAndValue{Type: typ, Value: v}
	}
	for _, c := range []struct {
		name    string
		subject pkix.RDNSequence
		want    string
	}{
		{"one common name", pkix.RDNSequence{{atv(org, "Org")}, {atv(cn, "TSA")}}, "TSA"},
		{"two common names", pkix.RDNSequence{{atv(cn, "First CN")}, {atv(cn, "Second CN")}}, "First CN"},
		{"a multi-valued RDN", pkix.RDNSequence{{atv(org, "Org"), atv(cn, "Multi CN")}}, "Multi CN"},
		{"characters kept as they are", pkix.RDNSequence{{atv(cn, " Acme, Inc. + \"TSA\" = #1 \\ <x>;\nnext ")}}, " Acme, Inc. + \"TSA\" = #1 \\ <x>;\nnext "},
		{"a BMPString", pkix.RDNSequence{{atv(cn, asn1.RawValue{Tag: asn1.TagBMPString, Bytes: []byte{0, 'Z', 0, 0xfc, 0, 'r'}})}}, "Zür"},
		{"a TeletexString", pkix.RDNSequence{{atv(cn, asn1.RawValue{Tag: asn1.TagT61String, Bytes: []byte{'Z', 0xfc, 'r'}})}}, "Zür"},
		{"an empty common name", pkix.RDNSequence{{atv(org, "Org")}, {atv(cn, "")}}, ""},
		{"no common name", pkix.RDNSequence{{atv(org, "Org")}}, ""},
		{"an empty subject", pkix.RDNSequence{}, ""},
	} {
		signer := testpki.WithName(root, c.subject)
		r := Verify(0, entry(testpki.BuildToken(testpki.TokenOptions{Digest: p, GenTime: gen, Signer: signer})), p, Trust{Roots: []*x509.Certificate{root.Cert}})
		if r.Trust.Outcome != report.Correct {
			t.Errorf("%s: trust %s %q", c.name, r.Trust.Outcome, r.Trust.Reason)
			continue
		}
		v, ok := r.Trust.Fact("authority")
		if !ok || v.S != c.want || r.Authority != c.want {
			t.Errorf("%s: authority %v, want %q", c.name, v, c.want)
		}
	}
}

// TestStepThreeFindingFirst: a requirement of step 3 this build can check,
// and that does not hold, decides step 3, verification_failed, even when
// another requirement needs an algorithm or a key it does not implement;
// missing_dependency only when every requirement it can check holds
// (tzun-anchor/1 §10.5 step 5).
func TestStepThreeFindingFirst(t *testing.T) {
	s := newStepOne(t)
	missing := want{valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency,
		trust: report.NotChecked, trustReason: "blocked_by:anchor.tsa.token[0]"}
	pss := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	data := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	wrong := make([]byte, 32)
	// Signers whose key is left unread at step 1: on brainpoolP256r1.
	unread := func(c *testpki.Cert) *testpki.Cert {
		c.Cert = testpki.Reissue(c, s.root, testpki.ECKey(c, testpki.OID(testpki.CurveBrainpoolP256r1)), nil)
		return c
	}
	now := time.Now()
	unreadTSA := unread(testpki.TSASigner("TSA", s.root))
	unreadTLS := unread(testpki.Signer("TLS", s.root, now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), testpki.EKU(false, testpki.ServerAuth)))
	for _, c := range []struct {
		name string
		o    testpki.TokenOptions
		w    want
	}{
		{"a signatureAlgorithm not implemented", testpki.TokenOptions{SignatureAlgorithm: pss}, missing},
		{"a signatureAlgorithm not implemented, and a message digest that is not the TSTInfo's",
			testpki.TokenOptions{SignatureAlgorithm: pss, MessageDigest: wrong}, vf},
		{"a signatureAlgorithm not implemented, and no signer binding", testpki.TokenOptions{SignatureAlgorithm: pss, Binding: "none"}, vf},
		{"a signatureAlgorithm not implemented, and a content type that is not TSTInfo",
			testpki.TokenOptions{SignatureAlgorithm: pss, ContentType: data}, vf},
		{"a digestAlgorithm not implemented", testpki.TokenOptions{DigestAlgorithm: testpki.SHA3_256}, missing},
		{"a digestAlgorithm not implemented, and a binding to another certificate",
			testpki.TokenOptions{DigestAlgorithm: testpki.SHA3_256, CertHashOf: s.root.Cert}, vf},
		{"a digestAlgorithm not implemented, and a content type that is not TSTInfo",
			testpki.TokenOptions{DigestAlgorithm: testpki.SHA3_256, ContentType: data}, vf},
		{"a digestAlgorithm not implemented, and no content type", testpki.TokenOptions{DigestAlgorithm: testpki.SHA3_256, OmitContentType: true}, vf},
		{"an ESSCertIDv2 hash algorithm not implemented", testpki.TokenOptions{Binding: "v2-unknown"}, missing},
		{"an ESSCertIDv2 hash algorithm not implemented, and a message digest that is not the TSTInfo's",
			testpki.TokenOptions{Binding: "v2-unknown", MessageDigest: wrong}, vf},
		{"an ESSCertIDv2 hash algorithm not implemented, and an issuerSerial naming another serial",
			testpki.TokenOptions{Binding: "v2-unknown", Serial: big.NewInt(7)}, vf},
		{"an ESSCertIDv2 hashAlgorithm of three members", testpki.TokenOptions{Binding: "v2-alg-three"}, vf},
		{"a signer key left unread", testpki.TokenOptions{Signer: unreadTSA}, missing},
		{"a signer key left unread, and not a timestamping certificate", testpki.TokenOptions{Signer: unreadTLS}, vf},
		{"a signer key left unread, and a message digest that is not the TSTInfo's",
			testpki.TokenOptions{Signer: unreadTSA, MessageDigest: wrong}, vf},
		{"a signer key left unread, and no signer binding", testpki.TokenOptions{Signer: unreadTSA, Binding: "none"}, vf},
		{"a signer key left unread, and a digestAlgorithm not implemented",
			testpki.TokenOptions{Signer: unreadTSA, DigestAlgorithm: testpki.SHA3_256}, missing},
	} {
		s.verify(c.name, s.build(c.o), c.w)
	}
	// The signature algorithm, with the hash it names or, for one that
	// names none, the digestAlgorithm's. The signature is ECDSA with
	// SHA-256.
	for _, c := range []struct {
		name string
		alg  asn1.ObjectIdentifier
		w    want
	}{
		{"id-ecPublicKey", asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, okw},
		{"the P-256 curve", asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, okw},
		{"ecdsa-with-SHA384", asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, vf},
		{"sha256WithRSAEncryption", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, vf},
		{"rsaEncryption", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, vf},
		{"Ed25519", asn1.ObjectIdentifier{1, 3, 101, 112}, vf},
		{"ML-DSA-65", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, vf},
		{"md5WithRSAEncryption", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}, missing},
		{"an OBJECT IDENTIFIER assigned to no algorithm", asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 0, 2}, missing},
	} {
		s.verify("signatureAlgorithm "+c.name, s.build(testpki.TokenOptions{SignatureAlgorithm: c.alg}), c.w)
	}
	// A signature this build checks, and that fails, beside a digestAlgorithm
	// it does not implement: the signature names its own hash.
	resp, _, si := tokenParts(t, s.build(testpki.TokenOptions{DigestAlgorithm: testpki.SHA3_256}))
	sig := si.at(5)
	sig.body = append([]byte{}, sig.body...)
	sig.body[len(sig.body)-1] ^= 1
	s.verify("a digestAlgorithm not implemented, and a signature that does not verify", encode(resp), vf)
	// The record's own token reads the same.
	r := VerifyRecordToken(report.S(s.build(testpki.TokenOptions{Signer: unreadTLS})), p, s.trusted)
	if r.Token.Outcome != report.Wrong || r.Token.Reason != ReasonVerificationFailed {
		t.Errorf("the record's token, a signer key left unread and not a timestamping certificate: %s %q", r.Token.Outcome, r.Token.Reason)
	}
}

// TestSignedAttributesAsCarried: the signature is verified over the
// signedAttrs octets the token carries, with only the [0] tag replaced by
// 0x31, never over the attributes encoded again: step 1 does not require
// them in DER SET OF order (RFC 5652 §5.4; tzun-anchor/1 §10.5 step 3).
func TestSignedAttributesAsCarried(t *testing.T) {
	s := newStepOne(t)
	outOfOrder := s.build(testpki.TokenOptions{AttrsOutOfOrder: true})
	_, _, si := tokenParts(t, outOfOrder)
	var carried []string
	for _, a := range si.at(3).kids {
		carried = append(carried, string(a.der()))
	}
	if slices.IsSorted(carried) {
		t.Fatal("the signed attributes are in DER order")
	}
	s.verify("signed attributes out of DER order, signed as carried", outOfOrder, okw)
	s.verify("signed attributes out of DER order, signed in DER order",
		s.build(testpki.TokenOptions{AttrsOutOfOrder: true, SignDEROrder: true}), vf)
	s.verify("signed attributes out of DER order, a binding to another certificate",
		s.build(testpki.TokenOptions{AttrsOutOfOrder: true, CertHashOf: s.root.Cert}), vf)

	// A public authority's token whose signed attributes are reordered after
	// signing no longer verifies: the signature covers the order carried.
	digest, _ := hex.DecodeString(fuzzRealDigest)
	raw, err := os.ReadFile(filepath.Join("testdata", "freetsa.tsr"))
	if err != nil {
		t.Fatal(err)
	}
	resp, _, si := tokenParts(t, base64.StdEncoding.EncodeToString(raw))
	attrs := si.at(3)
	if len(attrs.kids) < 2 {
		t.Fatal("fewer than two signed attributes")
	}
	slices.Reverse(attrs.kids)
	r := VerifyRecordToken(report.S(encode(resp)), digest, Trust{})
	if r.Token.Outcome != report.Wrong || r.Token.Reason != ReasonVerificationFailed {
		t.Errorf("FreeTSA's token, its signed attributes reversed: %s %q", r.Token.Outcome, r.Token.Reason)
	}
}

// TestSignedAttributeCounts: exactly one content-type and one
// message-digest attribute, each with one value, the message digest an
// OCTET STRING; a signingCertificate or a signingCertificateV2, or both,
// neither more than once. The tokens are signed over the attributes they
// carry.
func TestSignedAttributeCounts(t *testing.T) {
	s := newStepOne(t)
	// attrs are content-type, message-digest and the binding, in that order.
	edit := func(f func(attrs [][]byte) [][]byte) string {
		return s.build(testpki.TokenOptions{SignedAttrs: f})
	}
	twice := func(i int) func([][]byte) [][]byte {
		return func(a [][]byte) [][]byte { return append(a, a[i]) }
	}
	// A second value in the SET of attribute i, as built by add.
	values := func(i int, add func(first *node) *node) func([][]byte) [][]byte {
		return func(a [][]byte) [][]byte {
			n := tree(t, a[i])
			n.at(1).add(add(n.at(1, 0)))
			a[i] = n.der()
			return a
		}
	}
	same := func(first *node) *node { return tree(t, first.der()) }
	v1 := func() []byte {
		_, _, si := tokenParts(t, s.build(testpki.TokenOptions{Binding: "v1"}))
		return attributeOf(t, si.at(3), oidSigningCert).der()
	}()
	for _, c := range []struct {
		name string
		tok  string
		w    want
	}{
		{"as built", edit(func(a [][]byte) [][]byte { return a }), okw},
		{"two content-type attributes", edit(twice(0)), vf},
		{"two message-digest attributes", edit(twice(1)), vf},
		{"two signingCertificateV2 attributes", edit(twice(2)), vf},
		{"a content-type attribute of two values", edit(values(0, same)), vf},
		{"a message-digest attribute of two values", edit(values(1, same)), vf},
		{"a message-digest value a [4] holding the digest", edit(func(a [][]byte) [][]byte {
			n := tree(t, a[1])
			n.at(1, 0).class, n.at(1, 0).tag = asn1.ClassContextSpecific, 4
			a[1] = n.der()
			return a
		}), vf},
		{"signingCertificate and signingCertificateV2", edit(func(a [][]byte) [][]byte { return append(a, v1) }), okw},
		{"signingCertificate alone", edit(func(a [][]byte) [][]byte { return append(a[:2], v1) }), okw},
		{"two signingCertificate attributes", edit(func(a [][]byte) [][]byte { return append(a[:2], v1, v1) }), vf},
	} {
		s.verify(c.name, c.tok, c.w)
	}
}
