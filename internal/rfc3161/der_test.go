// SPDX-License-Identifier: BSD-3-Clause-Clear

package rfc3161

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/TzunAI/tzun-verify/internal/report"
	"github.com/TzunAI/tzun-verify/internal/testpki"
)

func unhex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestIsDER: the rules of DER that need no schema, element by element.
func TestIsDER(t *testing.T) {
	gt := func(s string) string { return hex.EncodeToString(append([]byte{0x18, byte(len(s))}, s...)) }
	ut := func(s string) string { return hex.EncodeToString(append([]byte{0x17, byte(len(s))}, s...)) }
	long := "0481 80" + strings.Repeat("41", 0x80)
	for _, c := range []struct {
		name string
		der  string
		ok   bool
	}{
		{"an empty SEQUENCE", "3000", true},
		{"nothing", "", false},
		{"two elements", "0500 0500", false},
		{"an element that runs past its end", "3002 04", false},
		{"a truncated header", "30", false},
		{"the indefinite form", "3080 0500 0000", false},
		{"a long form the short form fits", "0481 01 41", false},
		{"a length with a leading zero octet", "0482 0080" + strings.Repeat("41", 0x80), false},
		{"the long form for 128 octets", long, true},
		{"five length octets", "0485 0100000000", false},
		{"end-of-contents in a SEQUENCE", "3002 0000", false},
		{"a primitive SEQUENCE", "1000", false},
		{"a primitive SET", "1100", false},
		{"a constructed OCTET STRING", "2403 040141", false},
		{"a constructed UTF8String", "2c03 0c0141", false},
		{"a constructed EXTERNAL", "2800", true},
		{"a primitive EXTERNAL", "0800", false},
		{"a constructed EMBEDDED PDV", "2b00", true},
		{"a primitive EMBEDDED PDV", "0b00", false},
		{"a tag below 31 in the high-tag-number form", "9f1e00", false},
		{"a high tag number with a leading zero group", "9f801f00", false},
		{"context tag 31", "9f1f00", true},
		{"a context-specific primitive is not read inside", "8001ff", true},
		{"an OCTET STRING is not read inside", "0403 050100", true},
		{"a universal number X.680 assigns to no type", "3f2500", true},
		{"BOOLEAN FF", "0101ff", true},
		{"BOOLEAN 00", "010100", true},
		{"BOOLEAN 01", "010101", false},
		{"BOOLEAN of two octets", "0102ffff", false},
		{"BOOLEAN of length 6", "0106000000000000", false},
		{"NULL", "0500", true},
		{"NULL with content", "050100", false},
		{"INTEGER 0", "020100", true},
		{"INTEGER 128", "02020080", true},
		{"INTEGER -129", "0202ff7f", true},
		{"an empty INTEGER", "0200", false},
		{"INTEGER with a leading 00", "02020001", false},
		{"INTEGER with a leading FF", "0202ff80", false},
		{"ENUMERATED with a leading 00", "0a020001", false},
		{"an empty BIT STRING", "030100", true},
		{"a BIT STRING with one unused bit, zero", "03020102", true},
		{"a BIT STRING with one unused bit set", "03020101", false},
		{"a BIT STRING of no octets", "0300", false},
		{"a BIT STRING of no bits with unused bits", "030101", false},
		{"a BIT STRING with eight unused bits", "03020800", false},
		{"an OBJECT IDENTIFIER", "06032a8101", true},
		{"an empty OBJECT IDENTIFIER", "0600", false},
		{"an OBJECT IDENTIFIER cut inside a subidentifier", "06022a81", false},
		{"an OBJECT IDENTIFIER with a leading 80", "0603 2a 80 01", false},
		{"an OBJECT IDENTIFIER opening with 80", "0602 80 01", false},
		{"a RELATIVE-OID with a leading 80", "0d02 80 01", false},
		{"UTCTime", ut("261012120000Z"), true},
		{"UTCTime without seconds", ut("2610121200Z"), false},
		{"UTCTime with an offset", ut("261012120000+0000"), false},
		{"UTCTime with a letter among its digits", ut("26101212000AZ"), false},
		{"UTCTime of thirteen digits, without Z", ut("2610121200000"), false},
		{"GeneralizedTime", gt("20261012120000Z"), true},
		{"GeneralizedTime with a fraction", gt("20261012120000.125Z"), true},
		{"GeneralizedTime with a trailing zero", gt("20261012120000.10Z"), false},
		{"GeneralizedTime with an empty fraction", gt("20261012120000.Z"), false},
		{"GeneralizedTime with a comma", gt("20261012120000,5Z"), false},
		{"GeneralizedTime without seconds", gt("202610121200Z"), false},
		{"GeneralizedTime without Z", gt("20261012120000"), false},
		{"GeneralizedTime with a letter among its digits", gt("2026101212000AZ"), false},
		{"GeneralizedTime of fifteen digits, without Z", gt("202610121200000"), false},
		{"GeneralizedTime with a letter in its fraction", gt("20261012120000.1aZ"), false},
		{"a fault two levels down", "3006 3004 0102ffff", false},
		{"a fault after a nested SEQUENCE", "3006 3002 0500 050100", false},
	} {
		if got := isDER(unhex(t, c.der)); got != c.ok {
			t.Errorf("%s: isDER %v, want %v", c.name, got, c.ok)
		}
	}
	// No nesting depth is refused.
	deep := []byte{0x05, 0x00}
	for i := 0; i < 10000; i++ {
		var err error
		if deep, err = asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: deep}); err != nil {
			t.Fatal(err)
		}
	}
	if !isDER(deep) {
		t.Error("10000 nested SEQUENCEs")
	}
}

// node is a DER element held as a tree, so that a test can change one
// element of a token and encode the token again around it.
type node struct {
	class, tag int
	compound   bool
	kids       []*node
	body       []byte // the contents of a primitive element
	raw        []byte // when set, the whole encoding, written as it is
}

func tree(t *testing.T, der []byte) *node {
	t.Helper()
	var v asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &v); err != nil || len(rest) != 0 {
		t.Fatalf("tree: %v", err)
	}
	n := &node{class: v.Class, tag: v.Tag, compound: v.IsCompound}
	if !v.IsCompound {
		n.body = v.Bytes
		return n
	}
	for b := v.Bytes; len(b) > 0; {
		var c asn1.RawValue
		var err error
		if b, err = asn1.Unmarshal(b, &c); err != nil {
			t.Fatalf("tree: %v", err)
		}
		n.kids = append(n.kids, tree(t, c.FullBytes))
	}
	return n
}

func (n *node) der() []byte {
	if n.raw != nil {
		return n.raw
	}
	body := n.body
	if n.compound {
		body = nil
		for _, k := range n.kids {
			body = append(body, k.der()...)
		}
	}
	out, err := asn1.Marshal(asn1.RawValue{Class: n.class, Tag: n.tag, IsCompound: n.compound, Bytes: body})
	if err != nil {
		panic(err)
	}
	return out
}

func (n *node) at(path ...int) *node {
	for _, i := range path {
		n = n.kids[i]
	}
	return n
}

func (n *node) add(kids ...*node) { n.kids = append(n.kids, kids...) }

func raw(t *testing.T, h string) *node { return &node{raw: unhex(t, h)} }

func null() *node { return &node{tag: asn1.TagNull} }

// tokenParts returns the tree of a built token, and in it the SignedData and
// the SignerInfo.
func tokenParts(t *testing.T, tok string) (resp, sd, si *node) {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(tok)
	if err != nil {
		t.Fatal(err)
	}
	resp = tree(t, der)
	sd = resp.at(1, 1, 0)
	si = sd.kids[len(sd.kids)-1].at(0)
	return resp, sd, si
}

func encode(n *node) string { return base64.StdEncoding.EncodeToString(n.der()) }

// attributeOf returns the attribute of the given type among signedAttrs.
func attributeOf(t *testing.T, attrs *node, oid asn1.ObjectIdentifier) *node {
	t.Helper()
	for _, a := range attrs.kids {
		var typ asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(a.kids[0].der(), &typ); err == nil && typ.Equal(oid) {
			return a
		}
	}
	t.Fatalf("no attribute %v", oid)
	return nil
}

// TestStepOneStrictness: §10.5 step 1 reads the token as the DER of a
// TimeStampResp that is a CMS SignedData, every one of whose certificates
// decodes as an X.509 certificate. Every element of the response is DER by
// the rules that need no schema, wherever it sits; each structure has its
// members and nothing else. A token that breaks either is malformed at
// step 1, before a later step looks at it, and whether or not the signature
// covers the element.
func TestStepOneStrictness(t *testing.T) {
	root := testpki.Root("Root")
	signer := testpki.TSASigner("TSA", root)
	gen := time.Now().Add(-time.Hour)
	trusted := Trust{Roots: []*x509.Certificate{root.Cert}}
	build := func(o testpki.TokenOptions) string {
		o.Digest, o.GenTime = p, gen
		if o.Signer == nil {
			o.Signer = signer
		}
		return testpki.BuildToken(o)
	}
	good := build(testpki.TokenOptions{})
	okw := want{valid: "true", token: report.Correct, trust: report.Correct}
	mf := tokenFail(ReasonMalformed)
	vf := tokenFail(ReasonVerificationFailed)
	tokenMissing := want{valid: "null", reason: ReasonNotChecked, token: report.NotChecked, tokenReason: ReasonMissingDependency,
		trust: report.NotChecked, trustReason: "blocked_by:anchor.tsa.token[0]"}
	verify := func(name, tok string, w want) {
		t.Helper()
		check(t, name, Verify(0, entry(tok), p, trusted), w)
	}

	resp, _, _ := tokenParts(t, good)
	if encode(resp) != good {
		t.Fatal("the tree does not encode the token again")
	}
	verify("the token as built", good, okw)

	// Unsigned attributes, which the signature does not cover: the attribute
	// type is 1.2.3.4, and its one value an OCTET STRING.
	unsigned := func(tok string, attrs ...string) string {
		resp, _, si := tokenParts(t, tok)
		u := &node{class: asn1.ClassContextSpecific, tag: 1, compound: true}
		for _, a := range attrs {
			u.add(raw(t, a))
		}
		si.add(u)
		return encode(resp)
	}
	for _, c := range []struct {
		name, attr string
		w          want
	}{
		{"a DER unsigned attribute", "300a 0603 2a0304 3103 040141", okw},
		{"a non-minimal length inside attrValues", "300b 0603 2a0304 3104 04810141", mf},
		{"an indefinite length inside attrValues", "300c 0603 2a0304 3180 040141 0000", mf},
		{"a NULL with content inside attrValues", "300a 0603 2a0304 3103 050100", mf},
		{"a non-minimal length on the attribute's SEQUENCE", "30810a 0603 2a0304 3103 040141", mf},
		{"attrValues a SEQUENCE", "300a 0603 2a0304 3003 040141", mf},
		{"a member after attrValues", "300c 0603 2a0304 3103 040141 0500", mf},
	} {
		verify("unsigned attribute: "+c.name, unsigned(good, c.attr), c.w)
	}
	// The record's own token reads the same, malformed_token.
	r := VerifyRecordToken(report.S(unsigned(good, "300a 0603 2a0304 3103 050100")), p, trusted)
	if r.Token.ID != IDRecordToken || r.Token.Outcome != report.Wrong || r.Token.Reason != ReasonMalformedToken ||
		r.Trust.Reason != "blocked_by:"+IDRecordToken {
		t.Errorf("record token, unsigned NULL with content: %s %s %q, trust %q", r.Token.ID, r.Token.Outcome, r.Token.Reason, r.Trust.Reason)
	}

	// Signed attributes: the change also breaks the signature, which step 3
	// would find; step 1 decides first.
	signed := func(oid asn1.ObjectIdentifier, edit func(a *node)) string {
		resp, _, si := tokenParts(t, good)
		edit(attributeOf(t, si.kids[3], oid))
		return encode(resp)
	}
	verify("message-digest attrValues a SEQUENCE", signed(oidMessageDigest, func(a *node) { a.kids[1].tag = asn1.TagSequence }), mf)
	verify("message-digest value a NULL with content", signed(oidMessageDigest, func(a *node) { a.at(1, 0).tag = asn1.TagNull }), mf)
	verify("content-type with a member after attrValues", signed(oidContentType, func(a *node) { a.add(null()) }), mf)
	// SigningCertificateV2 { certs { ESSCertIDv2 { certHash, issuerSerial { issuer, serialNumber } } } }
	certID := func(a *node) *node { return a.at(1, 0, 0, 0) }
	verify("certHash a NULL with content", signed(oidSigningCertV2, func(a *node) { certID(a).kids[0].tag = asn1.TagNull }), mf)
	verify("issuerSerial's serial a BIT STRING that is not DER", signed(oidSigningCertV2, func(a *node) {
		s := certID(a).at(1, 1)
		s.tag, s.body = asn1.TagBitString, []byte{0x07, 0x01} // seven unused bits, one of them set
	}), mf)
	// A DER BIT STRING there is DER: what the value means is step 3's to
	// judge (the signer binding), and the signature fails there too.
	verify("issuerSerial's serial a DER BIT STRING", signed(oidSigningCertV2, func(a *node) {
		s := certID(a).at(1, 1)
		s.tag, s.body = asn1.TagBitString, []byte{0x00, 0x01}
	}), vf)

	// The members of each CMS structure, and nothing after them.
	cms := func(edit func(resp, sd, si *node)) string {
		resp, sd, si := tokenParts(t, good)
		edit(resp, sd, si)
		return encode(resp)
	}
	twoMore := func(n *node) { n.add(null(), null()) } // an AlgorithmIdentifier's third and fourth members
	for name, edit := range map[string]func(resp, sd, si *node){
		"TimeStampResp, a member after timeStampToken":        func(resp, _, _ *node) { resp.add(null()) },
		"ContentInfo, a member after content":                 func(resp, _, _ *node) { resp.at(1).add(null()) },
		"SignedData, a member after signerInfos":              func(_, sd, _ *node) { sd.add(null()) },
		"digestAlgorithms, an AlgorithmIdentifier of three":   func(_, sd, _ *node) { twoMore(sd.at(1, 0)) },
		"EncapsulatedContentInfo, a member after eContent":    func(_, sd, _ *node) { sd.at(2).add(null()) },
		"SignerInfo, a member after signature":                func(_, _, si *node) { si.add(null()) },
		"sid, a member after serialNumber":                    func(_, _, si *node) { si.at(1).add(null()) },
		"SignerInfo, a digestAlgorithm of three members":      func(_, _, si *node) { twoMore(si.at(2)) },
		"SignerInfo, a signatureAlgorithm of three members":   func(_, _, si *node) { twoMore(si.at(4)) },
		"SignerInfo, a SEQUENCE where unsignedAttrs [1] sits": func(_, _, si *node) { si.add(&node{tag: asn1.TagSequence, compound: true}) },
		"SignerInfo, signedAttrs [0] holding a non-attribute": func(_, _, si *node) { si.at(3).add(null()) },
	} {
		verify(name, cms(edit), mf)
	}

	// The certificates, each an RFC 5280 certificate. The signer's key: a
	// BOOLEAN of length 6 is not DER, whatever the algorithm, and an
	// AlgorithmIdentifier has at most one parameters element.
	reissued := func(spki func(s *testpki.Cert) []byte) string {
		s := testpki.TSASigner("TSA", root)
		s.Cert = testpki.Reissue(s, root, spki(s), nil)
		return build(testpki.TokenOptions{Signer: s})
	}
	point := func(s *testpki.Cert) []byte {
		b, err := s.Key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	p256 := testpki.OID(testpki.CurveP256)
	boolean6 := []byte{0x01, 0x06, 0, 0, 0, 0, 0, 0}
	unknownKey := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 0, 1}
	verify("the signer's key: P-256, then a BOOLEAN of length 6",
		reissued(func(s *testpki.Cert) []byte { return testpki.ECKey(s, append(append([]byte{}, p256...), boolean6...)) }), mf)
	verify("the signer's key: P-256, then a NULL",
		reissued(func(s *testpki.Cert) []byte { return testpki.ECKey(s, append(append([]byte{}, p256...), 0x05, 0x00)) }), mf)
	verify("the signer's key: an algorithm this build does not know, a BOOLEAN of length 6 as its parameters",
		reissued(func(s *testpki.Cert) []byte { return testpki.SPKI(unknownKey, boolean6, point(s)) }), mf)
	// Read with its key left unread, as step 1 has it.
	verify("the signer's key: an algorithm this build does not know, NULL as its parameters",
		reissued(func(s *testpki.Cert) []byte { return testpki.SPKI(unknownKey, []byte{0x05, 0x00}, point(s)) }), tokenMissing)

	// The signer's tbsCertificate after its subjectPublicKeyInfo:
	// issuerUniqueID [1] and subjectUniqueID [2], each a primitive BIT
	// STRING, then extensions [3], then nothing.
	rebuilt := func(edit func(f [][]byte) [][]byte) string {
		s := testpki.TSASigner("TSA", root)
		s.Cert = testpki.Rebuild(s, root, edit)
		return build(testpki.TokenOptions{Signer: s})
	}
	const exts = 7 // version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, extensions
	uniqueIDs := func(ids ...string) func(f [][]byte) [][]byte {
		return func(f [][]byte) [][]byte {
			var out [][]byte
			out = append(out, f[:exts]...)
			for _, id := range ids {
				out = append(out, unhex(t, id))
			}
			return append(out, f[exts:]...)
		}
	}
	verify("the signer with issuerUniqueID and subjectUniqueID", rebuilt(uniqueIDs("81020001", "82020001")), okw)
	verify("the signer's extensions under [2]", rebuilt(func(f [][]byte) [][]byte {
		f[exts] = append([]byte{0xa2}, f[exts][1:]...)
		return f
	}), mf)
	verify("the signer's issuerUniqueID constructed", rebuilt(uniqueIDs("a1020500")), mf)
	verify("the signer's tbsCertificate, a member after extensions", rebuilt(func(f [][]byte) [][]byte {
		return append(f, []byte{0x05, 0x00})
	}), mf)

	// A certificate no step needs: step 1 reads it, and no later step does.
	extra := testpki.Root("Extra")
	carried := func(edit func(c, tbs *node)) string {
		c := tree(t, extra.Cert.Raw)
		edit(c, c.at(0))
		return build(testpki.TokenOptions{Certs: []*x509.Certificate{{Raw: c.der()}}})
	}
	verify("an extra certificate as issued", carried(func(c, _ *node) {
		if !bytes.Equal(c.der(), extra.Cert.Raw) {
			t.Fatal("the tree does not encode the certificate again")
		}
	}), okw)
	// tbsCertificate: version [0], serialNumber, signature, issuer, validity,
	// subject, subjectPublicKeyInfo, extensions [3].
	for name, edit := range map[string]func(c, tbs *node){
		"a member after signatureValue":                         func(c, _ *node) { c.add(null()) },
		"a member after extensions":                             func(_, tbs *node) { tbs.add(null()) },
		"extensions [3] holding a second element":               func(_, tbs *node) { tbs.at(7).add(null()) },
		"an extension with a member after its value":            func(_, tbs *node) { tbs.at(7, 0, 0).add(null()) },
		"a validity of three times":                             func(_, tbs *node) { v := tbs.at(4); v.add(&node{tag: v.kids[1].tag, body: v.kids[1].body}) },
		"an issuer attribute with a second value":               func(_, tbs *node) { tbs.at(3, 0, 0).add(raw(t, "0c0141")) },
		"a subject attribute with a second value":               func(_, tbs *node) { tbs.at(5, 0, 0).add(raw(t, "0c0141")) },
		"subjectPublicKeyInfo, a member after subjectPublicKey": func(_, tbs *node) { tbs.at(6).add(null()) },
		"both signature AlgorithmIdentifiers of three members":  func(c, tbs *node) { twoMore(c.at(1)); twoMore(tbs.at(2)) },
	} {
		verify("an extra certificate, "+name, carried(edit), mf)
	}

	// A signer named by subjectKeyIdentifier is this build's abstention
	// (step 5) only for a token that step 1 otherwise reads.
	now := time.Now()
	skiExt := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: []byte{0x04, 0x04, 1, 2, 3, 4}}
	skiSigner := testpki.Signer("SKI TSA", root, now.AddDate(-5, 0, 0), now.AddDate(5, 0, 0), testpki.EKU(true, testpki.TimeStamping), skiExt)
	ski := build(testpki.TokenOptions{Signer: skiSigner, SKISid: true})
	verify("signer named by subjectKeyIdentifier", ski, tokenMissing)
	verify("signer named by subjectKeyIdentifier, an unsigned attribute not DER", unsigned(ski, "300a 0603 2a0304 3103 050100"), mf)
	verify("signer named by subjectKeyIdentifier, attrValues a SEQUENCE", unsigned(ski, "300a 0603 2a0304 3003 040141"), mf)
}
