// SPDX-License-Identifier: BSD-3-Clause-Clear

package rfc3161

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"slices"
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

// TestIsDER: the header, form and contents isDER checks, element by element.
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
		{"a constructed CHARACTER STRING", "3d00", true},
		{"a primitive CHARACTER STRING", "1d00", false},
		{"a tag below 31 in the high-tag-number form", "9f1e00", false},
		{"a high tag number with a leading zero group", "9f801f00", false},
		{"context tag 31", "9f1f00", true},
		{"a context-specific primitive is not read inside", "8001ff", true},
		{"an OCTET STRING is not read inside", "0403 050100", true},
		{"a universal number X.680 assigns to no type", "3f2500", true},
		{"a constructed reserved universal 15", "2f00", true},
		{"a primitive OID-IRI", "1f2300", true},
		{"a constructed OID-IRI", "3f2300", false},
		{"a primitive RELATIVE-OID-IRI", "1f2400", true},
		{"a constructed RELATIVE-OID-IRI", "3f2400", false},
		{"a constructed TIME", "2e00", false},
		{"a constructed DATE", "3f1f00", false},
		{"a constructed DURATION", "3f2200", false},
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

	// The decoder bounds: constructed elements, of any class, nest at most
	// 64 deep, the outermost at depth 1, and an encoding holds at most
	// 100,000 elements, the outermost included. What lies inside the
	// contents of a primitive element counts toward neither.
	for _, c := range []struct {
		name string
		der  []byte
		ok   bool
	}{
		{"64 nested SEQUENCEs", nested(64, asn1.ClassUniversal, nil), true},
		{"65 nested SEQUENCEs", nested(65, asn1.ClassUniversal, nil), false},
		{"64 nested SEQUENCEs around a NULL", nested(64, asn1.ClassUniversal, []byte{0x05, 0x00}), true},
		{"64 nested [0]", nested(64, asn1.ClassContextSpecific, nil), true},
		{"65 nested [0]", nested(65, asn1.ClassContextSpecific, nil), false},
		{"63 nested SEQUENCEs around a [0]", nested(63, asn1.ClassUniversal, []byte{0xa0, 0x00}), true},
		{"64 nested SEQUENCEs around a [0]", nested(64, asn1.ClassUniversal, []byte{0xa0, 0x00}), false},
		{"64 nested SEQUENCEs around an OCTET STRING holding 64 more",
			nested(64, asn1.ClassUniversal, octets(nested(64, asn1.ClassUniversal, nil))), true},
		{"a SEQUENCE of 99,999 NULLs", nulls(99999), true},
		{"a SEQUENCE of 100,000 NULLs", nulls(100000), false},
		{"a SEQUENCE of 99,998 NULLs and an OCTET STRING holding 1,000 more",
			sequence(append(bytes.Repeat([]byte{0x05, 0x00}, 99998), octets(nulls(1000))...)), true},
	} {
		if got := isDER(c.der); got != c.ok {
			t.Errorf("%s: isDER %v, want %v", c.name, got, c.ok)
		}
		if elems, depth := shape(t, c.der); c.ok != (elems <= 100000 && depth <= 64) {
			t.Errorf("%s: %d elements, %d deep", c.name, elems, depth)
		}
	}
}

// nested is n constructed elements of the given class (a SEQUENCE when
// universal, a [0] otherwise), each inside the next, around inner.
func nested(n, class int, inner []byte) []byte {
	b := inner
	tag := asn1.TagSequence
	if class != asn1.ClassUniversal {
		tag = 0
	}
	for i := 0; i < n; i++ {
		var err error
		if b, err = asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: b}); err != nil {
			panic(err)
		}
	}
	return b
}

func sequence(body []byte) []byte {
	b, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	if err != nil {
		panic(err)
	}
	return b
}

func octets(body []byte) []byte {
	b, err := asn1.Marshal(body)
	if err != nil {
		panic(err)
	}
	return b
}

// nulls is a SEQUENCE of n NULLs: n+1 elements.
func nulls(n int) []byte { return sequence(bytes.Repeat([]byte{0x05, 0x00}, n)) }

// shape counts, by encoding/asn1 rather than by isDER, the elements of an
// encoding that are not inside the contents of a primitive element, and the
// depth of the deepest constructed one, the outermost at depth 1.
func shape(t *testing.T, der []byte) (elements, depth int) {
	t.Helper()
	var walk func(b []byte, d int)
	walk = func(b []byte, d int) {
		for len(b) > 0 {
			var v asn1.RawValue
			rest, err := asn1.Unmarshal(b, &v)
			if err != nil {
				t.Fatalf("shape: %v", err)
			}
			elements++
			if v.IsCompound {
				depth = max(depth, d)
				walk(v.Bytes, d+1)
			}
			b = rest
		}
	}
	walk(der, 1)
	return elements, depth
}

// tlv is the hex of one element whose first octet is tag, around contents
// given as hex, with a length in the short form.
func tlv(tag byte, contents ...string) string {
	body := strings.ReplaceAll(strings.Join(contents, ""), " ", "")
	if len(body)%2 != 0 || len(body)/2 > 127 {
		panic("tlv: " + body)
	}
	return hex.EncodeToString([]byte{tag, byte(len(body) / 2)}) + body
}

// gtime is the hex of a GeneralizedTime, utime of a UTCTime.
func gtime(s string) string { return tlv(0x18, hex.EncodeToString([]byte(s))) }

func utime(s string) string { return tlv(0x17, hex.EncodeToString([]byte(s))) }

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
// decodes as an X.509 certificate. Every element of the response, wherever
// it sits, has the header, form and contents isDER checks; each structure
// has its members and nothing else. A token that breaks either is
// malformed at step 1, before a later step looks at it, and whether or not
// the signature covers the element.
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
	// A BIT STRING with DER contents there passes isDER: what the value
	// means is step 3's to judge (the signer binding), and the signature
	// fails there too.
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
	// crls [1] sits after certificates [0] and before signerInfos. The
	// signature does not cover it.
	crls := func(at int, h string) string {
		return cms(func(_, sd, _ *node) {
			if len(sd.kids) != 5 || !(sd.kids[3].class == asn1.ClassContextSpecific && sd.kids[3].tag == 0) {
				t.Fatal("the SignedData is not version, digestAlgorithms, encapContentInfo, certificates, signerInfos")
			}
			sd.kids = slices.Insert(sd.kids, at, raw(t, h))
		})
	}
	after, before, primitive := crls(4, "a100"), crls(3, "a100"), crls(4, "8100")
	verify("SignedData, an empty crls [1] after certificates", after, okw)
	verify("SignedData, an empty crls [1] before certificates", before, mf)
	verify("SignedData, a primitive crls [1] after certificates", primitive, mf)
	// tokenShape decides each, not isDER or the CMS decoder.
	for _, c := range []struct {
		name, tok string
		ok        bool
	}{{"after certificates", after, true}, {"before certificates", before, false}, {"primitive", primitive, false}} {
		der, err := base64.StdEncoding.DecodeString(c.tok)
		if err != nil || !isDER(der) {
			t.Fatalf("crls [1] %s: not DER (%v)", c.name, err)
		}
		if got := tokenShape(der); got != c.ok {
			t.Errorf("crls [1] %s: tokenShape %v, want %v", c.name, got, c.ok)
		}
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
	// Each at most once, in this order, in this form; nothing else
	// (tzun-anchor/1 §10.5 step 1).
	verify("the signer with subjectUniqueID alone", rebuilt(uniqueIDs("82020001")), okw)
	verify("the signer's subjectUniqueID before its issuerUniqueID", rebuilt(uniqueIDs("82020001", "81020001")), mf)
	verify("the signer with two issuerUniqueIDs", rebuilt(uniqueIDs("81020001", "81020001")), mf)
	verify("the signer's subjectUniqueID constructed", rebuilt(uniqueIDs("a2020500")), mf)
	verify("the signer's tbsCertificate, a [4] after subjectPublicKeyInfo", rebuilt(uniqueIDs("84020001")), mf)
	verify("the signer's tbsCertificate, an issuerUniqueID after extensions", rebuilt(func(f [][]byte) [][]byte {
		return append(f, unhex(t, "81020001"))
	}), mf)
	verify("the signer's tbsCertificate, two extensions [3]", rebuilt(func(f [][]byte) [][]byte {
		return append(f, f[exts])
	}), mf)
	verify("the signer's extensions [3] primitive", rebuilt(func(f [][]byte) [][]byte {
		f[exts] = append([]byte{0x83}, f[exts][1:]...)
		return f
	}), mf)
	verify("the signer's extensions [3] holding a SET", rebuilt(func(f [][]byte) [][]byte {
		e := tree(t, f[exts])
		e.at(0).tag = asn1.TagSet
		f[exts] = e.der()
		return f
	}), mf)
	verify("the signer's extensions [3] empty", rebuilt(func(f [][]byte) [][]byte {
		f[exts] = []byte{0xa3, 0x00}
		return f
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

	// A signer named by subjectKeyIdentifier, read as one named by issuer
	// and serial number is.
	now := time.Now()
	skiExt := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: []byte{0x04, 0x04, 1, 2, 3, 4}}
	skiSigner := testpki.Signer("SKI TSA", root, now.AddDate(-5, 0, 0), now.AddDate(5, 0, 0), testpki.EKU(true, testpki.TimeStamping), skiExt)
	ski := build(testpki.TokenOptions{Signer: skiSigner, SKISid: true})
	verify("signer named by subjectKeyIdentifier", ski, okw)
	verify("signer named by subjectKeyIdentifier, an unsigned attribute not DER", unsigned(ski, "300a 0603 2a0304 3103 050100"), mf)
	verify("signer named by subjectKeyIdentifier, attrValues a SEQUENCE", unsigned(ski, "300a 0603 2a0304 3003 040141"), mf)
	resp, _, si := tokenParts(t, ski)
	si.at(1).tag = 1 // [1], a form RFC 5652 §5.3 does not have
	verify("sid a primitive [1]", encode(resp), mf)
	resp, _, si = tokenParts(t, ski)
	si.at(1).compound, si.at(1).kids = true, []*node{{tag: asn1.TagOctetString, body: si.at(1).body}}
	verify("sid a constructed [0]", encode(resp), mf)
}

// stepOne is the setting of the step 1 tests: a root, a timestamping
// signer under it, and the outcomes they expect.
type stepOne struct {
	t       *testing.T
	root    *testpki.Cert
	signer  *testpki.Cert
	gen     time.Time
	trusted Trust
}

func newStepOne(t *testing.T) *stepOne {
	root := testpki.Root("Root")
	return &stepOne{t: t, root: root, signer: testpki.TSASigner("TSA", root), gen: time.Now().Add(-time.Hour),
		trusted: Trust{Roots: []*x509.Certificate{root.Cert}}}
}

func (s *stepOne) build(o testpki.TokenOptions) string {
	o.Digest = p
	if o.GenTime.IsZero() {
		o.GenTime = s.gen
	}
	if o.Signer == nil {
		o.Signer = s.signer
	}
	return testpki.BuildToken(o)
}

func (s *stepOne) verify(name, tok string, w want) Result {
	s.t.Helper()
	r := Verify(0, entry(tok), p, s.trusted)
	check(s.t, name, r, w)
	return r
}

// extra returns a token that also carries the root "Extra", its
// certificate as edit leaves its tree: a certificate no step after step 1
// needs, so its signature is never checked.
func (s *stepOne) extra(edit func(c, tbs *node)) string {
	extra := testpki.Root("Extra")
	c := tree(s.t, extra.Cert.Raw)
	edit(c, c.at(0))
	return s.build(testpki.TokenOptions{Certs: []*x509.Certificate{{Raw: c.der()}}})
}

var (
	okw         = want{valid: "true", token: report.Correct, trust: report.Correct}
	mf          = tokenFail(ReasonMalformed)
	vf          = tokenFail(ReasonVerificationFailed)
	tokenOKOnly = want{valid: "false", reason: ReasonVerificationFailed, token: report.Correct, trust: report.Wrong, trustReason: ReasonVerificationFailed}
)

// TestDecoderBoundsInTokens: the bounds of step 1 on each encoding they
// apply to, the TimeStampResp, the TSTInfo and a typed extension's value,
// each counted on its own: exactly 64 levels and exactly 100,000 elements
// pass, one more does not (malformed_publication, and malformed_token for
// the record's token).
func TestDecoderBoundsInTokens(t *testing.T) {
	s := newStepOne(t)
	good := s.build(testpki.TokenOptions{})

	// In the TimeStampResp: an unsigned attribute, which the signature does
	// not cover, whose value is what grows.
	unsigned := func(value []byte) string {
		resp, _, si := tokenParts(t, good)
		attr := &node{tag: asn1.TagSequence, compound: true}
		attr.add(raw(t, "06032a0304"), &node{tag: asn1.TagSet, compound: true, kids: []*node{{raw: value}}})
		si.add(&node{class: asn1.ClassContextSpecific, tag: 1, compound: true, kids: []*node{attr}})
		return encode(resp)
	}
	respShape := func(tok string) (int, int) {
		der, err := base64.StdEncoding.DecodeString(tok)
		if err != nil {
			t.Fatal(err)
		}
		return shape(t, der)
	}
	// Twenty nested SEQUENCEs reach deeper than anything else in the token.
	_, d20 := respShape(unsigned(nested(20, asn1.ClassUniversal, nil)))
	deep := 64 - d20 + 20 // nested SEQUENCEs that put the deepest at 64
	e0, _ := respShape(unsigned(nulls(0)))
	wide := 100000 - e0 // NULLs that make 100,000 elements
	for _, c := range []struct {
		name   string
		value  []byte
		elems  int
		depth  int
		result want
	}{
		{"the TimeStampResp 64 deep", nested(deep, asn1.ClassUniversal, nil), 0, 64, okw},
		{"the TimeStampResp 65 deep", nested(deep+1, asn1.ClassUniversal, nil), 0, 65, mf},
		{"the TimeStampResp of 100,000 elements", nulls(wide), 100000, 0, okw},
		{"the TimeStampResp of 100,001 elements", nulls(wide + 1), 100001, 0, mf},
	} {
		tok := unsigned(c.value)
		elems, depth := respShape(tok)
		if c.elems != 0 && elems != c.elems || c.depth != 0 && depth != c.depth {
			t.Fatalf("%s: %d elements, %d deep", c.name, elems, depth)
		}
		s.verify(c.name, tok, c.result)
		if c.result == mf {
			if r := VerifyRecordToken(report.S(tok), p, s.trusted); r.Token.Reason != ReasonMalformedToken {
				t.Errorf("%s, the record's token: %s %q", c.name, r.Token.Outcome, r.Token.Reason)
			}
		}
	}

	// In the TSTInfo, counted on its own: a tsa [0] holding a directoryName
	// [4], whose contents step 1 does not read but does bound. The TSTInfo
	// is changed after signing, so a TSTInfo within the bounds passes step
	// 1 and fails step 3.
	tsa := func(inner []byte) (string, []byte) {
		resp, sd, _ := tokenParts(t, good)
		oct := sd.at(2, 1, 0)
		tst := tree(t, oct.body)
		dn := &node{class: asn1.ClassContextSpecific, tag: 4, compound: true, kids: []*node{{raw: inner}}}
		tst.add(&node{class: asn1.ClassContextSpecific, tag: 0, compound: true, kids: []*node{dn}})
		oct.body = tst.der()
		return encode(resp), oct.body
	}
	_, tstInfo := tsa(nested(20, asn1.ClassUniversal, nil))
	_, d20 = shape(t, tstInfo)
	deep = 64 - d20 + 20
	_, tstInfo = tsa(nulls(0))
	e0, _ = shape(t, tstInfo)
	wide = 100000 - e0
	for _, c := range []struct {
		name   string
		inner  []byte
		elems  int
		depth  int
		result want
	}{
		{"the TSTInfo 64 deep", nested(deep, asn1.ClassUniversal, nil), 0, 64, vf},
		{"the TSTInfo 65 deep", nested(deep+1, asn1.ClassUniversal, nil), 0, 65, mf},
		{"the TSTInfo of 100,000 elements", nulls(wide), 100000, 0, vf},
		{"the TSTInfo of 100,001 elements", nulls(wide + 1), 100001, 0, mf},
	} {
		tok, tstInfo := tsa(c.inner)
		elems, depth := shape(t, tstInfo)
		if c.elems != 0 && elems != c.elems || c.depth != 0 && depth != c.depth {
			t.Fatalf("%s: %d elements, %d deep", c.name, elems, depth)
		}
		s.verify(c.name, tok, c.result)
	}

	// In the value of a typed extension, counted on its own: an
	// authorityKeyIdentifier, a SEQUENCE whose members past keyIdentifier
	// crypto/x509 does not read, on a carried certificate no later step
	// needs.
	aki := func(value []byte) string {
		return s.extra(func(_, tbs *node) { setExtension(t, tbs, oidAKI, value) })
	}
	for _, c := range []struct {
		name   string
		value  []byte
		result want
	}{
		{"an authorityKeyIdentifier 64 deep", nested(64, asn1.ClassUniversal, nil), okw},
		{"an authorityKeyIdentifier 65 deep", nested(65, asn1.ClassUniversal, nil), mf},
		{"an authorityKeyIdentifier of 100,000 elements", nulls(99999), okw},
		{"an authorityKeyIdentifier of 100,001 elements", nulls(100000), mf},
	} {
		s.verify(c.name, aki(c.value), c.result)
	}
}

var oidAKI = asn1.ObjectIdentifier{2, 5, 29, 35}

// setExtension gives a tbsCertificate's extensions the extension of the
// given type with value as its extnValue's contents, in place of any it
// has, as the last.
func setExtension(t *testing.T, tbs *node, id asn1.ObjectIdentifier, value []byte) {
	t.Helper()
	var exts *node
	for _, f := range tbs.kids {
		if f.class == asn1.ClassContextSpecific && f.tag == 3 {
			exts = f.at(0)
		}
	}
	if exts == nil {
		t.Fatal("no extensions [3]")
	}
	der, err := asn1.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	kept := exts.kids[:0]
	for _, e := range exts.kids {
		if !bytes.Equal(e.at(0).der(), der) {
			kept = append(kept, e)
		}
	}
	ext := &node{tag: asn1.TagSequence, compound: true}
	ext.add(&node{raw: der}, &node{tag: asn1.TagOctetString, body: value})
	exts.kids = append(kept, ext)
}

// TestTSTInfo: the TSTInfo decodes whole by RFC 3161 §2.4.2, as step 1
// states it: its five members, then accuracy, ordering, nonce, tsa and
// extensions, each when present and in that order, and nothing else, with
// the forms and ranges step 1 gives each. The tokens are signed over the
// TSTInfo they carry, so one step 1 accepts verifies.
func TestTSTInfo(t *testing.T) {
	s := newStepOne(t)
	tst := func(edit func(m [][]byte) [][]byte) string { return s.build(testpki.TokenOptions{TSTInfo: edit}) }
	with := func(members ...string) string {
		return tst(func(m [][]byte) [][]byte {
			for _, e := range members {
				m = append(m, unhex(t, e))
			}
			return m
		})
	}
	set := func(i int, member string) func(m [][]byte) [][]byte {
		return func(m [][]byte) [][]byte {
			m[i] = unhex(t, member)
			return m
		}
	}
	const (
		accuracy   = "300a 020101 800101 810203e7" // seconds 1, millis 1, micros 999
		ordering   = "010100"
		nonce      = "0208 0102030405060708"
		tsaName    = "a004 a402 3000" // a directoryName, its Name empty
		extensions = "a10b 3009 06032a0304 04020500"
	)
	sha256 := "300d 0609 608648016503040201 0500"
	imprint := func(alg string, rest ...string) string {
		return tlv(0x30, append([]string{alg, tlv(0x04, hex.EncodeToString(p))}, rest...)...)
	}
	for _, c := range []struct {
		name string
		tok  string
		w    want
	}{
		{"the five members", with(), okw},
		{"every member", with(accuracy, ordering, nonce, tsaName, extensions), okw},
		{"ordering TRUE alone", with("0101ff"), okw},
		{"a version of nine octets", tst(set(0, "0209 010000000000000000")), okw},
		{"a negative version", tst(set(0, "0201 ff")), okw},
		{"a serialNumber of 21 octets", tst(set(3, "0215 01"+strings.Repeat("00", 20))), okw},
		{"accuracy seconds of nine octets", with("300b 0209 010000000000000000"), okw},
		{"accuracy empty", with("3000"), okw},
		{"accuracy millis 999 alone", with("3004 800203e7"), okw},
		{"accuracy micros 1 alone", with("3003 810101"), okw},
		{"accuracy millis 128", with("3004 80020080"), okw},
		{"tsa an rfc822Name [1]", with("a003 810141"), okw},
		{"tsa a URI [6]", with("a003 860141"), okw},
		{"tsa an otherName [0]", with("a004 a0020500"), okw},
		{"tsa an iPAddress [7]", with("a006 87047f000001"), okw},
		{"tsa a registeredID [8]", with("a005 88032a0304"), okw},
		{"tsa an x400Address [3]", with("a002 a300"), okw},
		{"tsa an ediPartyName [5]", with("a002 a500"), okw},
		{"tsa a dNSName [2]", with("a003 820141"), okw},
		{"an extension marked critical", with("a10e 300c 06032a0304 0101ff 04020500"), okw},
		{"an extension's value not DER", with("a10b 3009 06032a0304 0402 0481"), okw},
		{"two extensions", with("a116 3009 06032a0304 04020500 3009 06032a0305 04020500"), okw},

		{"a NULL after genTime", with("0500"), mf},
		{"a NULL after extensions", with(extensions, "0500"), mf},
		{"a BOOLEAN after extensions", with(extensions, "0101ff"), mf},
		{"nonce before ordering", with(nonce, "0101ff"), mf},
		{"two nonces", with(nonce, nonce), mf},
		{"two orderings", with(ordering, ordering), mf},
		{"ordering before accuracy", with(ordering, accuracy), mf},
		{"two accuracies", with(accuracy, accuracy), mf},
		{"extensions before tsa", with(extensions, tsaName), mf},
		{"tsa before nonce", with(tsaName, nonce), mf},
		{"no genTime", tst(func(m [][]byte) [][]byte { return m[:4] }), mf},
		{"no serialNumber", tst(func(m [][]byte) [][]byte { return append(m[:3], m[4]) }), mf},
		{"version an ENUMERATED", tst(set(0, "0a0101")), mf},
		{"policy a RELATIVE-OID", tst(set(1, "0d020304")), mf},
		{"serialNumber an OCTET STRING", tst(set(3, "04012a")), mf},

		{"accuracy millis 0", with("3003 800100"), mf},
		{"accuracy millis 1000", with("3004 800203e8"), mf},
		{"accuracy micros 0", with("3003 810100"), mf},
		{"accuracy micros 1000", with("3004 810203e8"), mf},
		{"accuracy millis -1", with("3003 8001ff"), mf},
		{"accuracy millis 5 in two octets", with("3004 80020005"), mf},
		{"accuracy millis 128 without its leading zero", with("3003 800180"), mf},
		{"accuracy millis empty", with("3002 8000"), mf},
		{"accuracy millis constructed", with("3005 a003 020105"), mf},
		{"accuracy micros before millis", with("3006 810101 800101"), mf},
		{"accuracy seconds after millis", with("3006 800101 020101"), mf},
		{"accuracy two seconds", with("3006 020101 020101"), mf},
		{"accuracy a NULL", with("3002 0500"), mf},
		{"accuracy a member after micros", with("3005 810101 0500"), mf},

		{"tsa empty", with("a000"), mf},
		{"tsa primitive", with("8003 810141"), mf},
		{"tsa holding two names", with("a006 810141 810142"), mf},
		{"tsa a [9]", with("a003 890141"), mf},
		{"tsa a universal SEQUENCE", with("a002 3000"), mf},
		{"tsa a directoryName [4] primitive", with("a003 840141"), mf},
		{"tsa an otherName [0] primitive", with("a003 800141"), mf},
		{"tsa a dNSName [2] constructed", with("a004 a2020500"), mf},
		{"tsa an application-class name", with("a003 420141"), mf},
		{"tsa holding a non-minimal length", with("a004 81810141"), mf},
		{"tsa holding an indefinite length", with("a007 a180 810141 0000"), mf},

		{"extensions empty", with("a100"), mf},
		{"extensions primitive", with("8100"), mf},
		{"extensions holding a NULL", with("a102 0500"), mf},
		{"an extension with a member after its value", with("a10d 300b 06032a0304 04020500 0500"), mf},
		{"an extension without a value", with("a107 3005 06032a0304"), mf},
		{"an extension with an INTEGER where critical sits", with("a10e 300c 06032a0304 020101 04020500"), mf},

		{"messageImprint's hashAlgorithm with a second NULL", tst(set(2, imprint("300f 0609 608648016503040201 0500 0500"))), mf},
		{"messageImprint's hashAlgorithm with a BOOLEAN after its NULL", tst(set(2, imprint("3010 0609 608648016503040201 0500 0101ff"))), mf},
		{"messageImprint's hashAlgorithm an OBJECT IDENTIFIER alone", tst(set(2, imprint("0609 608648016503040201"))), mf},
		{"messageImprint with a member after hashedMessage", tst(set(2, imprint(sha256, "0500"))), mf},
		{"messageImprint's hashedMessage a BIT STRING", tst(set(2, tlv(0x30, sha256, tlv(0x03, "00"+hex.EncodeToString(p))))), mf},
		{"messageImprint a SET", tst(set(2, tlv(0x31, sha256, tlv(0x04, hex.EncodeToString(p))))), mf},
		{"a nonce with a leading zero", with("0202 0001"), mf},
	} {
		s.verify(c.name, c.tok, c.w)
	}
	// The record's own token reads the same, malformed_token.
	if r := VerifyRecordToken(report.S(with("0500")), p, s.trusted); r.Token.Reason != ReasonMalformedToken {
		t.Errorf("the record's token, a NULL after genTime: %s %q", r.Token.Outcome, r.Token.Reason)
	}

	// eContent holds the TSTInfo and nothing after it.
	resp, sd, _ := tokenParts(t, with())
	oct := sd.at(2, 1, 0)
	oct.body = append(oct.body, 0x05, 0x00)
	s.verify("a NULL after the TSTInfo in eContent", encode(resp), mf)

	// The TSTInfo is a SEQUENCE: one tagged a SET, changed after signing,
	// fails step 1 before step 3 finds the change.
	resp, sd, _ = tokenParts(t, with())
	oct = sd.at(2, 1, 0)
	asSet := tree(t, oct.body)
	asSet.tag = asn1.TagSet
	oct.body = asSet.der()
	s.verify("the TSTInfo a SET", encode(resp), mf)

	// genTime: a GeneralizedTime in the ranges of a validity time, the year
	// any of 0000 to 9999, a fraction allowed. A genTime outside the
	// signer's validity passes steps 1 to 3 and fails step 4.
	genTime := func(v string) string { return tst(set(4, gtime(v))) }
	for _, c := range []struct {
		value string
		w     want
	}{
		{"00000229000000Z", tokenOKOnly},
		{"00991231235959Z", tokenOKOnly},
		{"20000229000000Z", tokenOKOnly},
		{"99991231235959.999Z", tokenOKOnly},
		{"20261016000000.5Z", okw},
		{"01000229000000Z", mf},
		{"21000229000000Z", mf},
		{"20260229000000Z", mf},
		{"20261316000000Z", mf},
		{"20260016000000Z", mf},
		{"20261000000000Z", mf},
		{"20261032000000Z", mf},
		{"20260431000000Z", mf},
		{"20261016240000Z", mf},
		{"20261016006000Z", mf},
		{"20261016000060Z", mf},
		{"20261016000000+0000", mf},
		{"20261016000000.50Z", mf},
	} {
		s.verify("genTime "+c.value, genTime(c.value), c.w)
	}
	s.verify("genTime a UTCTime", tst(set(4, utime("261016000000Z"))), mf)

	// A fraction finer than a nanosecond still puts genTime after its whole
	// second: a signer valid until that second is not valid at it.
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	until := testpki.Signer("TSA", s.root, at.AddDate(-1, 0, 0), at, testpki.EKU(true, testpki.TimeStamping))
	finer := func(frac string) string {
		return s.build(testpki.TokenOptions{Signer: until, TSTInfo: set(4, gtime(at.Format("20060102150405")+frac))})
	}
	r := s.verify("genTime its signer's notAfter", finer("Z"), okw)
	if !r.GenTime.Equal(at) {
		t.Errorf("genTime %v, want %v", r.GenTime, at)
	}
	s.verify("genTime a nanosecond after its signer's notAfter", finer(".000000001Z"), tokenOKOnly)
	s.verify("genTime a picosecond after its signer's notAfter", finer(".000000000001Z"), tokenOKOnly)
}

// TestTypedExtensionValues: the value of each extension step 1 gives a
// type is, as an encoding of its own, one DER element of that type with
// nothing after it; the value of any other extension is not read. The
// extensions are on a carried certificate no later step needs.
func TestTypedExtensionValues(t *testing.T) {
	s := newStepOne(t)
	ext := func(id asn1.ObjectIdentifier, value string) string {
		return s.extra(func(_, tbs *node) { setExtension(t, tbs, id, unhex(t, value)) })
	}
	oid := func(arcs ...int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier(arcs) }
	uri := func(u string) string { return tlv(0x86, hex.EncodeToString([]byte(u))) }
	for _, c := range []struct {
		name  string
		id    asn1.ObjectIdentifier
		value string
	}{
		{"keyUsage", oid(2, 5, 29, 15), "03020184"},
		{"basicConstraints", oid(2, 5, 29, 19), tlv(0x30, "0101ff", "020101")},
		{"extendedKeyUsage", oid(2, 5, 29, 37), tlv(0x30, "06082b06010505070308")},
		{"subjectKeyIdentifier", oid(2, 5, 29, 14), "040401020304"},
		{"authorityKeyIdentifier", oid(2, 5, 29, 35), tlv(0x30, "800401020304")},
		{"subjectAltName", oid(2, 5, 29, 17), tlv(0x30, tlv(0x82, hex.EncodeToString([]byte("localhost"))))},
		{"nameConstraints", oid(2, 5, 29, 30), tlv(0x30, tlv(0xa0, tlv(0x30, tlv(0x82, hex.EncodeToString([]byte("example"))))))},
		{"cRLDistributionPoints", oid(2, 5, 29, 31), tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa0, uri("http://a/")))))},
		{"certificatePolicies", oid(2, 5, 29, 32), tlv(0x30, tlv(0x30, "0604551d2000"))},
		{"authorityInfoAccess", oid(1, 3, 6, 1, 5, 5, 7, 1, 1), tlv(0x30, tlv(0x30, "06082b06010505073002", uri("http://a/")))},
	} {
		s.verify(c.name, ext(c.id, c.value), okw)
		s.verify(c.name+", a NULL after its value", ext(c.id, c.value+"0500"), mf)
		s.verify(c.name+", its value an empty OCTET STRING's contents", ext(c.id, ""), mf)
		s.verify(c.name+", its value a NULL", ext(c.id, "0500"), mf)
	}
	for _, c := range []struct {
		name  string
		id    asn1.ObjectIdentifier
		value string
		w     want
	}{
		{"basicConstraints empty", oid(2, 5, 29, 19), "3000", okw},
		{"basicConstraints with pathLenConstraint alone", oid(2, 5, 29, 19), tlv(0x30, "020101"), okw},
		{"basicConstraints with a NULL after cA", oid(2, 5, 29, 19), tlv(0x30, "0101ff", "0500"), mf},
		{"basicConstraints with pathLenConstraint before cA", oid(2, 5, 29, 19), tlv(0x30, "020101", "0101ff"), mf},
		{"basicConstraints with two cAs", oid(2, 5, 29, 19), tlv(0x30, "0101ff", "0101ff"), mf},
		{"basicConstraints a SET", oid(2, 5, 29, 19), tlv(0x31, "0101ff"), mf},
		{"extendedKeyUsage with a NULL among its purposes", oid(2, 5, 29, 37), tlv(0x30, "06082b06010505070308", "0500"), mf},
		{"keyUsage an OCTET STRING", oid(2, 5, 29, 15), "040184", mf},
		{"subjectKeyIdentifier with a non-minimal length", oid(2, 5, 29, 14), "04810401020304", mf},
		{"subjectAltName a SET", oid(2, 5, 29, 17), tlv(0x31, tlv(0x82, "41")), mf},
		{"an extension of another type, two elements", oid(1, 2, 3, 4), "05000500", okw},
		{"an extension of another type, not DER", oid(1, 2, 3, 4), "04810141", okw},
		{"an extension of another type, empty", oid(1, 2, 3, 4), "", okw},
	} {
		s.verify(c.name, ext(c.id, c.value), c.w)
	}
}

// TestValidityTimes: a validity time is a UTCTime or a GeneralizedTime
// without a fraction of a second, whose fields are in their ranges: a
// GeneralizedTime's year its four digits, 0000 to 9999; a UTCTime's 19YY
// for 50 to 99 and 20YY for 00 to 49; the Gregorian leap years, applied to
// every year. On a carried certificate no later step needs.
func TestValidityTimes(t *testing.T) {
	s := newStepOne(t)
	validity := func(notBefore, notAfter string) string {
		return s.extra(func(_, tbs *node) {
			v := tbs.at(4)
			v.kids = []*node{raw(t, notBefore), raw(t, notAfter)}
		})
	}
	end := gtime("99991231235959Z")
	for _, c := range []struct {
		time string
		w    want
	}{
		{gtime("20500101000000Z"), okw},
		{gtime("00000101000000Z"), okw},
		{gtime("00990101000000Z"), okw},
		{gtime("00000229000000Z"), okw},
		{gtime("20000229000000Z"), okw},
		{gtime("20240229000000Z"), okw},
		{gtime("01000229000000Z"), mf},
		{gtime("19000229000000Z"), mf},
		{gtime("20260229000000Z"), mf},
		{gtime("20500101000000.5Z"), mf},
		{gtime("20500101000000.1Z"), mf},
		{gtime("20501301000000Z"), mf},
		{gtime("20500001000000Z"), mf},
		{gtime("20500100000000Z"), mf},
		{gtime("20500132000000Z"), mf},
		{gtime("20500431000000Z"), mf},
		{gtime("20500101240000Z"), mf},
		{gtime("20500101006000Z"), mf},
		{gtime("20500101000060Z"), mf},
		{utime("000229000000Z"), okw},
		{utime("520229000000Z"), okw},
		{utime("960229000000Z"), okw},
		{utime("500229000000Z"), mf},
		{utime("490229000000Z"), mf},
		{utime("501231235959Z"), okw},
		{utime("491231235959Z"), okw},
		{utime("500101000060Z"), mf},
	} {
		s.verify("notBefore "+c.time, validity(c.time, end), c.w)
		s.verify("notAfter "+c.time, validity(gtime("00000101000000Z"), c.time), c.w)
	}
}
