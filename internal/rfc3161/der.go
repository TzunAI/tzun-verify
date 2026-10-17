// SPDX-License-Identifier: BSD-3-Clause-Clear

package rfc3161

import (
	"encoding/asn1"
	"time"
)

// Step 1 reads a token as the DER of a TimeStampResp that is a CMS
// SignedData over a TSTInfo, every one of whose certificates decodes as an
// X.509 certificate (§10.5 step 1). The decoders it uses check less than
// that: encoding/asn1 accepts members after the last field of a SEQUENCE and
// does not check the tag of a RawValue, and crypto/x509 skips parts of a
// certificate. The checks of this file cover the difference, each before a
// decoder reads what it checks:
//
//   - isDER: every element of an encoding has a DER header (X.690 §8.1.2,
//     §8.1.3, §10.1); one with a universal tag has the form X.690 gives its
//     type (§8, §10.2) and, if it is a BOOLEAN, INTEGER, ENUMERATED,
//     BIT STRING, NULL, OBJECT IDENTIFIER, RELATIVE-OID, UTCTime or
//     GeneralizedTime, the contents contentsOK names; and the encoding keeps
//     to the decoder bounds of step 1 (maxElements, maxDepth). It reads the
//     TimeStampResp, and on their own the TSTInfo and the value of each
//     certificate extension typedExtensions names;
//   - tokenShape: the TimeStampResp, ContentInfo, SignedData,
//     EncapsulatedContentInfo and SignerInfo, and the AlgorithmIdentifiers
//     and attributes the SignedData and SignerInfo hold, have their members,
//     in order, and nothing else (RFC 3161 §2.4.2, RFC 5652 §5);
//   - readTSTInfo: the TSTInfo has the members of RFC 3161 §2.4.2, in order,
//     and nothing else, with the forms and ranges step 1 gives them;
//   - certificateShape: each carried certificate has the members of RFC 5280
//     §4.1, in order, and nothing else, and the value of each extension
//     typedExtensions names is one element of its type.
//
// None of them reads what a value means beyond that. The other rules of DER
// are not checked here, among them: midnight as 000000 rather than 240000 in
// a UTCTime or GeneralizedTime (X.690 §11.7.5, §11.8.3); the contents of a
// REAL (§11.3) and of a character string, such as a GeneralString's escape
// sequences (§11.4), the four octets of each of a UniversalString's
// characters and the two of a BMPString's (§8.23.7, §8.23.8) and a
// UTF8String's UTF-8 (§8.23.10); the form of an element whose tag is not
// universal, and the contents of a primitive one; and the rules that need
// the schema: the order of a SET's components (§10.3) and of a SET OF's
// elements (§11.6), the omission of a DEFAULT value (§11.5) and the removal
// of trailing zero bits from a named bit list (§11.2.2), such as a
// PKIStatusInfo's failInfo. Nor is a SIZE constraint. TSAs often send the
// certificates of a SignedData out of DER order (testdata/sectigo.tsr is
// one), and a token is not refused for it. Nor are the contents of any other
// OCTET STRING or BIT STRING (a signature, a key, the value of another
// extension), nor the members of the PKIStatusInfo, of an attribute's values
// or of a CRL, which only their decoders read.

// element is one DER element: its class, tag number and form, its whole
// encoding and its contents.
type element struct {
	class, tag int
	compound   bool
	full, body []byte
}

// readElement reads the element at the start of b by the header rules of DER
// (X.690 §8.1.2, §8.1.3, §10.1): the tag number in the low-tag-number form
// when it is below 31 and otherwise in the fewest octets, a definite length
// in the fewest octets, and contents that lie within b. It returns the
// element and the bytes after it.
func readElement(b []byte) (element, []byte, bool) {
	var e element
	if len(b) == 0 {
		return e, nil, false
	}
	e.class, e.compound, e.tag = int(b[0]>>6), b[0]&0x20 != 0, int(b[0]&0x1f)
	i := 1
	if e.tag == 0x1f {
		e.tag = 0
		for first := true; ; first = false {
			if i >= len(b) || e.tag > 1<<24 {
				return e, nil, false
			}
			c := b[i]
			i++
			if first && c == 0x80 {
				return e, nil, false // a leading zero group
			}
			e.tag = e.tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
		if e.tag < 0x1f {
			return e, nil, false
		}
	}
	if i >= len(b) {
		return e, nil, false
	}
	n := int(b[i])
	i++
	switch {
	case n == 0x80:
		return e, nil, false // the indefinite form
	case n > 0x80:
		k := n & 0x7f
		// More than four length octets, with the first not zero, is a length
		// of 4 GiB or more, which no input here holds.
		if k > 4 || k > len(b)-i || b[i] == 0 {
			return e, nil, false
		}
		n = 0
		for ; k > 0; k-- {
			n = n<<8 | int(b[i])
			i++
		}
		if n < 0x80 {
			return e, nil, false // the short form fits
		}
	}
	if n > len(b)-i {
		return e, nil, false
	}
	e.full, e.body = b[:i+n], b[i:i+n]
	return e, b[i+n:], true
}

// elementsOf splits the contents of a constructed element into its elements.
func elementsOf(body []byte) ([]element, bool) {
	var out []element
	for len(body) > 0 {
		e, rest, ok := readElement(body)
		if !ok {
			return nil, false
		}
		out = append(out, e)
		body = rest
	}
	return out, true
}

// Universal tag numbers encoding/asn1 does not name: EXTERNAL, EMBEDDED PDV,
// RELATIVE-OID, the one X.680 reserves, the unrestricted CHARACTER STRING,
// and the last it assigns (RELATIVE-OID-IRI).
const (
	tagExternal        = 8
	tagEmbeddedPDV     = 11
	tagRelativeOID     = 13
	tagReserved        = 15
	tagCharacterString = 29
	tagLastUniversal   = 36
)

// contentsOK checks these rules of DER for a universal element: that it is
// not end-of-contents; the form X.690 gives its type (constructed for
// SEQUENCE and SET, and for the types it encodes as a SEQUENCE: EXTERNAL,
// EMBEDDED PDV and the unrestricted CHARACTER STRING; primitive for every
// other type, the restricted character strings included); and the contents
// of a BOOLEAN (00 or FF), an INTEGER or ENUMERATED (in the fewest octets),
// a BIT STRING (its unused bits zero), a NULL (empty), an OBJECT IDENTIFIER
// or RELATIVE-OID (each subidentifier in the fewest octets), a UTCTime
// (YYMMDDhhmmssZ) and a GeneralizedTime (YYYYMMDDhhmmss, a fraction without
// trailing zeros, Z). A universal tag number X.680 assigns to no type, and
// an element of another class, are the schema's, and are not read here.
func contentsOK(e element) bool {
	if e.class != asn1.ClassUniversal {
		return true
	}
	switch e.tag {
	case 0:
		return false // end-of-contents, which only the indefinite form uses
	case asn1.TagSequence, asn1.TagSet, tagExternal, tagEmbeddedPDV, tagCharacterString:
		return e.compound
	}
	if e.tag == tagReserved || e.tag > tagLastUniversal {
		return true // a number X.680 assigns to no type: the schema's to refuse
	}
	if e.compound {
		return false
	}
	c := e.body
	switch e.tag {
	case asn1.TagBoolean:
		return len(c) == 1 && (c[0] == 0x00 || c[0] == 0xff)
	case asn1.TagInteger, asn1.TagEnum:
		return len(c) > 0 && (len(c) == 1 || !(c[0] == 0x00 && c[1]&0x80 == 0) && !(c[0] == 0xff && c[1]&0x80 != 0))
	case asn1.TagBitString:
		return len(c) > 0 && c[0] <= 7 && (len(c) > 1 || c[0] == 0) && c[len(c)-1]&(1<<c[0]-1) == 0
	case asn1.TagNull:
		return len(c) == 0
	case asn1.TagOID, tagRelativeOID:
		if len(c) == 0 || c[len(c)-1]&0x80 != 0 {
			return false
		}
		for i, b := range c {
			if b == 0x80 && (i == 0 || c[i-1]&0x80 == 0) {
				return false
			}
		}
		return true
	case asn1.TagUTCTime:
		return len(c) == 13 && digits(c[:12]) && c[12] == 'Z'
	case asn1.TagGeneralizedTime:
		if len(c) < 15 || !digits(c[:14]) || c[len(c)-1] != 'Z' {
			return false
		}
		frac := c[14 : len(c)-1]
		return len(frac) == 0 || len(frac) > 1 && frac[0] == '.' && digits(frac[1:]) && frac[len(frac)-1] != '0'
	}
	return true
}

func digits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// The decoder bounds of step 1, on each encoding isDER reads: at most
// maxElements elements, the outermost included, and constructed elements,
// of any class, nested at most maxDepth deep, the outermost at depth 1.
// Neither counts what lies inside a primitive element.
const (
	maxElements = 100000
	maxDepth    = 64
)

// isDER reports whether b is exactly one element and every element in it, b
// included and at any depth, has a header as readElement reads it and, if
// it is universal, the form and contents contentsOK checks, and whether b
// keeps to the decoder bounds. It walks the elements with a stack rather
// than by recursion.
func isDER(b []byte) bool {
	if _, rest, ok := readElement(b); !ok || len(rest) != 0 {
		return false
	}
	stack := [][]byte{b} // the elements left to read at each depth
	n := 0
	for len(stack) > 0 {
		top := len(stack) - 1
		if len(stack[top]) == 0 {
			stack = stack[:top]
			continue
		}
		e, rest, ok := readElement(stack[top])
		if !ok || !contentsOK(e) {
			return false
		}
		if n++; n > maxElements {
			return false
		}
		stack[top] = rest
		if e.compound {
			if len(stack) > maxDepth { // e sits at depth len(stack)
				return false
			}
			stack = append(stack, e.body)
		}
	}
	return true
}

func is(e element, class, tag int, compound bool) bool {
	return e.class == class && e.tag == tag && e.compound == compound
}

func isSequence(e element) bool { return is(e, asn1.ClassUniversal, asn1.TagSequence, true) }

func isSet(e element) bool { return is(e, asn1.ClassUniversal, asn1.TagSet, true) }

func isPrimitive(e element, tag int) bool { return is(e, asn1.ClassUniversal, tag, false) }

func isContext(e element, tag int, compound bool) bool {
	return is(e, asn1.ClassContextSpecific, tag, compound)
}

// members returns the elements of a SEQUENCE or SET.
func members(e element) ([]element, bool) {
	if !isSequence(e) && !isSet(e) && !isContext(e, e.tag, true) {
		return nil, false
	}
	return elementsOf(e.body)
}

// algorithmIdentifier reports whether e is an AlgorithmIdentifier: an
// OBJECT IDENTIFIER and at most one parameters element (RFC 5280 §4.1.1.2,
// RFC 5652 §10.1).
func algorithmIdentifier(e element) bool {
	m, ok := members(e)
	return ok && isSequence(e) && (len(m) == 1 || len(m) == 2) && isPrimitive(m[0], asn1.TagOID)
}

// tokenShape reports whether these structures of a TimeStampResp (one DER
// element) have the members RFC 3161 §2.4.2 and RFC 5652 §5 give them, in
// order, and nothing else:
//
//   - TimeStampResp: status and timeStampToken;
//   - ContentInfo: contentType, and content [0] holding one element;
//   - SignedData: version, digestAlgorithms (a SET of AlgorithmIdentifier),
//     encapContentInfo, certificates [0] and crls [1] when present, and
//     signerInfos (a SET);
//   - EncapsulatedContentInfo: eContentType, and eContent [0] holding one
//     OCTET STRING;
//   - each SignerInfo: version, sid (an IssuerAndSerialNumber, or a
//     subjectKeyIdentifier [0]), digestAlgorithm, signedAttrs [0] when
//     present, signatureAlgorithm, signature (an OCTET STRING), and
//     unsignedAttrs [1] when present;
//   - each signed and unsigned attribute: an OBJECT IDENTIFIER and a SET.
//
// Each element of certificates is held to certificateShape where it is read.
func tokenShape(der []byte) bool {
	resp, _, ok := readElement(der)
	if !ok {
		return false
	}
	m, ok := members(resp)
	if !ok || !isSequence(resp) || len(m) != 2 || !isSequence(m[0]) || !isSequence(m[1]) {
		return false
	}
	ci, ok := members(m[1])
	if !ok || len(ci) != 2 || !isPrimitive(ci[0], asn1.TagOID) || !isContext(ci[1], 0, true) {
		return false
	}
	content, ok := members(ci[1])
	if !ok || len(content) != 1 || !isSequence(content[0]) {
		return false
	}
	sd, ok := members(content[0])
	if !ok || len(sd) < 4 || !isPrimitive(sd[0], asn1.TagInteger) || !isSet(sd[1]) || !isSequence(sd[2]) {
		return false
	}
	algs, ok := members(sd[1])
	if !ok {
		return false
	}
	for _, a := range algs {
		if !algorithmIdentifier(a) {
			return false
		}
	}
	encap, ok := members(sd[2])
	if !ok || len(encap) != 2 || !isPrimitive(encap[0], asn1.TagOID) || !isContext(encap[1], 0, true) {
		return false
	}
	if e, ok := members(encap[1]); !ok || len(e) != 1 || !isPrimitive(e[0], asn1.TagOctetString) {
		return false
	}
	i := 3
	if i < len(sd) && isContext(sd[i], 0, true) {
		i++
	}
	if i < len(sd) && isContext(sd[i], 1, true) {
		i++
	}
	if i != len(sd)-1 || !isSet(sd[i]) {
		return false
	}
	infos, ok := members(sd[i])
	if !ok {
		return false
	}
	for _, si := range infos {
		if !signerInfoShape(si) {
			return false
		}
	}
	return true
}

func signerInfoShape(e element) bool {
	m, ok := members(e)
	if !ok || !isSequence(e) || len(m) < 5 || !isPrimitive(m[0], asn1.TagInteger) || !algorithmIdentifier(m[2]) {
		return false
	}
	if isSequence(m[1]) {
		ias, ok := members(m[1])
		if !ok || len(ias) != 2 || !isSequence(ias[0]) || !isPrimitive(ias[1], asn1.TagInteger) {
			return false
		}
	} else if !isContext(m[1], 0, false) {
		return false
	}
	i := 3
	if isContext(m[i], 0, true) {
		if !attributesShape(m[i]) {
			return false
		}
		i++
	}
	if i+1 >= len(m) || !algorithmIdentifier(m[i]) || !isPrimitive(m[i+1], asn1.TagOctetString) {
		return false
	}
	i += 2
	if i < len(m) && isContext(m[i], 1, true) {
		if !attributesShape(m[i]) {
			return false
		}
		i++
	}
	return i == len(m)
}

// attributesShape reports whether each element of signedAttrs or
// unsignedAttrs is an Attribute: an OBJECT IDENTIFIER and a SET of values.
func attributesShape(e element) bool {
	attrs, ok := members(e)
	if !ok {
		return false
	}
	for _, a := range attrs {
		m, ok := members(a)
		if !ok || !isSequence(a) || len(m) != 2 || !isPrimitive(m[0], asn1.TagOID) || !isSet(m[1]) {
			return false
		}
	}
	return true
}

// certificateShape reports whether der is one Certificate with the members
// RFC 5280 §4.1 gives it, in order, and nothing else: tbsCertificate,
// signatureAlgorithm and signatureValue; in tbsCertificate, version [0]
// (holding one INTEGER) when present, serialNumber, signature, issuer,
// validity (two times), subject, subjectPublicKeyInfo (an
// AlgorithmIdentifier and a BIT STRING), then issuerUniqueID [1] and
// subjectUniqueID [2] when present, each primitive, and extensions [3] when
// present, constructed and holding one SEQUENCE of Extension (extnID,
// critical when present, extnValue), whose value, for an extension
// typedExtensions names, is one element of its type. A Name is a SEQUENCE
// of SETs of AttributeTypeAndValue, each a type and one value.
func certificateShape(der []byte) bool {
	c, rest, ok := readElement(der)
	if !ok || len(rest) != 0 {
		return false
	}
	m, ok := members(c)
	if !ok || !isSequence(c) || len(m) != 3 || !isSequence(m[0]) || !algorithmIdentifier(m[1]) ||
		!isPrimitive(m[2], asn1.TagBitString) {
		return false
	}
	f, ok := members(m[0])
	if !ok {
		return false
	}
	i := 0
	if i < len(f) && isContext(f[i], 0, true) {
		if v, ok := members(f[i]); !ok || len(v) != 1 || !isPrimitive(v[0], asn1.TagInteger) {
			return false
		}
		i++
	}
	if len(f) < i+6 || !isPrimitive(f[i], asn1.TagInteger) || !algorithmIdentifier(f[i+1]) || !nameShape(f[i+2]) ||
		!validityShape(f[i+3]) || !nameShape(f[i+4]) || !spkiShape(f[i+5]) {
		return false
	}
	i += 6
	if i < len(f) && isContext(f[i], 1, false) {
		i++
	}
	if i < len(f) && isContext(f[i], 2, false) {
		i++
	}
	if i < len(f) && isContext(f[i], 3, true) {
		if !extensionsShape(f[i]) {
			return false
		}
		i++
	}
	return i == len(f)
}

func nameShape(e element) bool {
	rdns, ok := members(e)
	if !ok || !isSequence(e) {
		return false
	}
	for _, rdn := range rdns {
		atvs, ok := members(rdn)
		if !ok || !isSet(rdn) {
			return false
		}
		for _, atv := range atvs {
			m, ok := members(atv)
			if !ok || !isSequence(atv) || len(m) != 2 || !isPrimitive(m[0], asn1.TagOID) {
				return false
			}
		}
	}
	return true
}

func validityShape(e element) bool {
	m, ok := members(e)
	if !ok || !isSequence(e) || len(m) != 2 {
		return false
	}
	for _, t := range m {
		if !isPrimitive(t, asn1.TagUTCTime) && !isPrimitive(t, asn1.TagGeneralizedTime) {
			return false
		}
	}
	return true
}

func spkiShape(e element) bool {
	m, ok := members(e)
	return ok && isSequence(e) && len(m) == 2 && algorithmIdentifier(m[0]) && isPrimitive(m[1], asn1.TagBitString)
}

func extensionsShape(e element) bool {
	inner, ok := members(e)
	if !ok || len(inner) != 1 || !isSequence(inner[0]) {
		return false
	}
	exts, ok := members(inner[0])
	if !ok {
		return false
	}
	for _, ext := range exts {
		id, value, ok := extensionShape(ext)
		if !ok {
			return false
		}
		if typed, ok := typedExtensions[string(id.body)]; ok && !typedValue(value.body, typed) {
			return false
		}
	}
	return true
}

// extensionShape reports whether e is an Extension: an OBJECT IDENTIFIER,
// a BOOLEAN when present, and an OCTET STRING, and nothing else. It returns
// the OBJECT IDENTIFIER and the OCTET STRING.
func extensionShape(e element) (id, value element, ok bool) {
	m, ok := members(e)
	if !ok || !isSequence(e) || len(m) < 2 || !isPrimitive(m[0], asn1.TagOID) {
		return id, value, false
	}
	i := 1
	if isPrimitive(m[i], asn1.TagBoolean) {
		i++
	}
	if i != len(m)-1 || !isPrimitive(m[i], asn1.TagOctetString) {
		return id, value, false
	}
	return m[0], m[i], true
}

// typedExtensions are the certificate extensions whose value step 1 reads,
// by the contents of their OBJECT IDENTIFIER, each with the test of the one
// element its value is (RFC 5280 §4.2.1).
var typedExtensions = func() map[string]func(element) bool {
	bitString := func(e element) bool { return isPrimitive(e, asn1.TagBitString) }
	octetString := func(e element) bool { return isPrimitive(e, asn1.TagOctetString) }
	byID := map[string]func(element) bool{}
	for _, x := range []struct {
		id    asn1.ObjectIdentifier
		typed func(element) bool
	}{
		{asn1.ObjectIdentifier{2, 5, 29, 15}, bitString},               // keyUsage
		{asn1.ObjectIdentifier{2, 5, 29, 19}, basicConstraintsShape},   // basicConstraints
		{asn1.ObjectIdentifier{2, 5, 29, 37}, extKeyUsageShape},        // extendedKeyUsage
		{asn1.ObjectIdentifier{2, 5, 29, 14}, octetString},             // subjectKeyIdentifier
		{asn1.ObjectIdentifier{2, 5, 29, 35}, isSequence},              // authorityKeyIdentifier
		{asn1.ObjectIdentifier{2, 5, 29, 17}, isSequence},              // subjectAltName
		{asn1.ObjectIdentifier{2, 5, 29, 30}, isSequence},              // nameConstraints
		{asn1.ObjectIdentifier{2, 5, 29, 31}, isSequence},              // cRLDistributionPoints
		{asn1.ObjectIdentifier{2, 5, 29, 32}, isSequence},              // certificatePolicies
		{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, isSequence}, // authorityInfoAccess
	} {
		der, err := asn1.Marshal(x.id)
		if err != nil {
			panic(err) // each of these encodes
		}
		byID[string(der[2:])] = x.typed
	}
	return byID
}()

// typedValue reports whether b, the contents of an extension's OCTET
// STRING, is as an encoding of its own one element (isDER, with nothing
// after it) that typed accepts.
func typedValue(b []byte, typed func(element) bool) bool {
	if !isDER(b) {
		return false
	}
	v, _, _ := readElement(b)
	return typed(v)
}

// basicConstraintsShape: a SEQUENCE of cA (a BOOLEAN) and pathLenConstraint
// (an INTEGER), each when present, and nothing else.
func basicConstraintsShape(e element) bool {
	m, ok := members(e)
	if !ok || !isSequence(e) {
		return false
	}
	i := 0
	if i < len(m) && isPrimitive(m[i], asn1.TagBoolean) {
		i++
	}
	if i < len(m) && isPrimitive(m[i], asn1.TagInteger) {
		i++
	}
	return i == len(m)
}

// extKeyUsageShape: a SEQUENCE of OBJECT IDENTIFIERs.
func extKeyUsageShape(e element) bool {
	m, ok := members(e)
	if !ok || !isSequence(e) {
		return false
	}
	for _, purpose := range m {
		if !isPrimitive(purpose, asn1.TagOID) {
			return false
		}
	}
	return true
}

// tstInfo is what the steps after step 1 read of a TSTInfo.
type tstInfo struct {
	raw           []byte // the TSTInfo's encoding, which the message-digest attribute covers
	hashAlgorithm []byte // the DER of the OBJECT IDENTIFIER of messageImprint's hashAlgorithm
	hashParams    []byte // the DER of its parameters, nil when they are absent
	hashedMessage []byte
	genTime       time.Time
}

// readTSTInfo reads the TSTInfo that eContent carries, an encoding of its
// own, by RFC 3161 §2.4.2 as step 1 states it: isDER over it, then a
// SEQUENCE of version (an INTEGER), policy (an OBJECT IDENTIFIER),
// messageImprint (exactly an AlgorithmIdentifier and an OCTET STRING),
// serialNumber (an INTEGER) and genTime (a GeneralizedTime genTimeOf
// reads), then, each when present and in this order, accuracy
// (accuracyShape), ordering (a BOOLEAN), nonce (an INTEGER), tsa (a
// constructed [0], generalNameShape) and extensions (a constructed [1]
// holding one or more extensions, whose values it does not read), and
// nothing else. An INTEGER may be of any width.
func readTSTInfo(der []byte) (tstInfo, bool) {
	var t tstInfo
	if !isDER(der) {
		return t, false
	}
	seq, _, _ := readElement(der)
	m, ok := members(seq)
	if !ok || !isSequence(seq) || len(m) < 5 || !isPrimitive(m[0], asn1.TagInteger) || !isPrimitive(m[1], asn1.TagOID) ||
		!isPrimitive(m[3], asn1.TagInteger) || !isPrimitive(m[4], asn1.TagGeneralizedTime) {
		return t, false
	}
	imprint, ok := members(m[2])
	if !ok || !isSequence(m[2]) || len(imprint) != 2 || !algorithmIdentifier(imprint[0]) ||
		!isPrimitive(imprint[1], asn1.TagOctetString) {
		return t, false
	}
	gen, ok := genTimeOf(m[4].body)
	if !ok {
		return t, false
	}
	i := 5
	if i < len(m) && isSequence(m[i]) {
		if !accuracyShape(m[i]) {
			return t, false
		}
		i++
	}
	if i < len(m) && isPrimitive(m[i], asn1.TagBoolean) {
		i++
	}
	if i < len(m) && isPrimitive(m[i], asn1.TagInteger) {
		i++
	}
	if i < len(m) && isContext(m[i], 0, true) {
		if !generalNameShape(m[i]) {
			return t, false
		}
		i++
	}
	if i < len(m) && isContext(m[i], 1, true) {
		exts, ok := members(m[i])
		if !ok || len(exts) == 0 {
			return t, false
		}
		for _, ext := range exts {
			if _, _, ok := extensionShape(ext); !ok {
				return t, false
			}
		}
		i++
	}
	if i != len(m) {
		return t, false
	}
	alg, _ := members(imprint[0])
	t.raw, t.hashAlgorithm, t.hashedMessage, t.genTime = der, alg[0].full, imprint[1].body, gen
	if len(alg) == 2 {
		t.hashParams = alg[1].full
	}
	return t, true
}

// accuracyShape reports whether e, a SEQUENCE, is an Accuracy: seconds (an
// INTEGER), millis (a primitive [0]) and micros (a primitive [1]), each
// when present and in this order, and nothing else, with millis and micros
// each holding the contents of an INTEGER from 1 to 999.
func accuracyShape(e element) bool {
	m, ok := members(e)
	if !ok {
		return false
	}
	i := 0
	if i < len(m) && isPrimitive(m[i], asn1.TagInteger) {
		i++
	}
	for tag := 0; tag <= 1; tag++ {
		if i < len(m) && isContext(m[i], tag, false) {
			if !oneTo999(m[i].body) {
				return false
			}
			i++
		}
	}
	return i == len(m)
}

// oneTo999 reports whether c is the contents of an INTEGER, in its fewest
// octets, from 1 to 999.
func oneTo999(c []byte) bool {
	if !contentsOK(element{class: asn1.ClassUniversal, tag: asn1.TagInteger, body: c}) || len(c) > 2 || c[0]&0x80 != 0 {
		return false
	}
	v := int(c[0])
	if len(c) == 2 {
		v = v<<8 | int(c[1])
	}
	return v >= 1 && v <= 999
}

// generalNameShape reports whether e, the tsa [0], holds exactly one
// GeneralName (RFC 5280 §4.2.1.6): a context-specific element whose tag
// number, 0 to 8, is one of its alternatives', constructed for otherName
// [0], x400Address [3], directoryName [4] and ediPartyName [5], and
// primitive for the others. Its contents are not read.
func generalNameShape(e element) bool {
	inner, ok := members(e)
	if !ok || len(inner) != 1 {
		return false
	}
	g := inner[0]
	if g.class != asn1.ClassContextSpecific || g.tag > 8 {
		return false
	}
	switch g.tag {
	case 0, 3, 4, 5:
		return g.compound
	}
	return !g.compound
}

// genTimeOf reads c, the contents of a GeneralizedTime that contentsOK
// accepts (YYYYMMDDhhmmss, a fraction when present, Z), as an instant, when
// its fields are in the ranges step 1 gives a time: the year any of 0000 to
// 9999, the month 01 to 12, the day one that month has in that year, by the
// Gregorian rule applied to every year, the hour 00 to 23, and the minute
// and second each 00 to 59. The fraction is kept to the nanosecond, and one
// finer than that as one nanosecond, so that the instant stays after its
// whole second: a validity time, which genTime is compared with, has no
// fraction.
func genTimeOf(c []byte) (time.Time, bool) {
	num := func(i, j int) int {
		v := 0
		for _, d := range c[i:j] {
			v = v*10 + int(d-'0')
		}
		return v
	}
	year, month, day := num(0, 4), num(4, 6), num(6, 8)
	hour, minute, second := num(8, 10), num(10, 12), num(12, 14)
	if month < 1 || month > 12 || day < 1 || day > daysIn(year, month) || hour > 23 || minute > 59 || second > 59 {
		return time.Time{}, false
	}
	nanos := 0
	if frac := c[14 : len(c)-1]; len(frac) > 0 {
		for i := 1; i <= 9; i++ {
			nanos *= 10
			if i < len(frac) {
				nanos += int(frac[i] - '0')
			}
		}
		nanos = max(nanos, 1)
	}
	return time.Date(year, time.Month(month), day, hour, minute, second, nanos, time.UTC), true
}

// daysIn is the number of days of a month in a year of the Gregorian
// calendar, whose rule for leap years it applies to every year, 0000
// included.
func daysIn(year, month int) int {
	if month == 2 {
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	}
	return [...]int{31, 0, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[month-1]
}
