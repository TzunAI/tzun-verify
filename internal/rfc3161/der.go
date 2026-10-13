// SPDX-License-Identifier: BSD-3-Clause-Clear

package rfc3161

import "encoding/asn1"

// Step 1 reads a token as the DER of a TimeStampResp that is a CMS
// SignedData (§10.5 step 1). The decoders it uses check less than that:
// encoding/asn1 accepts members after the last field of a SEQUENCE and does
// not check the tag of a RawValue, and the CMS library converts BER to DER
// before it decodes. The checks of this file cover the difference, each
// before a decoder reads what it checks:
//
//   - isDER: the whole response is DER (X.690 §10, §11), every element of it;
//   - tokenShape: each CMS structure step 1 reads has its members, in order,
//     and nothing else (RFC 3161 §2.4.2, RFC 5652 §5).
//
// None of them reads what a value means. A SIZE constraint is not checked
// here, nor are the two rules of DER that need the schema: a DEFAULT value
// left out, and the elements of a SET OF in order. Nor are the contents of an
// OCTET STRING or a BIT STRING (a TSTInfo, an extension's value, a key),
// which are encodings of their own, read by the step that needs them.

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
// RELATIVE-OID, the one X.680 reserves, and the last it assigns
// (RELATIVE-OID-IRI).
const (
	tagExternal      = 8
	tagEmbeddedPDV   = 11
	tagRelativeOID   = 13
	tagReserved      = 15
	tagLastUniversal = 36
)

// contentsOK checks a universal element by the rules of DER that need no
// schema: the form X.690 gives its type (constructed for SEQUENCE, SET,
// EXTERNAL and EMBEDDED PDV, primitive for every other type, strings
// included), and the contents of a BOOLEAN (00 or FF), an INTEGER or
// ENUMERATED (in the fewest octets), a BIT STRING (its unused bits zero), a
// NULL (empty), an OBJECT IDENTIFIER or RELATIVE-OID (each subidentifier in
// the fewest octets), a UTCTime (YYMMDDhhmmssZ) and a GeneralizedTime
// (YYYYMMDDhhmmss, a fraction without trailing zeros, Z). An element of
// another class is the schema's, and is not read here.
func contentsOK(e element) bool {
	if e.class != asn1.ClassUniversal {
		return true
	}
	switch e.tag {
	case 0:
		return false // end-of-contents, which only the indefinite form uses
	case asn1.TagSequence, asn1.TagSet, tagExternal, tagEmbeddedPDV:
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

// isDER reports whether b is exactly one element and DER throughout: every
// element's header as readElement reads it and every universal element's
// contents as contentsOK checks them, at any depth. It walks the elements
// with a stack rather than by recursion, so no nesting depth is refused.
func isDER(b []byte) bool {
	if _, rest, ok := readElement(b); !ok || len(rest) != 0 {
		return false
	}
	stack := [][]byte{b} // the elements left to read at each depth
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
		stack[top] = rest
		if e.compound {
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

// tokenShape reports whether the structures of a TimeStampResp (one DER
// element) that step 1 reads have the members RFC 3161 §2.4.2 and RFC 5652
// §5 give them, in order, and nothing else:
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
// The elements of certificates are left to parseCertificate.
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
