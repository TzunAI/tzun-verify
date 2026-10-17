// SPDX-License-Identifier: BSD-3-Clause-Clear

// Package rfc3161 verifies an rfc3161/1 publication (Anchor §7.3,
// §10.5): an RFC 3161 timestamp token whose imprint is P. A bare §n in this
// package's comments is a section of Anchor; an RFC's sections are named
// with the RFC.
//
// The steps run in order and the first that does not hold decides:
//
//  1. parse: a granted TimeStampResp that wraps a CMS SignedData over a
//     TSTInfo. The response, and on their own the TSTInfo and the value of
//     each certificate extension step 1 gives a type, keep to the rules of
//     DER der.go's isDER checks and to the decoder bounds (der.go does not
//     check the other rules of DER, among them midnight as 000000, the
//     contents of a REAL or a character string, the order of a SET's
//     components and of a SET OF's elements, the omission of a DEFAULT
//     value and the removal of trailing zero bits from a named bit list);
//     the TimeStampResp, ContentInfo, SignedData, EncapsulatedContentInfo,
//     SignerInfo and TSTInfo, and the AlgorithmIdentifiers and attributes
//     the SignedData and SignerInfo hold, have their members and nothing
//     else (der.go), while inside the PKIStatusInfo, an attribute's values
//     and a CRL, members are checked only as far as their decoders read
//     them; the SignedData has a single SignerInfo, and the token itself
//     holds the certificate its sid names, by issuer and serial number or by
//     subjectKeyIdentifier; every certificate it carries has the members of
//     an RFC 5280 certificate and decodes (malformed_publication). A
//     certificate whose key uses an algorithm or curve this build does not
//     implement is read with its key left unread;
//  2. imprint: SHA-256 and P (imprint_mismatch);
//  3. signature and signer: the signed attributes hold one content type and
//     one message digest of the TSTInfo; the signature over the signed
//     attributes, as the token carries them, verifies under the signer's key
//     (crypto/x509); a signingCertificate or signingCertificateV2 attribute
//     binds the signer's certificate; and that certificate's
//     extendedKeyUsage extension is marked critical and names timestamping
//     as its one purpose (verification_failed);
//  4. trust: some path from the signer to a root the auditor supplied is
//     valid at genTime (verification_failed when a path reaches a supplied
//     root but none is valid; not-checked, no_matching_trust_anchor, when
//     none reaches one).
//
// Step 5: a step that needs a key or an algorithm this build does not
// implement (a curve other than P-224, P-256, P-384 and P-521, a DSA key, an
// MD5 signature, a SignerInfo signature algorithm signatureAlgorithm does
// not map, a digest algorithm digestAlgorithm does not name) is not-checked,
// missing_dependency, on its check; at step 3, only when every requirement
// of step 3 this build can check holds.
//
// Steps 1 to 3 are check anchor.tsa.token[i]; step 4 is anchor.tsa.trust[i].
package rfc3161

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // ESSCertID's certHash is SHA-1 by definition (RFC 2634).
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
)

// Kind is the publication kind this package verifies.
const Kind = "rfc3161/1"

// Reasons of §10.1 used here.
const (
	ReasonMalformed          = "malformed_publication"
	ReasonImprintMismatch    = "imprint_mismatch"
	ReasonVerificationFailed = "verification_failed"
	ReasonNoTrustAnchor      = "no_matching_trust_anchor"
	ReasonMissingDependency  = "missing_dependency"
	ReasonNotChecked         = "publication_not_checked"
	ReasonUnsupportedKind    = "unsupported_publication_kind"
)

var (
	oidSignedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningCert    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSigningCertV2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidSHA256         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSHA1           = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidSubjectKeyID   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidKPTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidCommonName     = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidPublicKeyEC    = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	// The curves crypto/x509 implements.
	implementedCurves = []asn1.ObjectIdentifier{
		{1, 3, 132, 0, 33},          // P-224
		{1, 2, 840, 10045, 3, 1, 7}, // P-256
		{1, 3, 132, 0, 34},          // P-384
		{1, 3, 132, 0, 35},          // P-521
	}
	// oidKeyUnread stands in for a key this build does not implement, so
	// that the stock parser reads the rest of its certificate. It lies under
	// the enterprise arc IANA reserves (1.3.6.1.4.1.0), which names no
	// algorithm.
	oidKeyUnread = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 0}
	// derSHA256 is the DER of id-sha256, the hash algorithm of step 2.
	derSHA256         = mustMarshal(oidSHA256)
	nullParams        = []byte{0x05, 0x00}
	errNotCertificate = errors.New("rfc3161: not an RFC 5280 certificate")
)

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// RFC 3161 §2.4.2 and RFC 5652, transcribed.
type pkiStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional,utf8"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

// attribute is one signed or unsigned attribute. encoding/asn1 does not
// check the tag of a RawValue: tokenShape has checked that Values is a SET.
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// Trust is the auditor's RFC 3161 configuration: the roots it trusts and
// any intermediates it supplies.
type Trust struct {
	Roots         []*x509.Certificate
	Intermediates []*x509.Certificate
}

// Result is the verification of one rfc3161/1 publication.
type Result struct {
	Token report.Check
	Trust report.Check
	// Valid and Reason are the publication-level outcome of §10.1.
	Valid     *bool
	Reason    string
	GenTime   time.Time
	Authority string
}

// token is the output of step 1.
type token struct {
	tst       tstInfo
	signer    *x509.Certificate
	certs     []*x509.Certificate
	signerInf signerInfo
}

// elements splits the contents of a constructed DER element into its
// elements.
func elements(b []byte) ([]asn1.RawValue, bool) {
	var out []asn1.RawValue
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, false
		}
		out = append(out, v)
		b = rest
	}
	return out, true
}

// constructed encodes a constructed DER element of the given class and tag
// around encoded elements.
func constructed(class, tag int, elems ...[]byte) []byte {
	var body []byte
	for _, e := range elems {
		body = append(body, e...)
	}
	out, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: body})
	if err != nil {
		panic(err) // a RawValue with its class, tag and bytes set always encodes
	}
	return out
}

// keyNotImplemented reports whether a SubjectPublicKeyInfo holds an EC key
// whose curve crypto/x509 does not implement: a named curve other than its
// four, or the curve given by explicit parameters (specifiedCurve) or left
// to the issuer (implicitCurve, RFC 3279 §2.3.5). Such a key is not a
// decoding failure (§10.5 step 1): no library implements every curve, and
// an OID assigned to no curve cannot be told from one this build lacks.
func keyNotImplemented(spki []byte) bool {
	var info struct {
		Algorithm asn1.RawValue
		Key       asn1.BitString
	}
	if rest, err := asn1.Unmarshal(spki, &info); err != nil || len(rest) != 0 {
		return false
	}
	alg, ok := elements(info.Algorithm.Bytes)
	if !ok || len(alg) != 2 {
		return false
	}
	var oid asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(alg[0].FullBytes, &oid); err != nil || len(rest) != 0 || !oid.Equal(oidPublicKeyEC) {
		return false
	}
	params := alg[1]
	if params.Class != asn1.ClassUniversal {
		return false
	}
	switch params.Tag {
	case asn1.TagOID:
		var curve asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(params.FullBytes, &curve); err != nil || len(rest) != 0 {
			return false
		}
		for _, c := range implementedCurves {
			if curve.Equal(c) {
				return false
			}
		}
		return true
	case asn1.TagSequence, asn1.TagNull:
		return true
	}
	return false
}

// parseCertificate reads one certificate. The stock parser refuses a
// certificate whose EC key is on a curve it does not implement; such a
// certificate is read with its key left unread instead (a nil PublicKey).
// Every other certificate the stock parser refuses is not a certificate.
func parseCertificate(der []byte) (*x509.Certificate, error) {
	if !certificateShape(der) {
		return nil, errNotCertificate
	}
	c, err := x509.ParseCertificate(der)
	if err == nil {
		return c, nil
	}
	var cert asn1.RawValue
	if rest, e := asn1.Unmarshal(der, &cert); e != nil || len(rest) != 0 || cert.Tag != asn1.TagSequence {
		return nil, err
	}
	parts, ok := elements(cert.Bytes) // tbsCertificate, signatureAlgorithm, signature
	if !ok || len(parts) != 3 {
		return nil, err
	}
	fields, ok := elements(parts[0].Bytes)
	spkiAt := 5 // after serialNumber, signature, issuer, validity and subject
	if ok && len(fields) > 0 && fields[0].Class == asn1.ClassContextSpecific && fields[0].Tag == 0 {
		spkiAt++ // after the version, too
	}
	if !ok || len(fields) <= spkiAt || !keyNotImplemented(fields[spkiAt].FullBytes) {
		return nil, err
	}
	spki := fields[spkiAt].FullBytes
	placeholder, e := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidKeyUnread}})
	if e != nil {
		return nil, err
	}
	raw := make([][]byte, len(fields))
	for i, f := range fields {
		raw[i] = f.FullBytes
	}
	raw[spkiAt] = placeholder
	shell := constructed(asn1.ClassUniversal, asn1.TagSequence,
		constructed(asn1.ClassUniversal, asn1.TagSequence, raw...), parts[1].FullBytes, parts[2].FullBytes)
	c, e = x509.ParseCertificate(shell)
	if e != nil {
		return nil, err
	}
	c.Raw, c.RawTBSCertificate, c.RawSubjectPublicKeyInfo = der, parts[0].FullBytes, spki
	return c, nil
}

// parseCertificates reads the certificates of a SignedData (its [0] field).
func parseCertificates(field asn1.RawValue) ([]*x509.Certificate, bool) {
	elems, ok := elements(field.Bytes)
	if !ok {
		return nil, false
	}
	var certs []*x509.Certificate
	for _, e := range elems {
		c, err := parseCertificate(e.FullBytes)
		if err != nil {
			return nil, false
		}
		certs = append(certs, c)
	}
	return certs, true
}

// KeyImplemented reports whether this build verifies signatures under a
// certificate's public key: RSA, ECDSA on P-224, P-256, P-384 and P-521,
// Ed25519 and ML-DSA, as crypto/x509 does. A DSA key, a key left unread
// and any other are not.
func KeyImplemented(c *x509.Certificate) bool {
	switch c.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *mldsa.PublicKey:
		return true
	}
	return false
}

// signerOf returns the first certificate the sid of a SignerInfo names, in
// either form of RFC 5652 §5.3, or nil: by issuerAndSerialNumber, the one
// whose issuer Name is byte for byte the sid's and whose serial number is
// the sid's; by subjectKeyIdentifier [0], the one whose
// subjectKeyIdentifier extension holds, byte for byte, the sid's key
// identifier.
func signerOf(sid asn1.RawValue, certs []*x509.Certificate) *x509.Certificate {
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 && !sid.IsCompound {
		for _, c := range certs {
			if id, ok := keyIdentifier(c); ok && bytes.Equal(id, sid.Bytes) {
				return c
			}
		}
		return nil
	}
	var ias struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	if rest, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil || len(rest) != 0 || ias.Serial == nil {
		return nil
	}
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 {
			return c
		}
	}
	return nil
}

// keyIdentifier returns the key identifier a certificate's
// subjectKeyIdentifier extension holds, and whether it has that extension.
// certificateShape has held the extension's value to one OCTET STRING.
func keyIdentifier(c *x509.Certificate) ([]byte, bool) {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidSubjectKeyID) {
			v, _, ok := readElement(e.Value)
			return v.body, ok
		}
	}
	return nil, false
}

func strictBase64(s string) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return nil, false
		}
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return b, true
}

// parse is step 1. It returns the token, or nil for one that is not what
// step 1 requires.
func parse(s string) *token {
	der, ok := strictBase64(s)
	if !ok || !isDER(der) || !tokenShape(der) {
		return nil
	}
	var resp timeStampResp
	if rest, err := asn1.Unmarshal(der, &resp); err != nil || len(rest) != 0 {
		return nil
	}
	if resp.Status.Status != 0 && resp.Status.Status != 1 {
		return nil
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil
	}
	var ci contentInfo
	if rest, err := asn1.Unmarshal(resp.TimeStampToken.FullBytes, &ci); err != nil || len(rest) != 0 || !ci.ContentType.Equal(oidSignedData) {
		return nil
	}
	var sd signedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) != 0 {
		return nil
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) || len(sd.SignerInfos) != 1 {
		return nil
	}
	var octets []byte
	if rest, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &octets); err != nil || len(rest) != 0 {
		return nil
	}
	t := &token{}
	if t.tst, ok = readTSTInfo(octets); !ok {
		return nil
	}
	if rest, err := asn1.Unmarshal(sd.SignerInfos[0].FullBytes, &t.signerInf); err != nil || len(rest) != 0 {
		return nil
	}
	if t.certs, ok = parseCertificates(sd.Certificates); !ok {
		return nil
	}
	if t.signer = signerOf(t.signerInf.SID, t.certs); t.signer == nil {
		return nil
	}
	return t
}

func parseAttrs(raw asn1.RawValue) ([]attribute, bool) {
	if len(raw.Bytes) == 0 {
		return nil, false
	}
	var out []attribute
	rest := raw.Bytes
	for len(rest) > 0 {
		var a attribute
		var err error
		rest, err = asn1.Unmarshal(rest, &a)
		if err != nil {
			return nil, false
		}
		out = append(out, a)
	}
	return out, true
}

func findAttr(attrs []attribute, oid asn1.ObjectIdentifier) (asn1.RawValue, int) {
	var found asn1.RawValue
	n := 0
	for _, a := range attrs {
		if a.Type.Equal(oid) {
			found = a.Values
			n++
		}
	}
	return found, n
}

// singleValue returns the only value of an attribute's SET.
func singleValue(set asn1.RawValue) ([]byte, bool) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(set.Bytes, &v)
	if err != nil || len(rest) != 0 {
		return nil, false
	}
	return v.FullBytes, true
}

// certID is the first certificate identifier of a signingCertificate(V2).
type certID struct {
	hash     crypto.Hash // 0 for an ESSCertIDv2 hash algorithm this build does not implement
	certHash []byte
	issuer   []byte // Name DER, nil when issuerSerial is absent
	serial   *big.Int
}

func parseCertID(value []byte, v2 bool) (*certID, error) {
	var outer struct {
		Certs    []asn1.RawValue
		Policies asn1.RawValue `asn1:"optional"`
	}
	if rest, err := asn1.Unmarshal(value, &outer); err != nil || len(rest) != 0 || len(outer.Certs) == 0 {
		return nil, errors.New("bad signingCertificate")
	}
	var parts []asn1.RawValue
	rest := outer.Certs[0].Bytes
	for len(rest) > 0 {
		var p asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &p); err != nil {
			return nil, err
		}
		parts = append(parts, p)
	}
	id := &certID{hash: crypto.SHA1}
	i := 0
	if v2 {
		id.hash = crypto.SHA256
		if i < len(parts) && parts[i].Class == asn1.ClassUniversal && parts[i].Tag == asn1.TagSequence {
			// An AlgorithmIdentifier of another shape names no algorithm
			// the certificate's hash was made with (§10.5 step 1).
			e, _, ok := readElement(parts[i].FullBytes)
			if !ok || !algorithmIdentifier(e) {
				return nil, errors.New("bad hashAlgorithm")
			}
			var alg pkix.AlgorithmIdentifier
			if _, err := asn1.Unmarshal(parts[i].FullBytes, &alg); err != nil {
				return nil, err
			}
			id.hash = digestAlgorithm(alg.Algorithm)
			i++
		}
	}
	if i >= len(parts) || parts[i].Class != asn1.ClassUniversal || parts[i].Tag != asn1.TagOctetString {
		return nil, errors.New("bad certHash")
	}
	id.certHash = parts[i].Bytes
	i++
	if i < len(parts) {
		var is struct {
			Issuer asn1.RawValue
			Serial *big.Int
		}
		if _, err := asn1.Unmarshal(parts[i].FullBytes, &is); err != nil {
			return nil, err
		}
		// GeneralNames: the first directoryName [4] EXPLICIT Name.
		rest := is.Issuer.Bytes
		for len(rest) > 0 {
			var gn asn1.RawValue
			var err error
			if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
				return nil, err
			}
			if gn.Class == asn1.ClassContextSpecific && gn.Tag == 4 {
				id.issuer = gn.Bytes
				break
			}
		}
		if id.issuer == nil {
			return nil, errors.New("issuerSerial without a directoryName")
		}
		id.serial = is.Serial
	}
	return id, nil
}

// digestAlgorithm is the hash a digest algorithm identifier names, of those
// this build implements: SHA-1, SHA-256, SHA-384 and SHA-512, or 0.
func digestAlgorithm(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1
	case oid.Equal(oidSHA256):
		return crypto.SHA256
	case oid.Equal(oidSHA384):
		return crypto.SHA384
	case oid.Equal(oidSHA512):
		return crypto.SHA512
	}
	return 0
}

// digest is b's digest under h, one of the hashes digestAlgorithm names.
func digest(h crypto.Hash, b []byte) []byte {
	switch h {
	case crypto.SHA1:
		s := sha1.Sum(b) //nolint:gosec
		return s[:]
	case crypto.SHA256:
		s := sha256.Sum256(b)
		return s[:]
	case crypto.SHA384:
		s := sha512.Sum384(b)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(b)
		return s[:]
	}
	panic(fmt.Sprintf("rfc3161: no digest %v", h))
}

// timestampingOnly reports whether a certificate's extendedKeyUsage
// extension is marked critical and names id-kp-timeStamping as its one
// purpose.
func timestampingOnly(c *x509.Certificate) bool {
	for _, e := range c.Extensions {
		if !e.Id.Equal(oidExtKeyUsage) {
			continue
		}
		if !e.Critical {
			return false
		}
		var oids []asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(e.Value, &oids); err != nil || len(rest) != 0 {
			return false
		}
		return len(oids) == 1 && oids[0].Equal(oidKPTimeStamping)
	}
	return false
}

// isMissingDependency reports whether an error of crypto/x509 says it does
// not implement an algorithm, rather than that a signature failed. An MD5
// signature, which crypto/x509 refuses to verify, is one.
func isMissingDependency(err error) bool {
	var insecure x509.InsecureAlgorithmError
	return errors.Is(err, x509.ErrUnsupportedAlgorithm) || errors.As(err, &insecure)
}

// The outcome of one requirement of step 3.
type finding int

const (
	met     finding = iota
	unmet           // the requirement does not hold
	unknown         // it needs an algorithm or a key this build does not implement
)

// signature is step 3. It returns "" when every requirement holds, and
// otherwise a reason: verification_failed when a requirement this build
// can check does not hold, whatever the others need; missing_dependency
// when each of those holds and another needs an algorithm or a key this
// build does not implement (§10.5 step 5: a finding comes before a missing
// dependency at step 3).
func signature(t *token) string {
	attrs, ok := parseAttrs(t.signerInf.SignedAttrs)
	if !ok {
		return ReasonVerificationFailed
	}
	lacking := false
	for _, requirement := range []func() finding{
		func() finding { return contentType(attrs) },
		func() finding { return messageDigest(t, attrs) },
		func() finding { return signerBinding(t, attrs) },
		func() finding { return timestamping(t.signer) },
		func() finding { return cmsSignature(t) },
	} {
		switch requirement() {
		case unmet:
			return ReasonVerificationFailed
		case unknown:
			lacking = true
		}
	}
	if lacking {
		return ReasonMissingDependency
	}
	return ""
}

// contentType: the signed attributes hold exactly one content-type
// attribute, whose one value is id-ct-TSTInfo.
func contentType(attrs []attribute) finding {
	set, n := findAttr(attrs, oidContentType)
	if n != 1 {
		return unmet
	}
	v, ok := singleValue(set)
	if !ok {
		return unmet
	}
	var oid asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(v, &oid); err != nil || len(rest) != 0 || !oid.Equal(oidTSTInfo) {
		return unmet
	}
	return met
}

// messageDigest: the signed attributes hold exactly one message-digest
// attribute, whose one value is an OCTET STRING holding the digest of the
// TSTInfo under the SignerInfo's digestAlgorithm.
func messageDigest(t *token, attrs []attribute) finding {
	set, n := findAttr(attrs, oidMessageDigest)
	if n != 1 {
		return unmet
	}
	v, ok := singleValue(set)
	if !ok {
		return unmet
	}
	e, _, ok := readElement(v)
	if !ok || !isPrimitive(e, asn1.TagOctetString) {
		return unmet
	}
	h := digestAlgorithm(t.signerInf.DigestAlgorithm.Algorithm)
	if h == 0 {
		return unknown
	}
	if !bytes.Equal(e.body, digest(h, t.tst.raw)) {
		return unmet
	}
	return met
}

// signerBinding: the signed attributes hold a signingCertificate or a
// signingCertificateV2 attribute, or both, neither more than once, and the
// first certificate identifier of each names the signer's certificate: its
// certHash is the certificate's hash, and its issuerSerial, when present,
// names the certificate's issuer and serial number.
func signerBinding(t *token, attrs []attribute) finding {
	result, present := met, false
	for _, v2 := range []bool{false, true} {
		oid := oidSigningCert
		if v2 {
			oid = oidSigningCertV2
		}
		set, n := findAttr(attrs, oid)
		if n == 0 {
			continue
		}
		present = true
		if n != 1 {
			return unmet
		}
		val, ok := singleValue(set)
		if !ok {
			return unmet
		}
		id, err := parseCertID(val, v2)
		if err != nil {
			return unmet
		}
		if id.issuer != nil && (!bytes.Equal(id.issuer, t.signer.RawIssuer) || id.serial == nil || id.serial.Cmp(t.signer.SerialNumber) != 0) {
			return unmet
		}
		if id.hash == 0 {
			result = unknown
			continue
		}
		if !bytes.Equal(id.certHash, digest(id.hash, t.signer.Raw)) {
			return unmet
		}
	}
	if !present {
		return unmet
	}
	return result
}

// timestamping: the signer's certificate is a timestamping certificate.
func timestamping(c *x509.Certificate) finding {
	if !timestampingOnly(c) {
		return unmet
	}
	return met
}

// cmsSignature: the signature of the SignerInfo verifies under the signer's
// key over the signed attributes as the token carries them: the octets of
// signedAttrs, with the first, the [0] tag, replaced by 0x31, the tag of a
// SET OF, and the length and contents octets unchanged (RFC 5652 §5.4).
// They are never encoded again: step 1 does not require the attributes in
// DER SET OF order, which an encoder would put them in.
func cmsSignature(t *token) finding {
	alg := signatureAlgorithm(t.signerInf)
	if alg == x509.UnknownSignatureAlgorithm || !KeyImplemented(t.signer) {
		return unknown
	}
	signed := bytes.Clone(t.signerInf.SignedAttrs.FullBytes)
	signed[0] = 0x31
	if err := t.signer.CheckSignature(alg, signed, t.signerInf.Signature); err != nil {
		if isMissingDependency(err) {
			return unknown
		}
		return unmet
	}
	return met
}

// Signature algorithms a SignerInfo names.
var (
	oidECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidMLDSA44         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

// signatureAlgorithm is the crypto/x509 algorithm of a SignerInfo's
// signature, or x509.UnknownSignatureAlgorithm for one this build does not
// implement: ECDSA and RSA PKCS #1 v1.5, each with SHA-1, SHA-256, SHA-384
// or SHA-512, Ed25519 and ML-DSA. A signature algorithm that names its hash
// is taken with it (RFC 5754 §3); rsaEncryption (RFC 3370 §3.2), and an EC
// key's algorithm or curve named where the signature algorithm belongs, as
// some signers write it, are taken with the hash of the digestAlgorithm.
// RSASSA-PSS, DSA and MD5 are not implemented.
func signatureAlgorithm(si signerInfo) x509.SignatureAlgorithm {
	byDigest := func(rsa bool) x509.SignatureAlgorithm {
		algs := map[crypto.Hash][2]x509.SignatureAlgorithm{
			crypto.SHA1:   {x509.ECDSAWithSHA1, x509.SHA1WithRSA},
			crypto.SHA256: {x509.ECDSAWithSHA256, x509.SHA256WithRSA},
			crypto.SHA384: {x509.ECDSAWithSHA384, x509.SHA384WithRSA},
			crypto.SHA512: {x509.ECDSAWithSHA512, x509.SHA512WithRSA},
		}
		a, ok := algs[digestAlgorithm(si.DigestAlgorithm.Algorithm)]
		if !ok {
			return x509.UnknownSignatureAlgorithm
		}
		if rsa {
			return a[1]
		}
		return a[0]
	}
	oid := si.SignatureAlgorithm.Algorithm
	for _, a := range []struct {
		oid asn1.ObjectIdentifier
		alg x509.SignatureAlgorithm
	}{
		{oidECDSAWithSHA1, x509.ECDSAWithSHA1}, {oidECDSAWithSHA256, x509.ECDSAWithSHA256},
		{oidECDSAWithSHA384, x509.ECDSAWithSHA384}, {oidECDSAWithSHA512, x509.ECDSAWithSHA512},
		{oidSHA1WithRSA, x509.SHA1WithRSA}, {oidSHA256WithRSA, x509.SHA256WithRSA},
		{oidSHA384WithRSA, x509.SHA384WithRSA}, {oidSHA512WithRSA, x509.SHA512WithRSA},
		{oidEd25519, x509.PureEd25519},
		{oidMLDSA44, x509.MLDSA44}, {oidMLDSA65, x509.MLDSA65}, {oidMLDSA87, x509.MLDSA87},
	} {
		if oid.Equal(a.oid) {
			return a.alg
		}
	}
	if oid.Equal(oidRSAEncryption) {
		return byDigest(true)
	}
	if oid.Equal(oidPublicKeyEC) {
		return byDigest(false)
	}
	for _, c := range implementedCurves[1:] { // P-256, P-384 and P-521
		if oid.Equal(c) {
			return byDigest(false)
		}
	}
	return x509.UnknownSignatureAlgorithm
}

func validAt(c *x509.Certificate, t time.Time) bool {
	return !t.Before(c.NotBefore) && !t.After(c.NotAfter)
}

// The search of step 4 is bounded, because a hostile token chooses its own
// certificates: many that share one name would otherwise make the number of
// issuer-to-subject paths grow exponentially. A real authority's path is a
// handful of certificates; these bounds sit far above any.
const (
	// maxPathCerts is the longest path, in certificates, the signer and the
	// root included.
	maxPathCerts = 10
	// maxCandidates is the most certificates the search considers: the
	// token's, the supplied intermediates and the supplied roots.
	maxCandidates = 256
	// maxSignatureChecks is the most issuer signatures one search verifies.
	maxSignatureChecks = 1024
	// maxEdges is the most issuer-to-subject name comparisons one search
	// makes.
	maxEdges = 1 << 16
)

// Outcomes of step 4.
const (
	trustValid = "valid" // a path to a supplied root is valid at genTime
	// trustUnchecked: no path is valid, and one to a supplied root would be
	// but for signatures this build cannot check (missing_dependency).
	trustUnchecked = "unchecked"
	trustReached   = "reached" // a path reached a supplied root, and none is valid
	trustNone      = "none"    // no path reached a supplied root
	trustBudget    = "budget"  // the search hit its bounds before deciding
)

// An issuer's signature on a certificate holds, fails, or cannot be checked
// by this build: the issuer's key, or the signature's algorithm (MD5, for
// one), is one it does not implement.
type sigVerdict int

const (
	sigFails sigVerdict = iota
	sigHolds
	sigUnchecked
)

// trust is step 4. It searches breadth first from the signer, and visits
// each certificate once, at its shallowest depth.
//
// For a path to be valid, the signature of every issuer on the certificate
// it issued must verify, the validity period of each certificate must cover
// genTime, and each intermediate between the signer and the root must be a
// CA certificate allowed to sign certificates, with a path-length limit the
// path respects. All of these are decided edge by edge or certificate by
// certificate, except the path-length limit, which depends on where a
// certificate sits and only tightens as it sits deeper. The shallowest visit
// along valid edges therefore decides whether a certificate can lie on a
// valid path, and a search along valid edges finds a valid path whenever
// one of at most maxPathCerts certificates exists.
//
// When none is valid and the search met a signature it cannot check, a
// second search walks those edges too: a path it finds to a supplied root
// is valid but for signatures this build cannot check, which step 5 reports
// as missing_dependency whatever other paths hold ("unchecked"). Otherwise a
// search along names alone, ignoring signatures and validity, tells
// "reached" (some issuer-to-subject path ends at a supplied root:
// verification_failed) from "none".
//
// Past its bounds the search stops and reports "budget", which is never a
// verdict on the token.
func trust(t *token, cfg Trust) string {
	var cands []*x509.Certificate
	seen := map[string]bool{}
	add := func(c *x509.Certificate) {
		if c == nil || seen[string(c.Raw)] {
			return
		}
		seen[string(c.Raw)] = true
		cands = append(cands, c)
	}
	for _, r := range cfg.Roots {
		add(r)
	}
	for _, c := range cfg.Intermediates {
		add(c)
	}
	for _, c := range t.certs {
		add(c)
	}
	if len(cands) > maxCandidates {
		return trustBudget
	}
	isRoot := func(c *x509.Certificate) bool {
		for _, r := range cfg.Roots {
			if r.Equal(c) {
				return true
			}
		}
		return false
	}
	gen := t.tst.genTime
	edges, sigChecks := 0, 0
	// sigCache holds an issuer's signature over a subject by the issuer's
	// public key: certificates that share a key share the answer.
	type sigKey struct{ subject, issuerKey string }
	sigCache := map[sigKey]sigVerdict{}
	unchecked := false // the search met a signature it cannot check
	signs := func(issuer, subject *x509.Certificate) (sigVerdict, bool) {
		k := sigKey{string(subject.Raw), string(issuer.RawSubjectPublicKeyInfo)}
		if v, ok := sigCache[k]; ok {
			return v, true
		}
		if sigChecks >= maxSignatureChecks {
			return sigFails, false
		}
		sigChecks++
		v := sigHolds
		if err := issuer.CheckSignature(subject.SignatureAlgorithm, subject.RawTBSCertificate, subject.Signature); err != nil {
			v = sigFails
			if isMissingDependency(err) {
				v = sigUnchecked
			}
		}
		sigCache[k] = v
		return v, true
	}

	// Along valid edges.
	type node struct {
		c     *x509.Certificate
		depth int // the certificate's index on its path; the signer is 0
	}
	if isRoot(t.signer) {
		// A signer the auditor supplied as a root is a path of one.
		if validAt(t.signer, gen) {
			return trustValid
		}
		return trustReached
	}
	// search walks the edges whose signature holds, and with lenient set
	// also those whose signature this build cannot check. It returns
	// trustValid when it reaches a supplied root, trustBudget at its bounds,
	// and "" otherwise.
	search := func(lenient bool) string {
		visited := map[string]bool{string(t.signer.Raw): true}
		queue := []node{{t.signer, 0}}
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			if n.depth > 0 && isRoot(n.c) {
				return trustValid // every certificate before it was checked on the way
			}
			if n.depth+1 >= maxPathCerts {
				continue
			}
			for _, next := range cands {
				if visited[string(next.Raw)] {
					continue
				}
				if edges++; edges > maxEdges {
					return trustBudget
				}
				if !bytes.Equal(n.c.RawIssuer, next.RawSubject) {
					continue
				}
				sig, decided := signs(next, n.c)
				if !decided {
					return trustBudget
				}
				if sig == sigUnchecked {
					unchecked = true
				}
				if !(sig == sigHolds || lenient && sig == sigUnchecked) || !validAt(next, gen) {
					continue
				}
				d := n.depth + 1
				// As an intermediate, next must be a CA within its path
				// length; a supplied root ends the path and is exempt.
				if !isRoot(next) && !intermediateOK(next, d) {
					continue
				}
				visited[string(next.Raw)] = true
				queue = append(queue, node{next, d})
			}
		}
		return ""
	}
	if validAt(t.signer, gen) {
		if r := search(false); r != "" {
			return r
		}
		if unchecked {
			switch search(true) {
			case trustValid:
				return trustUnchecked
			case trustBudget:
				return trustBudget
			}
		}
	}

	// Along names alone.
	visited := map[string]bool{string(t.signer.Raw): true}
	queue := []node{{t.signer, 0}}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if n.depth > 0 && isRoot(n.c) {
			return trustReached
		}
		if n.depth+1 >= maxPathCerts {
			continue
		}
		for _, next := range cands {
			if visited[string(next.Raw)] {
				continue
			}
			if edges++; edges > maxEdges {
				return trustBudget
			}
			if bytes.Equal(n.c.RawIssuer, next.RawSubject) {
				visited[string(next.Raw)] = true
				queue = append(queue, node{next, n.depth + 1})
			}
		}
	}
	return trustNone
}

// intermediateOK checks the rules of step 4 for a certificate at index i of
// a path (0 is the signer) that is neither its first nor its last: a CA that
// may sign certificates, with no more intermediates below it than its path
// length allows.
func intermediateOK(c *x509.Certificate, i int) bool {
	if !c.BasicConstraintsValid || !c.IsCA {
		return false
	}
	if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return false
	}
	// Intermediates below this one on the path: path[1..i-1].
	if (c.MaxPathLen > 0 || c.MaxPathLenZero) && i-1 > c.MaxPathLen {
		return false
	}
	return true
}

// Authority is the value of the first commonName attribute of the signer
// certificate's subject, taking its attributes in the order they are
// encoded, exactly as the attribute holds it (no escaping, no trimming, an
// empty value kept), or "" when the subject has none (§10.5 step 4).
func Authority(c *x509.Certificate) string {
	for _, a := range c.Subject.Names {
		if a.Type.Equal(oidCommonName) {
			s, _ := a.Value.(string)
			return s
		}
	}
	return ""
}

// Verify runs §10.5 over one publication entry at index i against P.
func Verify(i int, entry *jsonv.Value, p []byte, cfg Trust) Result {
	tokID := fmt.Sprintf("anchor.tsa.token[%d]", i)
	trustID := fmt.Sprintf("anchor.tsa.trust[%d]", i)
	if entry == nil || entry.Kind != jsonv.Object {
		return failed(tokID, trustID, ReasonMalformed)
	}
	if k, ok := entry.Get("kind"); !ok || k.Kind != jsonv.String || k.Lone || k.S != Kind {
		res := Result{Token: report.Check{ID: tokID, Outcome: report.Abstain, Reason: ReasonUnsupportedKind},
			Trust: report.BlockedBy(trustID, tokID)}
		res.Reason = ReasonUnsupportedKind
		return res
	}
	tv, _ := entry.Get("token")
	s, ok := tv.Str()
	if !ok {
		return failed(tokID, trustID, ReasonMalformed)
	}
	return verifyToken(s, p, cfg, tokID, trustID, ReasonMalformed)
}

// Check ids and the malformed reason of the record's own timestamp
// (Verification §4.4).
const (
	IDRecordToken        = "ts.record.token"
	IDRecordTrust        = "ts.record.trust"
	ReasonMalformedToken = "malformed_token"
)

// VerifyRecordToken runs §10.5's steps over the record's own RFC 3161
// token, nonRepudiation.rfc3161Token, with the record's digest as the
// imprint: ts.record.token (parse, imprint, signature and signer), then
// ts.record.trust (the path to a supplied root). A token that does not
// parse is malformed_token.
func VerifyRecordToken(v *jsonv.Value, digest []byte, cfg Trust) Result {
	s, ok := v.Str()
	if !ok || s == "" {
		return failed(IDRecordToken, IDRecordTrust, ReasonMalformedToken)
	}
	return verifyToken(s, digest, cfg, IDRecordToken, IDRecordTrust, ReasonMalformedToken)
}

func failed(tokID, trustID, reason string) Result {
	f := false
	return Result{
		Token: report.Check{ID: tokID, Outcome: report.Wrong, Reason: reason},
		Trust: report.BlockedBy(trustID, tokID),
		Valid: &f, Reason: reason,
	}
}

// verifyToken is steps 1 to 4 over a token's base64 text against an
// imprint.
func verifyToken(s string, imprint []byte, cfg Trust, tokID, trustID, malformed string) (res Result) {
	t := parse(s)
	if t == nil {
		return failed(tokID, trustID, malformed)
	}
	if !bytes.Equal(t.tst.hashAlgorithm, derSHA256) || (t.tst.hashParams != nil && !bytes.Equal(t.tst.hashParams, nullParams)) ||
		!bytes.Equal(t.tst.hashedMessage, imprint) {
		return failed(tokID, trustID, ReasonImprintMismatch)
	}
	res.Token = report.Check{ID: tokID}
	res.Trust = report.BlockedBy(trustID, tokID)
	switch why := signature(t); why {
	case "":
	case ReasonMissingDependency:
		res.Token.Outcome, res.Token.Reason = report.NotChecked, why
		res.Reason = ReasonNotChecked
		return res
	default:
		return failed(tokID, trustID, why)
	}
	res.Token.Outcome = report.Correct
	res.Trust = report.Check{ID: trustID}
	switch trust(t, cfg) {
	case trustValid:
		res.Trust.Outcome = report.Correct
		res.GenTime = t.tst.genTime
		res.Authority = Authority(t.signer)
		res.Trust.SetFact("genTime", report.S(res.GenTime.UTC().Format("2006-01-02T15:04:05.000Z")))
		res.Trust.SetFact("authority", report.S(res.Authority))
		tr := true
		res.Valid = &tr
	case trustUnchecked:
		res.Trust.Outcome, res.Trust.Reason = report.NotChecked, ReasonMissingDependency
		res.Reason = ReasonNotChecked
	case trustReached:
		res.Trust.Outcome, res.Trust.Reason = report.Wrong, ReasonVerificationFailed
		f := false
		res.Valid, res.Reason = &f, ReasonVerificationFailed
	default:
		// trustNone, or trustBudget: a search that hit its bounds has not
		// shown a path to a supplied root, and says nothing against the
		// token.
		res.Trust.Outcome, res.Trust.Reason = report.NotChecked, ReasonNoTrustAnchor
		res.Reason = ReasonNotChecked
	}
	return res
}
