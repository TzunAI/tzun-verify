// SPDX-License-Identifier: BSD-3-Clause-Clear

// Package rfc3161 verifies an rfc3161/1 publication (Anchor §7.3,
// §10.5): an RFC 3161 timestamp token whose imprint is P. A bare §n in this
// package's comments is a section of Anchor; an RFC's sections are named
// with the RFC.
//
// The steps run in order and the first that does not hold decides:
//
//  1. parse: the DER of a granted TimeStampResp, every element of it DER
//     (der.go), that wraps a CMS SignedData over a TSTInfo; the SignedData
//     has a single SignerInfo, and the token itself holds that signer's
//     certificate (malformed_publication). A certificate whose key uses an
//     algorithm or curve this build does not implement is read with its key
//     left unread;
//  2. imprint: SHA-256 and P (imprint_mismatch);
//  3. signature and signer: the stock digitorus/timestamp and
//     digitorus/pkcs7 libraries verify the CMS signature; the signed
//     attributes hold one content type and one message digest; a
//     signingCertificate or signingCertificateV2 attribute binds the signer's
//     certificate; and that certificate's extendedKeyUsage extension is
//     marked critical and names timestamping as its one purpose
//     (verification_failed);
//  4. trust: some path from the signer to a root the auditor supplied is
//     valid at genTime (verification_failed when a path reaches a supplied
//     root but none is valid; not-checked, no_matching_trust_anchor, when
//     none reaches one).
//
// Step 5: a step that needs a key or an algorithm this build does not
// implement (a curve other than P-224, P-256, P-384 and P-521, a DSA key, an
// MD5 signature, a CMS signature algorithm the CMS library does not map)
// is not-checked, missing_dependency, on its check.
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

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

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
	// cmsSignatureAlgorithms are the SignerInfo signature algorithms the CMS
	// library maps to one crypto/x509 verifies. DSA is not among them.
	cmsSignatureAlgorithms = []asn1.ObjectIdentifier{
		pkcs7.OIDDigestAlgorithmECDSASHA1, pkcs7.OIDDigestAlgorithmECDSASHA256,
		pkcs7.OIDDigestAlgorithmECDSASHA384, pkcs7.OIDDigestAlgorithmECDSASHA512,
		pkcs7.OIDPublicKeyAlgorithmEC,
		pkcs7.OIDEncryptionAlgorithmRSA, pkcs7.OIDEncryptionAlgorithmRSASHA1, pkcs7.OIDEncryptionAlgorithmRSASHA256,
		pkcs7.OIDEncryptionAlgorithmRSASHA384, pkcs7.OIDEncryptionAlgorithmRSASHA512,
		pkcs7.OIDEncryptionAlgorithmECDSAP256, pkcs7.OIDEncryptionAlgorithmECDSAP384, pkcs7.OIDEncryptionAlgorithmECDSAP521,
		pkcs7.OIDEncryptionAlgorithmEDDSA25519,
		pkcs7.OIDSignatureAlgorithmMLDSA44, pkcs7.OIDSignatureAlgorithmMLDSA65, pkcs7.OIDSignatureAlgorithmMLDSA87,
	}
	nullParams           = []byte{0x05, 0x00}
	errUnsupportedDigest = errors.New("rfc3161: unsupported certHash algorithm")
)

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

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"tag:0,optional"`
	Micros  int `asn1:"tag:1,optional"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension `asn1:"tag:1,optional"`
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
	// stock is the token (its ContentInfo) as the CMS library reads it:
	// less any certificate whose key this build does not implement. Nothing
	// before step 4 needs those, and the signature does not cover them.
	stock     []byte
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
// certificate is read with its key left unread instead (a nil PublicKey),
// and readable is false. Every other certificate the stock parser refuses
// is not a certificate.
func parseCertificate(der []byte) (c *x509.Certificate, readable bool, err error) {
	c, err = x509.ParseCertificate(der)
	if err == nil {
		return c, true, nil
	}
	var cert asn1.RawValue
	if rest, e := asn1.Unmarshal(der, &cert); e != nil || len(rest) != 0 || cert.Tag != asn1.TagSequence {
		return nil, false, err
	}
	parts, ok := elements(cert.Bytes) // tbsCertificate, signatureAlgorithm, signature
	if !ok || len(parts) != 3 {
		return nil, false, err
	}
	fields, ok := elements(parts[0].Bytes)
	spkiAt := 5 // after serialNumber, signature, issuer, validity and subject
	if ok && len(fields) > 0 && fields[0].Class == asn1.ClassContextSpecific && fields[0].Tag == 0 {
		spkiAt++ // after the version, too
	}
	if !ok || len(fields) <= spkiAt || !keyNotImplemented(fields[spkiAt].FullBytes) {
		return nil, false, err
	}
	spki := fields[spkiAt].FullBytes
	placeholder, e := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidKeyUnread}})
	if e != nil {
		return nil, false, err
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
		return nil, false, err
	}
	c.Raw, c.RawTBSCertificate, c.RawSubjectPublicKeyInfo = der, parts[0].FullBytes, spki
	return c, false, nil
}

// parseCertificates reads the certificates of a SignedData (its [0] field),
// and returns them with the encoding of that field less the certificates
// the stock parser cannot read.
func parseCertificates(field asn1.RawValue) ([]*x509.Certificate, []byte, bool) {
	elems, ok := elements(field.Bytes)
	if !ok {
		return nil, nil, false
	}
	var certs []*x509.Certificate
	var stock [][]byte
	for _, e := range elems {
		c, readable, err := parseCertificate(e.FullBytes)
		if err != nil {
			return nil, nil, false
		}
		certs = append(certs, c)
		if readable {
			stock = append(stock, e.FullBytes)
		}
	}
	if len(stock) == len(elems) {
		return certs, field.FullBytes, true
	}
	return certs, constructed(asn1.ClassContextSpecific, 0, stock...), true
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

// signerOf returns the first certificate the SignerInfo names by issuer and
// serial number, as the CMS library looks it up, or nil.
func signerOf(si signerInfo, certs []*x509.Certificate) *x509.Certificate {
	var ias struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	if rest, err := asn1.Unmarshal(si.SID.FullBytes, &ias); err != nil || len(rest) != 0 || ias.Serial == nil {
		return nil
	}
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 {
			return c
		}
	}
	return nil
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

// parse is step 1. It returns the token, or the reason step 1 does not
// hold: "" with a nil token for a token that is not what step 1 requires,
// or ReasonMissingDependency for one the linked CMS library cannot read.
func parse(s string) (*token, string) {
	t, ok, why := parseToken(s)
	if !ok {
		return nil, why
	}
	return t, ""
}

func parseToken(s string) (*token, bool, string) {
	der, ok := strictBase64(s)
	if !ok || !isDER(der) {
		return nil, false, ""
	}
	t, ok := parseStrict(der)
	if ok {
		return t, true, ""
	}
	if skiSigner(der) {
		// A signer named by subjectKeyIdentifier is legal CMS (RFC 5652
		// §5.3); the linked library finds a signer only by issuer and
		// serial number. That is a gap in this verifier, not in the token
		// (§10.5 step 5).
		return nil, false, ReasonMissingDependency
	}
	return nil, false, ""
}

// skiSigner reports whether a token otherwise well-formed names its signer
// by subjectKeyIdentifier ([0]), and carries the certificate it names.
func skiSigner(der []byte) bool {
	var resp timeStampResp
	if rest, err := asn1.Unmarshal(der, &resp); err != nil || len(rest) != 0 || len(resp.TimeStampToken.FullBytes) == 0 {
		return false
	}
	var ci contentInfo
	if rest, err := asn1.Unmarshal(resp.TimeStampToken.FullBytes, &ci); err != nil || len(rest) != 0 || !ci.ContentType.Equal(oidSignedData) {
		return false
	}
	var sd signedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) != 0 || len(sd.SignerInfos) != 1 {
		return false
	}
	var si signerInfo
	if rest, err := asn1.Unmarshal(sd.SignerInfos[0].FullBytes, &si); err != nil || len(rest) != 0 {
		return false
	}
	if si.SID.Class != asn1.ClassContextSpecific || si.SID.Tag != 0 || si.SID.IsCompound || len(si.SID.Bytes) == 0 {
		return false
	}
	certs, _, ok := parseCertificates(sd.Certificates)
	if !ok {
		return false
	}
	for _, c := range certs {
		if bytes.Equal(c.SubjectKeyId, si.SID.Bytes) {
			return true
		}
	}
	return false
}

// parseStrict decodes a token that isDER has checked.
func parseStrict(der []byte) (*token, bool) {
	var resp timeStampResp
	rest, err := asn1.Unmarshal(der, &resp)
	if err != nil || len(rest) != 0 {
		return nil, false
	}
	if resp.Status.Status != 0 && resp.Status.Status != 1 {
		return nil, false
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, false
	}
	tok := resp.TimeStampToken.FullBytes
	var ci contentInfo
	if rest, err := asn1.Unmarshal(tok, &ci); err != nil || len(rest) != 0 || !ci.ContentType.Equal(oidSignedData) {
		return nil, false
	}
	var sd signedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) != 0 {
		return nil, false
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) || len(sd.SignerInfos) != 1 {
		return nil, false
	}
	var octets []byte
	if rest, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &octets); err != nil || len(rest) != 0 {
		return nil, false
	}
	t := &token{stock: tok}
	if rest, err := asn1.Unmarshal(octets, &t.tst); err != nil || len(rest) != 0 {
		return nil, false
	}
	if rest, err := asn1.Unmarshal(sd.SignerInfos[0].FullBytes, &t.signerInf); err != nil || len(rest) != 0 {
		return nil, false
	}
	certs, stockCerts, ok := parseCertificates(sd.Certificates)
	if !ok {
		return nil, false
	}
	if !bytes.Equal(stockCerts, sd.Certificates.FullBytes) {
		// Rebuild the token around the certificates the CMS library reads.
		var sdSeq, ciSeq asn1.RawValue
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &sdSeq); err != nil {
			return nil, false
		}
		fields, ok := elements(sdSeq.Bytes)
		if !ok {
			return nil, false
		}
		raw := make([][]byte, 0, len(fields))
		for _, f := range fields {
			if f.Class == asn1.ClassContextSpecific && f.Tag == 0 {
				raw = append(raw, stockCerts)
			} else {
				raw = append(raw, f.FullBytes)
			}
		}
		if _, err := asn1.Unmarshal(tok, &ciSeq); err != nil {
			return nil, false
		}
		ciFields, ok := elements(ciSeq.Bytes)
		if !ok || len(ciFields) != 2 {
			return nil, false
		}
		t.stock = constructed(asn1.ClassUniversal, asn1.TagSequence, ciFields[0].FullBytes,
			constructed(asn1.ClassContextSpecific, 0, constructed(asn1.ClassUniversal, asn1.TagSequence, raw...)))
	}
	if _, err := pkcs7.Parse(t.stock); err != nil {
		return nil, false
	}
	t.certs = certs
	t.signer = signerOf(t.signerInf, certs)
	if t.signer == nil {
		return nil, false
	}
	return t, true
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
	hash     crypto.Hash
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
			var alg pkix.AlgorithmIdentifier
			if _, err := asn1.Unmarshal(parts[i].FullBytes, &alg); err != nil {
				return nil, err
			}
			switch {
			case alg.Algorithm.Equal(oidSHA256):
				id.hash = crypto.SHA256
			case alg.Algorithm.Equal(oidSHA384):
				id.hash = crypto.SHA384
			case alg.Algorithm.Equal(oidSHA512):
				id.hash = crypto.SHA512
			case alg.Algorithm.Equal(oidSHA1):
				id.hash = crypto.SHA1
			default:
				return nil, errUnsupportedDigest
			}
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

func hashCert(h crypto.Hash, der []byte) []byte {
	switch h {
	case crypto.SHA1:
		s := sha1.Sum(der) //nolint:gosec
		return s[:]
	case crypto.SHA384:
		s := sha512.Sum384(der)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(der)
		return s[:]
	default:
		s := sha256.Sum256(der)
		return s[:]
	}
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

// isMissingDependency reports whether an error of the stock libraries says
// they do not implement an algorithm, rather than that a check failed. An
// MD5 signature, which crypto/x509 refuses to verify, is one.
func isMissingDependency(err error) bool {
	var insecure x509.InsecureAlgorithmError
	return errors.Is(err, pkcs7.ErrUnsupportedAlgorithm) || errors.Is(err, x509.ErrUnsupportedAlgorithm) ||
		errors.As(err, &insecure) || errors.Is(err, errUnsupportedDigest)
}

// cmsSignatureImplemented reports whether the stock libraries can check the
// token's CMS signature: the signer's key is one this build implements, and
// the SignerInfo names a signature algorithm the CMS library maps.
func cmsSignatureImplemented(t *token) bool {
	if !KeyImplemented(t.signer) {
		return false
	}
	for _, oid := range cmsSignatureAlgorithms {
		if t.signerInf.SignatureAlgorithm.Algorithm.Equal(oid) {
			return true
		}
	}
	return false
}

// signature is step 3. It returns "" when it holds, or a reason.
func signature(t *token) string {
	attrs, ok := parseAttrs(t.signerInf.SignedAttrs)
	if !ok {
		return ReasonVerificationFailed
	}
	ct, n := findAttr(attrs, oidContentType)
	var ctOID asn1.ObjectIdentifier
	ok2 := false
	if ctv, ok := singleValue(ct); ok {
		rest, err := asn1.Unmarshal(ctv, &ctOID)
		ok2 = err == nil && len(rest) == 0
	}
	if n != 1 || !ok2 || !ctOID.Equal(oidTSTInfo) {
		return ReasonVerificationFailed
	}
	if _, n := findAttr(attrs, oidMessageDigest); n != 1 {
		return ReasonVerificationFailed
	}
	// The CMS signature and message digest, by the stock libraries, over the
	// key and the algorithm they implement (step 5).
	if !cmsSignatureImplemented(t) {
		return ReasonMissingDependency
	}
	ts, err := timestamp.Parse(t.stock)
	if err != nil {
		if isMissingDependency(err) {
			return ReasonMissingDependency
		}
		return ReasonVerificationFailed
	}
	if !bytes.Equal(ts.HashedMessage, t.tst.MessageImprint.HashedMessage) || !ts.Time.Equal(t.tst.GenTime) {
		return ReasonVerificationFailed
	}
	// The signer binding.
	bound := 0
	for _, v2 := range []bool{false, true} {
		oid := oidSigningCert
		if v2 {
			oid = oidSigningCertV2
		}
		set, n := findAttr(attrs, oid)
		if n == 0 {
			continue
		}
		if n != 1 {
			return ReasonVerificationFailed
		}
		val, ok := singleValue(set)
		if !ok {
			return ReasonVerificationFailed
		}
		id, err := parseCertID(val, v2)
		if err != nil {
			if errors.Is(err, errUnsupportedDigest) {
				return ReasonMissingDependency
			}
			return ReasonVerificationFailed
		}
		if !bytes.Equal(id.certHash, hashCert(id.hash, t.signer.Raw)) {
			return ReasonVerificationFailed
		}
		if id.issuer != nil && (!bytes.Equal(id.issuer, t.signer.RawIssuer) || id.serial == nil || id.serial.Cmp(t.signer.SerialNumber) != 0) {
			return ReasonVerificationFailed
		}
		bound++
	}
	if bound == 0 {
		return ReasonVerificationFailed
	}
	if !timestampingOnly(t.signer) {
		return ReasonVerificationFailed
	}
	return ""
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
	gen := t.tst.GenTime
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
	t, why := parse(s)
	switch {
	case why == ReasonMissingDependency:
		res.Token = report.Check{ID: tokID, Outcome: report.NotChecked, Reason: why}
		res.Trust = report.BlockedBy(trustID, tokID)
		res.Reason = ReasonNotChecked
		return res
	case t == nil:
		return failed(tokID, trustID, malformed)
	}
	mi := t.tst.MessageImprint
	params := mi.HashAlgorithm.Parameters.FullBytes
	if !mi.HashAlgorithm.Algorithm.Equal(oidSHA256) || (len(params) != 0 && !bytes.Equal(params, nullParams)) ||
		!bytes.Equal(mi.HashedMessage, imprint) {
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
		res.GenTime = t.tst.GenTime
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
