// SPDX-License-Identifier: BSD-3-Clause-Clear

// Package testpki builds a throwaway RFC 3161 PKI and tokens for tests: a
// root, a timestamping intermediate CA, a timestamping signer, and
// certificates for other purposes under the same root. Only tests import it.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // ESSCertID's certHash is SHA-1 by definition (RFC 2634).
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"slices"
	"time"

	"github.com/digitorus/timestamp"
)

var (
	oidEKU          = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidServerAuth   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
)

// Cert is a certificate with its key.
type Cert struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

var serial int64 = 1000

func mk(tmpl *x509.Certificate, parent *Cert) *Cert {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return mkWithKey(tmpl, parent, key)
}

func mkWithKey(tmpl *x509.Certificate, parent *Cert, key *ecdsa.PrivateKey) *Cert {
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	signer, parentCert := key, tmpl
	if parent != nil {
		signer, parentCert = parent.Key, parent.Cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, signer)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &Cert{Cert: c, Key: key}
}

// EKU returns an extendedKeyUsage extension.
func EKU(critical bool, purposes ...asn1.ObjectIdentifier) pkix.Extension {
	v, err := asn1.Marshal(purposes)
	if err != nil {
		panic(err)
	}
	return pkix.Extension{Id: oidEKU, Critical: critical, Value: v}
}

// Purposes.
var (
	TimeStamping = oidTimeStamping
	ServerAuth   = oidServerAuth
)

// Root is a self-signed CA.
func Root(name string) *Cert {
	now := time.Now()
	return mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: name}, NotBefore: now.AddDate(-20, 0, 0), NotAfter: now.AddDate(20, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil)
}

// Intermediate is a CA under parent; ca false gives a certificate that
// claims no CA role.
func Intermediate(name string, parent *Cert, ca bool) *Cert {
	now := time.Now()
	t := &x509.Certificate{
		Subject: pkix.Name{CommonName: name}, NotBefore: now.AddDate(-10, 0, 0), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	if ca {
		t.IsCA, t.BasicConstraintsValid = true, true
	} else {
		t.KeyUsage = x509.KeyUsageDigitalSignature
	}
	return mk(t, parent)
}

// Signer is an end-entity certificate under parent with the given
// extensions and validity.
func Signer(name string, parent *Cert, notBefore, notAfter time.Time, ext ...pkix.Extension) *Cert {
	return mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: name, Organization: []string{"Test"}}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: ext,
	}, parent)
}

// TSASigner is a timestamping signer valid for ten years either side of now.
func TSASigner(name string, parent *Cert) *Cert {
	now := time.Now()
	return Signer(name, parent, now.AddDate(-5, 0, 0), now.AddDate(5, 0, 0), EKU(true, TimeStamping))
}

// Token returns a base64 DER TimeStampResp over digest (SHA-256 imprint),
// signed by signer, carrying signer and chain, at genTime.
func Token(digest []byte, signer *Cert, chain []*x509.Certificate, genTime time.Time, withCerts bool) string {
	ts := timestamp.Timestamp{
		HashAlgorithm: crypto.SHA256, HashedMessage: digest, Time: genTime,
		Policy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, AddTSACertificate: withCerts, Certificates: chain,
	}
	der, err := ts.CreateResponseWithOpts(signer.Cert, signer.Key, crypto.SHA256)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// Rejection returns a base64 TimeStampResp with status rejection.
func Rejection() string {
	der, err := timestamp.CreateErrorResponse(timestamp.Rejection, timestamp.BadAlgorithm)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// TokenOptions control a token built field by field, for the cases a
// signing library will not produce: a missing or wrong signer binding, a
// content-type attribute naming something else.
type TokenOptions struct {
	Digest []byte
	// GenTime is written with the fraction of a second it carries, which
	// RFC 3161 §2.4.2 allows; Token writes whole seconds only.
	GenTime time.Time
	Signer  *Cert
	// Certs are carried in the token; the signer's certificate is added
	// unless OmitSignerCert is set.
	Certs          []*x509.Certificate
	OmitSignerCert bool
	// ContentType is the content-type attribute's value; nil means
	// id-ct-TSTInfo. OmitContentType leaves the attribute out.
	ContentType     asn1.ObjectIdentifier
	OmitContentType bool
	// Binding is "v2" (the default), "v2-sha384", "v1" or "none"; or
	// "v2-unknown", whose ESSCertIDv2 names SHA3-256, or "v2-alg-three",
	// whose hashAlgorithm is SHA-256 with a NULL and a second NULL.
	Binding string
	// CertHashOf names the certificate whose hash the binding carries;
	// nil means the signer's.
	CertHashOf *x509.Certificate
	// Serial overrides the binding's issuerSerial serial number.
	Serial *big.Int
	// SKISid names the signer by its subjectKeyIdentifier ([0]) instead of
	// by issuer and serial number, as RFC 5652 §5.3 allows.
	SKISid bool
	// SignatureAlgorithm is the algorithm the SignerInfo names; nil means
	// ecdsa-with-SHA256. The signature is ECDSA over SHA-256 whatever it
	// names.
	SignatureAlgorithm asn1.ObjectIdentifier
	// DigestAlgorithm is the SignerInfo's digestAlgorithm; nil means
	// SHA-256. The message digest is SHA-256 whatever it names.
	DigestAlgorithm asn1.ObjectIdentifier
	// MessageDigest, when set, is the message-digest attribute's value in
	// place of the TSTInfo's digest.
	MessageDigest []byte
	// AttrsOutOfOrder carries the signed attributes in the reverse of their
	// DER SET OF order, and signs them as carried. With SignDEROrder they
	// are signed in DER order instead: what a verifier that encodes the
	// attributes again would check.
	AttrsOutOfOrder, SignDEROrder bool
	// TSTInfo, when set, edits the members of the TSTInfo (version, policy,
	// messageImprint, serialNumber and genTime, each as its DER) before the
	// token is signed over it.
	TSTInfo func(members [][]byte) [][]byte
	// SignedAttrs, when set, edits the signed attributes (content-type,
	// message-digest and the binding, those that are written, each as its
	// DER) before they are put in order and signed.
	SignedAttrs func(attrs [][]byte) [][]byte
}

var (
	// SHA3_256 is a digest algorithm crypto/x509 does not implement.
	SHA3_256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}

	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningCert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidECDSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// generalizedTime is t as a DER GeneralizedTime: UTC, with a fraction of a
// second only when t has one, and without trailing zeros.
func generalizedTime(t time.Time) asn1.RawValue {
	s := t.UTC().Format("20060102150405.999999999") + "Z"
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagGeneralizedTime, Bytes: []byte(s)}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// sorted returns DER elements in DER SET OF order (X.690 §11.6).
func sorted(elems [][]byte) [][]byte {
	out := append([][]byte{}, elems...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && string(out[j]) < string(out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// wrap encodes a constructed element of the given class and tag around
// elements, in the order given.
func wrap(tag int, class int, elems [][]byte) []byte {
	var content []byte
	for _, e := range elems {
		content = append(content, e...)
	}
	return must(asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: content}))
}

func set(tag int, class int, elems [][]byte) []byte { return wrap(tag, class, sorted(elems)) }

func attr(oid asn1.ObjectIdentifier, value []byte) []byte {
	return must(asn1.Marshal(struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}{oid, asn1.RawValue{FullBytes: set(asn1.TagSet, asn1.ClassUniversal, [][]byte{value})}}))
}

func binding(o TokenOptions) []byte {
	target := o.Signer.Cert
	if o.CertHashOf != nil {
		target = o.CertHashOf
	}
	serial := o.Signer.Cert.SerialNumber
	if o.Serial != nil {
		serial = o.Serial
	}
	issuer := must(asn1.Marshal(struct {
		Names  []asn1.RawValue
		Serial *big.Int
	}{[]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: o.Signer.Cert.RawIssuer}}, serial}))
	var id []byte
	switch o.Binding {
	case "v2-unknown":
		h := sha256.Sum256(target.Raw)
		id = must(asn1.Marshal(struct {
			Alg    algID
			Hash   []byte
			Issuer asn1.RawValue
		}{algID{Algorithm: SHA3_256}, h[:], asn1.RawValue{FullBytes: issuer}}))
	case "v2-alg-three":
		h := sha256.Sum256(target.Raw)
		alg := wrap(asn1.TagSequence, asn1.ClassUniversal, [][]byte{OID(oidSHA256), {0x05, 0x00}, {0x05, 0x00}})
		id = must(asn1.Marshal(struct {
			Alg    asn1.RawValue
			Hash   []byte
			Issuer asn1.RawValue
		}{asn1.RawValue{FullBytes: alg}, h[:], asn1.RawValue{FullBytes: issuer}}))
	case "v1":
		h := sha1.Sum(target.Raw)
		id = must(asn1.Marshal(struct {
			Hash   []byte
			Issuer asn1.RawValue
		}{h[:], asn1.RawValue{FullBytes: issuer}}))
	case "v2-sha384":
		h := sha512.Sum384(target.Raw)
		id = must(asn1.Marshal(struct {
			Alg    algID
			Hash   []byte
			Issuer asn1.RawValue
		}{algID{Algorithm: oidSHA384}, h[:], asn1.RawValue{FullBytes: issuer}}))
	default:
		h := sha256.Sum256(target.Raw)
		id = must(asn1.Marshal(struct {
			Hash   []byte
			Issuer asn1.RawValue
		}{h[:], asn1.RawValue{FullBytes: issuer}}))
	}
	return must(asn1.Marshal(struct{ Certs []asn1.RawValue }{[]asn1.RawValue{{FullBytes: id}}}))
}

// BuildToken builds a TimeStampResp field by field and signs it with the
// signer's ECDSA key.
func BuildToken(o TokenOptions) string {
	members := [][]byte{
		must(asn1.Marshal(1)),
		OID(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}),
		must(asn1.Marshal(struct {
			HashAlgorithm algID
			HashedMessage []byte
		}{algID{Algorithm: oidSHA256}, o.Digest})),
		must(asn1.Marshal(big.NewInt(42))),
		must(asn1.Marshal(generalizedTime(o.GenTime))),
	}
	if o.TSTInfo != nil {
		members = o.TSTInfo(members)
	}
	content := wrap(asn1.TagSequence, asn1.ClassUniversal, members)
	digest := sha256.Sum256(content)
	md := digest[:]
	if o.MessageDigest != nil {
		md = o.MessageDigest
	}

	var attrs [][]byte
	if !o.OmitContentType {
		ct := o.ContentType
		if ct == nil {
			ct = oidTSTInfo
		}
		attrs = append(attrs, attr(oidContentType, must(asn1.Marshal(ct))))
	}
	attrs = append(attrs, attr(oidMessageDigest, must(asn1.Marshal(md))))
	switch o.Binding {
	case "none":
	case "v1":
		attrs = append(attrs, attr(oidSigningCert, binding(o)))
	default:
		attrs = append(attrs, attr(oidSigningCertV2, binding(o)))
	}
	if o.SignedAttrs != nil {
		attrs = o.SignedAttrs(attrs)
	}
	carried := sorted(attrs)
	signedOrder := carried
	if o.AttrsOutOfOrder {
		carried = slices.Clone(carried)
		slices.Reverse(carried)
		if !o.SignDEROrder {
			signedOrder = carried
		}
	}
	signedSet := wrap(asn1.TagSet, asn1.ClassUniversal, signedOrder)
	h := sha256.Sum256(signedSet)
	sig := must(ecdsa.SignASN1(rand.Reader, o.Signer.Key, h[:]))
	implicit := wrap(0, asn1.ClassContextSpecific, carried)

	version := 1
	sid := asn1.RawValue{FullBytes: must(asn1.Marshal(struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{asn1.RawValue{FullBytes: o.Signer.Cert.RawIssuer}, o.Signer.Cert.SerialNumber}))}
	if o.SKISid {
		version = 3
		sid = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: o.Signer.Cert.SubjectKeyId}
	}
	sigAlg := o.SignatureAlgorithm
	if sigAlg == nil {
		sigAlg = oidECDSASHA256
	}
	digestAlg := o.DigestAlgorithm
	if digestAlg == nil {
		digestAlg = oidSHA256
	}
	signerInfo := must(asn1.Marshal(struct {
		Version     int
		SID         asn1.RawValue
		DigestAlg   algID
		SignedAttrs asn1.RawValue
		SigAlg      algID
		Signature   []byte
	}{
		Version:     version,
		SID:         sid,
		DigestAlg:   algID{Algorithm: digestAlg},
		SignedAttrs: asn1.RawValue{FullBytes: implicit},
		SigAlg:      algID{Algorithm: sigAlg},
		Signature:   sig,
	}))
	var certs [][]byte
	if !o.OmitSignerCert {
		certs = append(certs, o.Signer.Cert.Raw)
	}
	for _, c := range o.Certs {
		certs = append(certs, c.Raw)
	}
	eContent := must(asn1.Marshal(content))
	sd := struct {
		Version    int
		DigestAlgs asn1.RawValue
		Encap      struct {
			Type    asn1.ObjectIdentifier
			Content asn1.RawValue
		}
		Certs       asn1.RawValue `asn1:"optional"`
		SignerInfos asn1.RawValue
	}{Version: 3}
	sd.DigestAlgs = asn1.RawValue{FullBytes: set(asn1.TagSet, asn1.ClassUniversal, [][]byte{must(asn1.Marshal(algID{Algorithm: oidSHA256}))})}
	sd.Encap.Type = oidTSTInfo
	sd.Encap.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: eContent}
	if len(certs) > 0 {
		sd.Certs = asn1.RawValue{FullBytes: set(0, asn1.ClassContextSpecific, certs)}
	}
	sd.SignerInfos = asn1.RawValue{FullBytes: set(asn1.TagSet, asn1.ClassUniversal, [][]byte{signerInfo})}
	sdDER := must(asn1.Marshal(sd))
	token := must(asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER}}))
	resp := must(asn1.Marshal(struct {
		Status struct{ Status int }
		Token  asn1.RawValue
	}{Token: asn1.RawValue{FullBytes: token}}))
	return base64.StdEncoding.EncodeToString(resp)
}

// CA is an intermediate under parent with exactly the given constraints:
// basicConstraints present only when bc is set, keyUsage as given (0 leaves
// the extension out), and pathLen when it is not negative.
func CA(name string, parent *Cert, bc, isCA bool, ku x509.KeyUsage, pathLen int) *Cert {
	now := time.Now()
	t := &x509.Certificate{
		Subject: pkix.Name{CommonName: name}, NotBefore: now.AddDate(-10, 0, 0), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: ku, BasicConstraintsValid: bc, IsCA: isCA, MaxPathLen: -1,
	}
	if pathLen >= 0 {
		t.MaxPathLen, t.MaxPathLenZero = pathLen, pathLen == 0
	}
	return mk(t, parent)
}

// CAValid is a CA under parent, valid only from notBefore to notAfter. With
// key set, it certifies that key: a renewal of a CA keeps its key.
func CAValid(name string, parent *Cert, notBefore, notAfter time.Time, key ...*ecdsa.PrivateKey) *Cert {
	tmpl := &x509.Certificate{
		Subject: pkix.Name{CommonName: name}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: -1,
	}
	if len(key) > 0 {
		return mkWithKey(tmpl, parent, key[0])
	}
	return mk(tmpl, parent)
}

// Curves and key algorithms by OID, for SPKI.
var (
	CurveP256            = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	CurveBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	// CurveUnassigned is an OID under the ANSI X9.62 prime curves that names
	// no curve.
	CurveUnassigned = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 99}
)

// OID is the DER of an object identifier.
func OID(o asn1.ObjectIdentifier) []byte { return must(asn1.Marshal(o)) }

// SPKI is a SubjectPublicKeyInfo naming algorithm alg with the given
// parameters (DER, nil for none) over key.
func SPKI(alg asn1.ObjectIdentifier, params, key []byte) []byte {
	ai := algID{Algorithm: alg}
	if params != nil {
		ai.Parameters = asn1.RawValue{FullBytes: params}
	}
	return must(asn1.Marshal(struct {
		Algorithm algID
		Key       asn1.BitString
	}{ai, asn1.BitString{Bytes: key, BitLength: 8 * len(key)}}))
}

// ECKey is an id-ecPublicKey SubjectPublicKeyInfo holding c's P-256 point,
// under the given parameters: the DER of a named curve's OID, of explicit
// curve parameters, or of NULL.
func ECKey(c *Cert, params []byte) []byte {
	point, err := c.Key.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	return SPKI(oidECPublicKey, params, point)
}

// OffCurve is c's P-256 key with its point moved off the curve.
func OffCurve(c *Cert) []byte {
	point, err := c.Key.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	point[len(point)-1] ^= 1
	return SPKI(oidECPublicKey, OID(CurveP256), point)
}

// Reissue returns c's certificate with its SubjectPublicKeyInfo replaced by
// spki (kept when spki is nil) and signed again by issuer (by c itself when
// issuer is nil) with ECDSA over SHA-256. With sigAlg set, the certificate
// names that signature algorithm instead, over the same signature. It
// returns what Rebuild returns.
func Reissue(c, issuer *Cert, spki []byte, sigAlg asn1.ObjectIdentifier) *x509.Certificate {
	alg := algID{Algorithm: oidECDSASHA256}
	if sigAlg != nil {
		alg = algID{Algorithm: sigAlg}
	}
	return Rebuild(c, issuer, func(fields [][]byte) [][]byte {
		fields[2] = must(asn1.Marshal(alg))
		if spki != nil {
			fields[6] = spki
		}
		return fields
	})
}

// Rebuild returns c's certificate with the elements of its tbsCertificate
// (version, serialNumber, signature, issuer, validity, subject,
// subjectPublicKeyInfo, extensions, each as its DER) as edit returns them,
// signed again by issuer (by c itself when issuer is nil) with ECDSA over
// SHA-256, under the outer signature algorithm the third element names. It
// returns what the stock parser reads when it can, and otherwise a
// certificate that carries only Raw, RawIssuer, RawSubject and SerialNumber,
// which is all BuildToken reads.
func Rebuild(c, issuer *Cert, edit func(fields [][]byte) [][]byte) *x509.Certificate {
	var cert struct {
		TBS asn1.RawValue
		Alg asn1.RawValue
		Sig asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.Cert.Raw, &cert); err != nil {
		panic(err)
	}
	var fields [][]byte
	for rest := cert.TBS.Bytes; len(rest) > 0; {
		var f asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &f); err != nil {
			panic(err)
		}
		fields = append(fields, f.FullBytes)
	}
	fields = edit(fields)
	var body []byte
	for _, f := range fields {
		body = append(body, f...)
	}
	tbs := must(asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body}))
	key := c.Key
	if issuer != nil {
		key = issuer.Key
	}
	h := sha256.Sum256(tbs)
	sig := must(ecdsa.SignASN1(rand.Reader, key, h[:]))
	der := must(asn1.Marshal(struct {
		TBS asn1.RawValue
		Alg asn1.RawValue
		Sig asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, asn1.RawValue{FullBytes: fields[2]}, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}}))
	if parsed, err := x509.ParseCertificate(der); err == nil {
		return parsed
	}
	return &x509.Certificate{Raw: der, RawIssuer: c.Cert.RawIssuer, RawSubject: c.Cert.RawSubject, SerialNumber: c.Cert.SerialNumber}
}

// WithName is a timestamping signer under parent whose subject is exactly
// the given RDNSequence, attribute by attribute as given.
func WithName(parent *Cert, subject pkix.RDNSequence) *Cert {
	now := time.Now()
	raw := must(asn1.Marshal(subject))
	return mk(&x509.Certificate{
		RawSubject: raw, NotBefore: now.AddDate(-5, 0, 0), NotAfter: now.AddDate(5, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{EKU(true, TimeStamping)},
	}, parent)
}
