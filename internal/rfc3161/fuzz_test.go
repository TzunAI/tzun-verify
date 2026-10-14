// SPDX-License-Identifier: BSD-3-Clause-Clear

package rfc3161

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
	"github.com/TzunAI/tzun-verify/internal/testpki"
)

// fuzzRealDigest is the record digest the FreeTSA and Sectigo responses in
// testdata are over (internal/corpus, realTokenDigest).
const fuzzRealDigest = "9739ebd76cc45223ccc88920802c9032208f3c09f67fc129a41a769109dead6a"

// FuzzVerifyRecordToken runs §10.5's steps through the entry point a bundle
// reaches them by, the record's own token, on any token text and imprint.
// The seeds are the public authorities' responses, the OpenSSL tokens and
// the test-PKI tokens in testdata, each with the digest it is over, and a
// rejection; the trust is every root those chain to. The test-PKI tokens are
// kept in testdata rather than made on each run, so that every fuzzing
// process reads them against the same root, and an input that fails
// reproduces in a later go test. It never panics, and its result
// keeps to Anchor §10.1 and Verification §4.4: the two rows under their own
// ids, each one of the four outcomes; ts.record.trust blocked by
// ts.record.token unless the token row holds; the publication valid exactly
// when both rows hold, with a genTime and the authority's name then, and
// invalid exactly when a row is checked-wrong. The same input gives the same
// result twice.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzVerifyRecordToken fuzzes.
func FuzzVerifyRecordToken(f *testing.F) {
	var trust Trust
	addRoot := func(pemText []byte) {
		for {
			var blk *pem.Block
			blk, pemText = pem.Decode(pemText)
			if blk == nil {
				return
			}
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				trust.Roots = append(trust.Roots, c)
			}
		}
	}
	realDigest, _ := hex.DecodeString(fuzzRealDigest)
	for _, name := range []string{"freetsa", "sectigo"} {
		raw, err := os.ReadFile(filepath.Join("testdata", name+".tsr"))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(base64.StdEncoding.EncodeToString(raw), realDigest)
	}
	for _, name := range []string{"freetsa-root.pem", "sectigo-root-r46.pem"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		addRoot(b)
	}
	for _, name := range []string{"openssl-tokens.json", "testpki-tokens.json"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		var set struct {
			Digest string            `json:"digest"`
			Roots  map[string]string `json:"roots"`
			Tokens map[string]string `json:"tokens"`
		}
		if err := json.Unmarshal(b, &set); err != nil {
			f.Fatal(err)
		}
		digest, err := hex.DecodeString(set.Digest)
		if err != nil || len(set.Tokens) == 0 || len(set.Roots) == 0 {
			f.Fatalf("%s: digest %q, %d tokens, %d roots", name, set.Digest, len(set.Tokens), len(set.Roots))
		}
		for _, k := range slices.Sorted(maps.Keys(set.Tokens)) {
			f.Add(set.Tokens[k], digest)
		}
		for _, k := range slices.Sorted(maps.Keys(set.Roots)) {
			addRoot([]byte(set.Roots[k]))
		}
	}
	f.Add(testpki.Rejection(), realDigest)

	f.Fuzz(func(t *testing.T, token string, digest []byte) {
		v := &jsonv.Value{Kind: jsonv.String, S: token}
		r := VerifyRecordToken(v, digest, trust)
		if again := VerifyRecordToken(v, digest, trust); !fuzzSameResult(r, again) {
			t.Fatalf("two runs disagree: %+v and %+v", r, again)
		}
		if r.Token.ID != IDRecordToken || r.Trust.ID != IDRecordTrust {
			t.Fatalf("ids %q and %q", r.Token.ID, r.Trust.ID)
		}
		for _, c := range []report.Check{r.Token, r.Trust} {
			switch c.Outcome {
			case report.Correct, report.Wrong, report.NotChecked, report.Abstain:
			default:
				t.Fatalf("%s: outcome %q", c.ID, c.Outcome)
			}
		}
		if r.Token.Outcome != report.Correct && (r.Trust.Outcome != report.NotChecked || r.Trust.Reason != "blocked_by:"+IDRecordToken) {
			t.Fatalf("token %s, and trust %s %q", r.Token.Outcome, r.Trust.Outcome, r.Trust.Reason)
		}
		wrong := r.Token.Outcome == report.Wrong || r.Trust.Outcome == report.Wrong
		both := r.Token.Outcome == report.Correct && r.Trust.Outcome == report.Correct
		switch {
		case r.Valid == nil:
			if wrong || both || r.Reason == "" {
				t.Fatalf("null with token %s, trust %s, reason %q", r.Token.Outcome, r.Trust.Outcome, r.Reason)
			}
		case *r.Valid:
			if !both || r.Reason != "" || r.GenTime.IsZero() {
				t.Fatalf("valid with token %s, trust %s, reason %q, genTime %v", r.Token.Outcome, r.Trust.Outcome, r.Reason, r.GenTime)
			}
			if _, ok := r.Trust.Fact("authority"); !ok {
				t.Fatalf("valid with no authority fact")
			}
		default:
			if !wrong || r.Reason == "" {
				t.Fatalf("invalid with token %s, trust %s, reason %q", r.Token.Outcome, r.Trust.Outcome, r.Reason)
			}
		}
	})
}

// fuzzSameResult compares two results by what a report states of them.
func fuzzSameResult(a, b Result) bool {
	same := func(x, y report.Check) bool {
		if x.ID != y.ID || x.Outcome != y.Outcome || x.Reason != y.Reason || len(x.Facts) != len(y.Facts) {
			return false
		}
		for i := range x.Facts {
			vx, errx := canonical.Serialize(x.Facts[i].Value)
			vy, erry := canonical.Serialize(y.Facts[i].Value)
			if x.Facts[i].Name != y.Facts[i].Name || (errx == nil) != (erry == nil) || !bytes.Equal(vx, vy) {
				return false
			}
		}
		return true
	}
	valid := func(v *bool) string {
		if v == nil {
			return "null"
		}
		if *v {
			return "true"
		}
		return "false"
	}
	return same(a.Token, b.Token) && same(a.Trust, b.Trust) && valid(a.Valid) == valid(b.Valid) &&
		a.Reason == b.Reason && a.GenTime.Equal(b.GenTime) && a.Authority == b.Authority
}
