// SPDX-License-Identifier: BSD-3-Clause-Clear

package bundle

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TzunAI/tzun-verify/internal/anchor"
	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/evm"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
	"github.com/TzunAI/tzun-verify/internal/rfc3161"
)

// FuzzVerify runs Verify over any bundle with any auditor inputs, read
// from a corpus case's inputs.json format (Bundle §13.2): the publisher
// manifest, header sources by chain and trust anchors. The seeds are every
// case of the b1 corpus.
//
// With repair set, the bundle's payload is first given the digest it
// recomputes to, in the envelope and in the subject, so that a payload the
// fuzzer changed still reaches the rows that need record.digest to hold:
// the decider, contributions, links and mandate rows.
//
// Verify never panics: it, the anchor verification and the EVM
// verification each recover from a panic as a reason of their own
// (bundle_verifier_error, anchor_verifier_error, evm_verifier_error), and
// each of those is a failure here. The report keeps to Verification §6:
// every check is one of the four outcomes, under an id no other check has;
// a bundle row that does not hold is the only row; the report serializes
// canonically, or fails to only with one of the three refusals of Record
// §3.6 (a report copies some bundle values as they stand, §6.5; which value
// was refused is not checked), and the exit is then 2, as the command's
// is; the exit is the one §6.6 gives for the rows, transcribed here as
// specExit; and the same input gives the same report again (checkedAt left
// out), compared whole and in the text form, which a report with no
// canonical form has too.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzVerify fuzzes.
func FuzzVerify(f *testing.F) {
	cases, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "bundle-b1", "*", "bundle.json"))
	if err != nil || len(cases) == 0 {
		f.Fatalf("no bundle cases: %v", err)
	}
	for _, c := range cases {
		b, err := os.ReadFile(c)
		if err != nil {
			f.Fatal(err)
		}
		in, err := os.ReadFile(filepath.Join(filepath.Dir(c), "inputs.json"))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, in, false)
		f.Add(b, in, true)
	}
	// Reports that have no canonical form (§6.5): an unreadable bundle's
	// bundleVersion, and a member of a readable bundle's subject, which the
	// report copies as they stand, holding what Record §3 refuses: a lone
	// surrogate, a number beyond the doubles, nesting deeper than 64.
	first, _ := os.ReadFile(cases[0])
	firstInputs, _ := os.ReadFile(filepath.Join(filepath.Dir(cases[0]), "inputs.json"))
	for _, v := range []string{`"\ud800"`, `1e400`, strings.Repeat("[", 65) + strings.Repeat("]", 65)} {
		f.Add([]byte(`{"bundleVersion":`+v+`}`), []byte(`{}`), false)
		f.Add(bytes.Replace(first, []byte(`"subject": {`), []byte(`"subject": {"zz":`+v+`,`), 1), firstInputs, false)
	}
	f.Fuzz(func(t *testing.T, data, inputs []byte, repair bool) {
		if repair {
			data = repaired(data)
		}
		opts := fuzzOptions(inputs)
		res := Verify(data, opts)
		if res == nil || res.Report == nil || len(res.Report.Checks) == 0 {
			t.Fatalf("no report")
		}
		r := res.Report
		seen := map[string]bool{}
		for _, c := range r.Checks {
			switch c.Reason {
			case ReasonBundleError, anchor.ReasonVerifierError, evm.ReasonVerifierError:
				t.Fatalf("%s: %s: the verifier recovered from a panic", c.ID, c.Reason)
			}
			switch c.Outcome {
			case report.Correct, report.Wrong, report.NotChecked, report.Abstain:
			default:
				t.Fatalf("%s: outcome %q", c.ID, c.Outcome)
			}
			if c.ID == "" || seen[c.ID] {
				t.Fatalf("check id %q empty or repeated", c.ID)
			}
			seen[c.ID] = true
		}
		if !r.Readable() && len(r.Checks) != 1 {
			t.Fatalf("an unreadable bundle has %d rows", len(r.Checks))
		}
		if r.Readable() && r.Checks[0].ID != IDBundle {
			t.Fatalf("a readable bundle's first row is %q", r.Checks[0].ID)
		}

		// A report has no canonical form only for one of the refusals of
		// Record §3.6 (§6.5); with checkedAt, a well-formed string, it has one
		// exactly when it has one without.
		c1, err := r.Canonical(false)
		if err != nil && !errors.Is(err, canonical.ErrLoneSurrogate) && !errors.Is(err, canonical.ErrNonFinite) &&
			!errors.Is(err, canonical.ErrDepth) {
			t.Fatalf("the report has no canonical form: %v", err)
		}
		written := err == nil
		if _, err := r.Canonical(true); (err == nil) != written {
			t.Fatalf("the report with checkedAt: %v; without it, written %v", err, written)
		}

		// The command exits 2 when it cannot write the report (§6.5).
		exit := report.ExitCode(r, report.Policy{})
		if !written {
			exit = report.ExitBundle
		}
		if want := specExit(r, written); exit != want {
			t.Fatalf("exit %d, §6.6 gives %d", exit, want)
		}

		again := Verify(data, opts).Report
		c2, err := again.Canonical(false)
		if (err == nil) != written || !bytes.Equal(c1, c2) || !reflect.DeepEqual(r.JSON(false), again.JSON(false)) {
			t.Fatalf("two runs disagree:\n%s\n%s", c1, c2)
		}
		var t1, t2 bytes.Buffer
		report.WriteText(&t1, r, nil, nil, exit)
		report.WriteText(&t2, again, nil, nil, exit)
		if !bytes.Equal(t1.Bytes(), t2.Bytes()) {
			t.Fatalf("two runs disagree:\n%s\n%s", t1.Bytes(), t2.Bytes())
		}
	})
}

// specExit is the exit code Verification §6.6 gives a report under no
// regime and without allowUnchecked, read from the rows alone: the first
// of 2, 1, 3 and 4 that applies, else 0. written says whether the report
// could be written. Code 3 needs a regime, and there is none.
func specExit(r *report.Report, written bool) int {
	outcome := map[string]report.Outcome{}
	for _, c := range r.Checks {
		outcome[c.ID] = c.Outcome
	}
	// 2: the bundle could not be read, the row bundle is not
	// checked-correct, or the report could not be written.
	if !written || outcome["bundle"] != report.Correct {
		return 2
	}
	// 1: some row is checked-wrong.
	for _, c := range r.Checks {
		if c.Outcome == report.Wrong {
			return 1
		}
	}
	// 4: some row abstains, or is not-checked for any reason other than
	// absent, not_applicable, or blocked_by a row that is checked-wrong.
	for _, c := range r.Checks {
		switch c.Outcome {
		case report.Abstain:
			return 4
		case report.NotChecked:
			by, blocked := strings.CutPrefix(c.Reason, "blocked_by:")
			if c.Reason != "absent" && c.Reason != "not_applicable" && !(blocked && outcome[by] == report.Wrong) {
				return 4
			}
		}
	}
	return 0
}

// fuzzOptions reads the auditor's inputs from a case's inputs.json, taking
// what it can: a manifest object, each header source ParseStaticSource
// reads, and each PEM certificate this build can use as a root.
func fuzzOptions(inputs []byte) Options {
	opts := Options{Timeout: 10 * time.Second, Sources: evm.Sources{ByChain: map[string]evm.HeaderSource{}}}
	in, err := jsonv.Parse(inputs)
	if err != nil {
		return opts
	}
	if m := member(in, "publisherManifest"); m != nil {
		opts.Manifest = m
		opts.ManifestBytes, _ = canonical.Serialize(m)
	}
	if hs := member(in, "headerSources"); hs != nil && hs.Kind == jsonv.Object {
		for _, m := range hs.O {
			b, err := canonical.Serialize(m.Value)
			if err != nil {
				continue
			}
			if src, err := evm.ParseStaticSource(b); err == nil {
				opts.Sources.ByChain[m.Key] = src
			}
		}
	}
	if pems := member(in, "trustAnchorsPem"); pems != nil && pems.Kind == jsonv.Array {
		for _, p := range pems.A {
			s, ok := p.Str()
			if !ok {
				continue
			}
			rest := []byte(s)
			for {
				var blk *pem.Block
				if blk, rest = pem.Decode(rest); blk == nil {
					break
				}
				if c, err := x509.ParseCertificate(blk.Bytes); err == nil && rfc3161.KeyImplemented(c) {
					opts.Trust.Roots = append(opts.Trust.Roots, c)
				}
			}
		}
	}
	return opts
}

// repaired gives a bundle's payload the digest it recomputes to, in
// envelope.integrity.canonicalDigest and subject.canonicalDigest, and
// returns the bundle's canonical form; or the bundle unchanged when it has
// no payload or no canonical form.
func repaired(data []byte) []byte {
	root, err := jsonv.Parse(data)
	if err != nil {
		return data
	}
	env := member(root, "envelope")
	payload, integrity, subject := member(env, "payload"), member(env, "integrity"), member(root, "subject")
	if !isObject(payload) || !isObject(integrity) || !isObject(subject) {
		return data
	}
	d, err := canonical.RecordDigest(payload)
	if err != nil {
		return data
	}
	for _, o := range []*jsonv.Value{integrity, subject} {
		set := false
		for i := range o.O {
			if o.O[i].Key == "canonicalDigest" {
				o.O[i].Value, set = report.S(d), true
			}
		}
		if !set {
			o.O = append(o.O, jsonv.Member{Key: "canonicalDigest", Value: report.S(d)})
		}
	}
	b, err := canonical.Serialize(root)
	if err != nil {
		return data
	}
	return b
}
