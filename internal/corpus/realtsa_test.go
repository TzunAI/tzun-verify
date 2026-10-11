// SPDX-License-Identifier: BSD-3-Clause-Clear

package corpus

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/cli"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// realTokenDigest is the record digest the two public authorities' responses
// in internal/rfc3161/testdata are over: corpus case anchored-with-newer's.
const realTokenDigest = "9739ebd76cc45223ccc88920802c9032208f3c09f67fc129a41a769109dead6a"

// TestRealAuthorityTokenInBundle runs the command, with the flags an
// auditor passes, over corpus case anchored-with-newer
// whose record token is replaced by a response from a public authority
// (FreeTSA or Sectigo, internal/rfc3161/testdata). Both responses are over
// that case's record digest, realTokenDigest. The trust is the two public
// roots, each named by its own --tsa-roots, and the checks the auditor
// requires are passed as one comma-separated --require.
//
// Everything the corpus decides without its test authority must come out
// as the corpus states it: every row other than ts.record.token and
// ts.record.trust, and the summary's existedBy, whose bound here is the
// anchor's block time. The two ts rows must be checked-correct, naming the
// authority, and the exit must be 0. Under the other authority's root alone
// the token still verifies but reaches no supplied root, so the required
// ts.record.trust is not met and the exit is 3.
func TestRealAuthorityTokenInBundle(t *testing.T) {
	dir := filepath.Join(vectorDir, "bundle-b1", "anchored-with-newer")
	tsaDir := filepath.Join("..", "rfc3161", "testdata")
	in, err := jsonv.Parse(readCase(t, dir, "inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := jsonv.Parse(readCase(t, dir, "expected-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if d := str(t, want, "subject", "canonicalDigest"); d != realTokenDigest {
		t.Fatalf("anchored-with-newer's record digest is %s; the public authorities' responses are over %s. "+
			"Request new ones over the case's digest (openssl ts -query -digest <digest> -sha256 -cert, "+
			"sent to https://freetsa.org/tsr and http://timestamp.sectigo.com), and update realTokenDigest "+
			"and TestRealAuthorityTokens", d, realTokenDigest)
	}
	// The case's own flags, without its test authority's root.
	var base []string
	all := args(t, in, t.TempDir())
	for i := 0; i < len(all); i++ {
		if all[i] == "--tsa-roots" {
			i++
			continue
		}
		base = append(base, all[i])
	}
	required := "record.digest,record.chainLink,ts.record.token,ts.record.trust,anchor,anchor.evm.canonical[*]"
	freeRoot := filepath.Join(tsaDir, "freetsa-root.pem")
	sectigoRoot := filepath.Join(tsaDir, "sectigo-root-r46.pem")

	for _, c := range []struct {
		response, authority, otherRoot string
	}{
		{"freetsa.tsr", "www.freetsa.org", sectigoRoot},
		{"sectigo.tsr", "Sectigo Public Time Stamping Signer R37", freeRoot},
	} {
		t.Run(c.response, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(tsaDir, c.response))
			if err != nil {
				t.Fatal(err)
			}
			b := loadDoc(t, filepath.Join(dir, "bundle.json"))
			sub(b, "envelope", "nonRepudiation")["rfc3161Token"] = base64.StdEncoding.EncodeToString(raw)
			enc, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			f := filepath.Join(t.TempDir(), "bundle.json")
			if err := os.WriteFile(f, enc, 0o600); err != nil {
				t.Fatal(err)
			}
			run := func(roots ...string) (int, *jsonv.Value) {
				flags := append([]string{}, base...)
				for _, r := range roots {
					flags = append(flags, "--tsa-roots", r)
				}
				flags = append(flags, "--require", required, "--json", f)
				var stdout, stderr bytes.Buffer
				exit := cli.Run(flags, &stdout, &stderr)
				if stderr.Len() > 0 {
					t.Fatalf("tzun-verify %v: %s", flags, stderr.String())
				}
				rep, err := jsonv.Parse(stdout.Bytes())
				if err != nil {
					t.Fatalf("report: %v", err)
				}
				return exit, rep
			}

			exit, got := run(freeRoot, sectigoRoot)
			if exit != 0 {
				t.Errorf("exit %d, want 0", exit)
			}
			gotChecks, wantChecks := get(t, got, "checks").A, get(t, want, "checks").A
			if len(gotChecks) != len(wantChecks) {
				t.Fatalf("%d rows, the corpus states %d", len(gotChecks), len(wantChecks))
			}
			for i, g := range gotChecks {
				id := str(t, g, "id")
				switch id {
				case "ts.record.token":
					if rowLine(t, g) != "checked-correct" {
						t.Errorf("ts.record.token: %s", rowLine(t, g))
					}
				case "ts.record.trust":
					a, _ := g.Get("facts")
					if rowLine(t, g) != "checked-correct" || a == nil || str(t, a, "authority") != c.authority {
						t.Errorf("ts.record.trust: %s", canonicalOf(t, g))
					}
				default:
					if canonicalOf(t, g) != canonicalOf(t, wantChecks[i]) {
						t.Errorf("row %d: %s, the corpus states %s", i, canonicalOf(t, g), canonicalOf(t, wantChecks[i]))
					}
				}
			}
			if g, w := canonicalOf(t, get(t, got, "summary", "existedBy")), canonicalOf(t, get(t, want, "summary", "existedBy")); g != w {
				t.Errorf("existedBy %s, the corpus states %s", g, w)
			}

			exit, got = run(c.otherRoot)
			if tr := rowLine(t, rowOf(t, got, "ts.record.trust")); exit != 3 || tr != "not-checked no_matching_trust_anchor" {
				t.Errorf("under the other authority's root: ts.record.trust %s, exit %d, want not-checked no_matching_trust_anchor, exit 3", tr, exit)
			}
		})
	}
}
