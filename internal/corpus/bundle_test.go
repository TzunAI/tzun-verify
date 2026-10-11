// SPDX-License-Identifier: BSD-3-Clause-Clear

package corpus

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/cli"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// TestBundleCorpus runs the b1 conformance corpus (Bundle §13,
// Specs §6) through the command itself: each case's inputs.json is
// turned into the flags an auditor would pass, and tzun-verify --json must
// print expected-report.json exactly and exit with expected-exit. Reports
// compare as DEO canonical bytes, checkedAt left out (Verification §6.5).
//
// inputs.json (Bundle §13.2):
//
//	{ "publisherManifest": <manifest> | null,        --publishers <file> | --no-publishers
//	  "headerSources": { "<eip155 chain>": <source> }, --evm-header-file <chain>=<file>
//	  "trustAnchorsPem": ["<PEM>"],                    --tsa-roots <file>
//	  "regime": { "require": [], "requireRung": [],    --require, --require-rung
//	              "allowUnchecked": bool | [<reason>] } } --allow-unchecked | --allow-unchecked-reason
//
// Any member this runner does not know fails the case, so a change to the
// corpus's input format is noticed.
func TestBundleCorpus(t *testing.T) {
	dir := filepath.Join(vectorDir, "bundle-b1")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		t.Fatal("testdata/vectors/bundle-b1 is missing from this checkout")
	}
	if err != nil {
		t.Fatal(err)
	}
	src := load(t, "SOURCE.json")
	version := str(t, src, "generator", "version")

	index := load(t, filepath.Join("bundle-b1", "index.json"))
	listed := map[string]string{}
	for _, c := range get(t, index, "cases").A {
		listed[str(t, c, "name")] = strconv.Itoa(int(get(t, c, "exit").N))
	}
	var cases []string
	for _, e := range entries {
		if e.IsDir() {
			cases = append(cases, e.Name())
		}
	}
	sort.Strings(cases)
	if len(cases) == 0 || len(cases) != len(listed) {
		t.Fatalf("%d case directories, %d cases in index.json", len(cases), len(listed))
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			runBundleCase(t, filepath.Join(dir, name), listed[name])
		})
	}
	t.Logf("bundle corpus of reference implementation %s: %d cases", version, len(cases))
}

func readCase(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b
}

func onlyKeys(t *testing.T, v *jsonv.Value, what string, known ...string) {
	t.Helper()
	ok := map[string]bool{}
	for _, k := range known {
		ok[k] = true
	}
	if v == nil || v.Kind != jsonv.Object {
		t.Fatalf("%s is not an object", what)
	}
	for _, k := range v.Keys() {
		if !ok[k] {
			t.Fatalf("%s: unknown member %q: teach the runner what it means", what, k)
		}
	}
}

func writeCanonical(t *testing.T, path string, v *jsonv.Value) string {
	t.Helper()
	b, err := canonical.Serialize(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// args turns a case's inputs.json into tzun-verify's flags.
func args(t *testing.T, in *jsonv.Value, tmp string) []string {
	onlyKeys(t, in, "inputs.json", "publisherManifest", "headerSources", "trustAnchorsPem", "regime")
	var out []string
	switch m := get(t, in, "publisherManifest"); m.Kind {
	case jsonv.Null:
		out = append(out, "--no-publishers")
	default:
		out = append(out, "--publishers", writeCanonical(t, filepath.Join(tmp, "publishers.json"), m))
	}
	hs := get(t, in, "headerSources")
	if hs.Kind != jsonv.Object {
		t.Fatal("headerSources is not an object")
	}
	for i, m := range hs.O {
		onlyKeys(t, m.Value, "headerSources."+m.Key, "chainId", "finality", "finalizedBlockNumber", "blocks")
		f := writeCanonical(t, filepath.Join(tmp, "headers-"+strconv.Itoa(i)+".json"), m.Value)
		out = append(out, "--evm-header-file", m.Key+"="+f)
	}
	if pems := get(t, in, "trustAnchorsPem"); len(pems.A) > 0 {
		var b strings.Builder
		for _, p := range pems.A {
			b.WriteString(p.S)
			b.WriteString("\n")
		}
		f := filepath.Join(tmp, "roots.pem")
		if err := os.WriteFile(f, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		out = append(out, "--tsa-roots", f)
	}
	regime := get(t, in, "regime")
	onlyKeys(t, regime, "regime", "require", "requireRung", "allowUnchecked")
	for _, id := range get(t, regime, "require").A {
		out = append(out, "--require", id.S)
	}
	for _, r := range get(t, regime, "requireRung").A {
		out = append(out, "--require-rung", r.S)
	}
	// allowUnchecked is a switch, or the list of reasons of the scoped
	// allowance (Verification §6.6).
	switch au := get(t, regime, "allowUnchecked"); au.Kind {
	case jsonv.Bool:
		if au.B {
			out = append(out, "--allow-unchecked")
		}
	case jsonv.Array:
		for _, r := range au.A {
			out = append(out, "--allow-unchecked-reason", r.S)
		}
	default:
		t.Fatalf("regime.allowUnchecked is neither a boolean nor a list of reasons")
	}
	return out
}

// runBundleCase runs one case. indexExit is the exit code index.json lists
// for it. The report must equal expected-report.json, checkedAt left out,
// and the exit code expected-exit (Specs §6).
func runBundleCase(t *testing.T, dir, indexExit string) {
	in, err := jsonv.Parse(readCase(t, dir, "inputs.json"))
	if err != nil {
		t.Fatalf("inputs.json: %v", err)
	}
	expectedExit, err := strconv.Atoi(strings.TrimSpace(string(readCase(t, dir, "expected-exit"))))
	if err != nil {
		t.Fatalf("expected-exit: %v", err)
	}
	if strconv.Itoa(expectedExit) != indexExit {
		t.Errorf("expected-exit %d, index.json %q", expectedExit, indexExit)
	}
	flags := append(args(t, in, t.TempDir()), "--json", filepath.Join(dir, "bundle.json"))
	var stdout, stderr bytes.Buffer
	exit := cli.Run(flags, &stdout, &stderr)
	if stderr.Len() > 0 {
		t.Fatalf("tzun-verify %v: %s", flags, stderr.String())
	}
	got, err := jsonv.Parse(stdout.Bytes())
	if err != nil {
		t.Fatalf("report: %v\n%s", err, stdout.String())
	}
	want, err := jsonv.Parse(readCase(t, dir, "expected-report.json"))
	if err != nil {
		t.Fatalf("expected-report.json: %v", err)
	}
	if !bytes.Equal(comparable(t, got), comparable(t, want)) {
		t.Errorf("report differs:%s", differences(t, got, want))
	}
	if exit != expectedExit {
		t.Errorf("exit %d, want %d", exit, expectedExit)
	}
}

// rowOf returns a report's row with the given id, nil when it has none.
func rowOf(t *testing.T, r *jsonv.Value, id string) *jsonv.Value {
	t.Helper()
	for _, c := range get(t, r, "checks").A {
		if str(t, c, "id") == id {
			return c
		}
	}
	return nil
}

// rowLine is a row's outcome and reason, as one line.
func rowLine(t *testing.T, c *jsonv.Value) string {
	t.Helper()
	if c == nil {
		return "(none)"
	}
	if r, ok := c.Get("reason"); ok {
		return str(t, c, "outcome") + " " + r.S
	}
	return str(t, c, "outcome")
}

func canonicalOf(t *testing.T, v *jsonv.Value) string {
	t.Helper()
	b, err := canonical.Serialize(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// comparable is a report in DEO canonical form without checkedAt, which
// comparisons leave out (Verification §6.5).
func comparable(t *testing.T, r *jsonv.Value) []byte {
	t.Helper()
	stripped := &jsonv.Value{Kind: jsonv.Object}
	for _, m := range r.O {
		if m.Key != "checkedAt" {
			stripped.O = append(stripped.O, m)
		}
	}
	b, err := canonical.Serialize(stripped)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// differences names what differs between two reports: each member other
// than checks, then each check row by position.
func differences(t *testing.T, got, want *jsonv.Value) string {
	t.Helper()
	var b strings.Builder
	ser := func(v *jsonv.Value) string {
		if v == nil {
			return "(none)"
		}
		out, _ := canonical.Serialize(v)
		return string(out)
	}
	for _, k := range want.Keys() {
		if k == "checks" || k == "checkedAt" {
			continue
		}
		g, _ := got.Get(k)
		w, _ := want.Get(k)
		if ser(g) != ser(w) {
			b.WriteString("\n  " + k + "\n     got " + ser(g) + "\n    want " + ser(w))
		}
	}
	gc, _ := got.Get("checks")
	wc, _ := want.Get("checks")
	n := len(wc.A)
	if len(gc.A) > n {
		n = len(gc.A)
	}
	for i := 0; i < n; i++ {
		var g, w *jsonv.Value
		if i < len(gc.A) {
			g = gc.A[i]
		}
		if i < len(wc.A) {
			w = wc.A[i]
		}
		if ser(g) != ser(w) {
			b.WriteString("\n  checks[" + strconv.Itoa(i) + "]\n     got " + ser(g) + "\n    want " + ser(w))
		}
	}
	return b.String()
}
