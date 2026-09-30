package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/canonical"
)

// checkedAt is the one member of a report two runs may differ in
// (Verification §6.5).
var checkedAt = regexp.MustCompile(`"checkedAt":"[^"]*"`)

// masked is a run's standard output with checkedAt blanked. It fails
// unless a report holds exactly one checkedAt.
func masked(t *testing.T, out []byte, isReport bool) []byte {
	t.Helper()
	if n := len(checkedAt.FindAll(out, -1)); isReport && n != 1 {
		t.Fatalf("%d checkedAt members in the report", n)
	}
	return checkedAt.ReplaceAll(out, []byte(`"checkedAt":""`))
}

// filesIn reads every file of dir into a map keyed by its path, as the
// flags name it.
func filesIn(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		files[p] = b
	}
	return files
}

// TestRunBytesIsRun: given the same flags and the same bytes, RunBytes
// prints and returns what Run does, byte for byte (checkedAt aside), on
// every usage error, on the help and version output, on a report that cannot
// be written and on reports in both formats. With --json, its text report
// is the one Run prints without --json.
func TestRunBytesIsRun(t *testing.T) {
	d := loadE2E(t)
	dir := t.TempDir()
	bundle := write(t, dir, "b.json", bundleFor(t, d, 0))
	notJSON := filepath.Join(dir, "p.json")
	_ = os.WriteFile(notJSON, []byte("{publishers"), 0o600)
	badHeaders := filepath.Join(dir, "h.json")
	_ = os.WriteFile(badHeaders, []byte(`{"chainId":1,"finality":"finalized","finalizedBlockNumber":1,"blocks":[],"extra":1}`), 0o600)
	notPEM := filepath.Join(dir, "n.pem")
	_ = os.WriteFile(notPEM, []byte("not a certificate"), 0o600)
	b, err := canonical.Serialize(bundleFor(t, d, 0))
	if err != nil {
		t.Fatal(err)
	}
	unwritable := filepath.Join(dir, "lone.json")
	_ = os.WriteFile(unwritable, bytes.Replace(b, []byte(`"subject":{`), []byte(`"subject":{"x":"\ud800",`), 1), 0o600)
	files := filesIn(t, dir)

	for _, args := range [][]string{
		{}, {"--help"}, {"-h"}, {"--version"}, {"--bogus", bundle}, {"a.json", "b.json"},
		{"--publishers", notJSON, bundle}, {"--publishers", filepath.Join(dir, "missing.json"), bundle},
		{"--tsa-roots", notPEM, bundle}, {"--tsa-intermediates", filepath.Join(dir, "missing.pem"), bundle},
		{"--evm-header-file", badHeaders, bundle}, {"--evm-header-file", "eip155:1=" + filepath.Join(dir, "missing.json"), bundle},
		{"--evm-rpc", "ftp://x", bundle}, {"--confirmations", "10", "--evm-rpc", "https://example.invalid", bundle},
		{"--allow-unchecked=false", bundle},
		{filepath.Join(dir, "missing.json")}, {"--json", filepath.Join(dir, "missing.json")},
		{unwritable}, {"--json", unwritable},
		{bundle}, {"--no-publishers", bundle}, {"--allow-unchecked", "--require", "anchor", bundle},
	} {
		var stdout, stderr bytes.Buffer
		exit := Run(args, &stdout, &stderr)
		got := RunBytes(args, files)
		if got.Exit != exit || !bytes.Equal(got.Stdout, stdout.Bytes()) || !bytes.Equal(got.Stderr, stderr.Bytes()) {
			t.Errorf("%v:\n  Run       exit %d\n%s%s\n  RunBytes  exit %d\n%s%s", args, exit, stdout.String(), stderr.String(), got.Exit, got.Stdout, got.Stderr)
		}
		if len(got.Text) != 0 {
			t.Errorf("%v: a text report without --json", args)
		}
	}

	for _, flags := range [][]string{{}, {"--no-publishers"}, {"--allow-unchecked"}, {"--require", "anchor"}} {
		args := append(append([]string{}, flags...), bundle)
		var text, report, stderr bytes.Buffer
		textExit := Run(args, &text, &stderr)
		jsonExit := Run(append([]string{"--json"}, args...), &report, &stderr)
		got := RunBytes(append([]string{"--json"}, args...), files)
		if stderr.Len() != 0 || len(got.Stderr) != 0 {
			t.Fatalf("%v: %s%s", args, stderr.String(), got.Stderr)
		}
		if got.Exit != jsonExit || got.Exit != textExit {
			t.Errorf("%v: exit %d, Run %d and %d", args, got.Exit, jsonExit, textExit)
		}
		if !bytes.Equal(masked(t, got.Stdout, true), masked(t, report.Bytes(), true)) {
			t.Errorf("%v: the JSON report differs\n%s\n%s", args, got.Stdout, report.String())
		}
		if !bytes.Equal(got.Text, text.Bytes()) {
			t.Errorf("%v: the text report differs\n%s\n%s", args, got.Text, text.String())
		}
	}
}
