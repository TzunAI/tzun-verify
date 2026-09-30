package corpus

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/cli"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// checkedAt is the one member of a report two runs may differ in
// (Verification §6.5).
var checkedAt = regexp.MustCompile(`"checkedAt":"[^"]*"`)

// TestBundleCorpusBytes runs every case of the b1 corpus twice: through
// the command, reading its files from disk, and through cli.RunBytes, the
// entry point of the WebAssembly build, given the same bytes under the
// names a browser has for them. The JSON reports must be the same bytes,
// checkedAt aside, the text reports the same bytes, and the exit codes the
// same and the one the case expects.
func TestBundleCorpusBytes(t *testing.T) {
	dir := filepath.Join(vectorDir, "bundle-b1")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var cases []string
	for _, e := range entries {
		if e.IsDir() {
			cases = append(cases, e.Name())
		}
	}
	sort.Strings(cases)
	if len(cases) == 0 {
		t.Fatal("no bundle cases")
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			caseDir := filepath.Join(dir, name)
			in, err := jsonv.Parse(readCase(t, caseDir, "inputs.json"))
			if err != nil {
				t.Fatalf("inputs.json: %v", err)
			}
			want, err := strconv.Atoi(strings.TrimSpace(string(readCase(t, caseDir, "expected-exit"))))
			if err != nil {
				t.Fatalf("expected-exit: %v", err)
			}
			flags := append(args(t, in, t.TempDir()), filepath.Join(caseDir, "bundle.json"))

			var report, text, stderr bytes.Buffer
			jsonExit := cli.Run(append([]string{"--json"}, flags...), &report, &stderr)
			textExit := cli.Run(flags, &text, &stderr)
			if stderr.Len() != 0 {
				t.Fatalf("tzun-verify %v: %s", flags, stderr.String())
			}

			renamed, files := inMemory(t, flags)
			got := cli.RunBytes(append([]string{"--json"}, renamed...), files)
			if len(got.Stderr) != 0 {
				t.Fatalf("RunBytes %v: %s", renamed, got.Stderr)
			}
			if got.Exit != want || jsonExit != want || textExit != want {
				t.Errorf("exit: RunBytes %d, Run %d (--json) and %d, want %d", got.Exit, jsonExit, textExit, want)
			}
			a, b := checkedAt.FindAll(got.Stdout, -1), checkedAt.FindAll(report.Bytes(), -1)
			if len(a) != 1 || len(b) != 1 {
				t.Fatalf("checkedAt: %d and %d", len(a), len(b))
			}
			blank := []byte(`"checkedAt":""`)
			if !bytes.Equal(checkedAt.ReplaceAll(got.Stdout, blank), checkedAt.ReplaceAll(report.Bytes(), blank)) {
				t.Errorf("the JSON reports differ\nRunBytes %s\nRun      %s", got.Stdout, report.String())
			}
			if !bytes.Equal(got.Text, text.Bytes()) {
				t.Errorf("the text reports differ\nRunBytes\n%s\nRun\n%s", got.Text, text.String())
			}
		})
	}
}

// inMemory reads every file the flags name into a map, under the name a
// browser page would give it (its base name, which no file in the test's
// working directory has), and rewrites the flags to those names.
func inMemory(t *testing.T, flags []string) ([]string, map[string][]byte) {
	t.Helper()
	files := map[string][]byte{}
	load := func(path string) string {
		name := "in-memory/" + filepath.Base(path)
		if _, err := os.Stat(name); err == nil {
			t.Fatalf("%s exists on disk", name)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = b
		return name
	}
	out := append([]string{}, flags...)
	for i := 0; i < len(out); i++ {
		switch out[i] {
		case "--publishers", "--tsa-roots", "--tsa-intermediates":
			i++
			out[i] = load(out[i])
		case "--evm-header-file":
			i++
			chain, path, ok := strings.Cut(out[i], "=")
			if !ok {
				t.Fatalf("--evm-header-file %q without a chain", out[i])
			}
			out[i] = chain + "=" + load(path)
		}
	}
	out[len(out)-1] = load(out[len(out)-1])
	return out, files
}
