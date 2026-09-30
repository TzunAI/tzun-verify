package cli

import (
	"bytes"
	"io/fs"
	"syscall"
)

// Output is what one run of the command prints and returns.
type Output struct {
	// Exit is the exit code (Verification §6.6), or
	// report.ExitUsageError.
	Exit int
	// Stdout is what the command prints on standard output: with --json,
	// the tzun-verify-report/1 report and a newline.
	Stdout []byte
	// Text is, with --json, the text report of the same verification: what
	// the command prints on standard output without --json. It is empty
	// when there is no report.
	Text []byte
	// Stderr is what the command prints on standard error.
	Stderr []byte
}

// RunBytes is the command for a caller with no file system, the browser
// page's WebAssembly build (cmd/tzun-verify-wasm) among them. args are the
// command's flags and the bundle's name, as an auditor types them; every
// file they name, the bundle included, is read from files by that name, and
// a name files does not hold reads as a file that does not exist. The
// verification, the report and the exit code are the command's own: only
// where the bytes come from differs.
func RunBytes(args []string, files map[string][]byte) Output {
	read := func(name string) ([]byte, error) {
		b, ok := files[name]
		if !ok {
			// The error os.ReadFile gives for a missing file.
			return nil, &fs.PathError{Op: "open", Path: name, Err: syscall.ENOENT}
		}
		return b, nil
	}
	var stdout, text, stderr bytes.Buffer
	exit := run(args, read, &stdout, &stderr, &text)
	return Output{Exit: exit, Stdout: stdout.Bytes(), Text: text.Bytes(), Stderr: stderr.Bytes()}
}
