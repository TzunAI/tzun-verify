// Package cli is the tzun-verify command: its flags, the verifier's inputs
// they build, and the JSON and human-readable reports. The conformance
// corpus runner (internal/corpus) drives it through Run, so the report's
// inputs block it checks is the one the command builds.
package cli

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TzunAI/tzun-verify/internal/bundle"
	"github.com/TzunAI/tzun-verify/internal/evm"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
	"github.com/TzunAI/tzun-verify/internal/rfc3161"
	"github.com/TzunAI/tzun-verify/publishers"
)

// Version is this build's version. Releases set it in source, not by
// linker flag, so a rebuild from the tagged tree reproduces the binary.
const Version = "0.1.0-dev"

const usage = `usage: tzun-verify [flags] <bundle.json>

Verifies a Tzun b1 proof bundle offline. Flags may come before or after the
bundle path.

  --evm-rpc [eip155:<id>=]<url>  an Ethereum JSON-RPC endpoint you choose, as the
                                 header source (repeatable; without a chain prefix
                                 it serves whichever chain the manifest names)
  --evm-header-file [eip155:<id>=]<file.json>
                                 a header source you wrote: its chain id, finality,
                                 finalized height and canonical blocks (repeatable;
                                 taken at its word, as any header source is)
  --confirmations <n>            count a block final at this depth instead of the
                                 chain's "finalized" tag (at least 64)
  --accept-non-final             allow --confirmations below 64
  --no-tx-lookup                 never ask the node for the transaction itself
  --publishers <manifest.json>   the publisher manifest to trust (default: the copy
                                 pinned in this release)
  --no-publishers                trust no publisher manifest at all
  --tsa-roots <file.pem>         RFC 3161 trust roots (repeatable)
  --tsa-intermediates <file.pem> RFC 3161 intermediate certificates (repeatable)
  --timeout <ms>                 one deadline for every header-source call
                                 (default 30000)
  --json                         print the tzun-verify-report/1 JSON report
  --allow-unchecked              exit 0 even when something present was not checked
  --require <id>[,<id>...]       checks that must be checked-correct (exit 3
                                 otherwise); "anchor.evm.canonical[*]" matches every
                                 index (repeatable)
  --require-rung <rung>          a sign-off rung that must be met (repeatable)
  --version                      print the version and the pinned manifest's SHA-256
  -h, --help                     print this help

Switches (--json, --allow-unchecked, --accept-non-final, --no-publishers,
--no-tx-lookup) take no value: --allow-unchecked=false is refused.

Exit codes: 0 nothing wrong and everything present checked; 1 something is
wrong; 2 the bundle could not be read, or was abstained on as a whole; 3 a
--require or --require-rung was not met; 4 something present was not checked.

A record with no anchor at all reads "absent" on every anchor row, and absent
does not stop exit 0: exit 0 alone does not say the record is anchored. An
auditor whose regime needs an anchor passes --require anchor, and one who
needs the record's own timestamp trusted passes --require ts.record.trust.
`

type config struct {
	path           string
	rpcs           []string
	headerFiles    []string
	confirmations  uint64
	acceptNonFinal bool
	noLookup       bool
	publishers     string
	noPublishers   bool
	tsaRoots       []string
	tsaInter       []string
	timeout        time.Duration
	json           bool
	policy         report.Policy
	showVersion    bool
}

var errHelp = errors.New("help")

func parseArgs(args []string) (*config, error) {
	c := &config{timeout: 30 * time.Second}
	next := func(i *int, name string) (string, error) {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("%s needs a value", name)
		}
		*i++
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-h" {
			return nil, errHelp
		}
		name, val, hasVal := strings.Cut(a, "=")
		if !strings.HasPrefix(a, "--") {
			if c.path != "" {
				return nil, fmt.Errorf("more than one bundle path: %q and %q", c.path, a)
			}
			c.path = a
			continue
		}
		value := func() (string, error) {
			if hasVal {
				return val, nil
			}
			return next(&i, name)
		}
		switch name {
		case "--accept-non-final", "--no-tx-lookup", "--no-publishers", "--json", "--allow-unchecked", "--version", "--help":
			// A switch takes no value. "--allow-unchecked=false" would
			// otherwise switch it on, and a wrapper passing
			// --allow-unchecked=${ALLOW:-false} would fail open.
			if hasVal {
				return nil, fmt.Errorf("%s takes no value (got %q)", name, a)
			}
		}
		var err error
		var v string
		switch name {
		case "--evm-rpc":
			if v, err = value(); err == nil {
				c.rpcs = append(c.rpcs, v)
			}
		case "--evm-header-file":
			if v, err = value(); err == nil {
				c.headerFiles = append(c.headerFiles, v)
			}
		case "--confirmations":
			if v, err = value(); err == nil {
				c.confirmations, err = strconv.ParseUint(v, 10, 64)
				if err == nil && c.confirmations == 0 {
					err = fmt.Errorf("--confirmations must be a positive integer")
				}
			}
		case "--accept-non-final":
			c.acceptNonFinal = true
		case "--no-tx-lookup":
			c.noLookup = true
		case "--publishers":
			c.publishers, err = value()
		case "--no-publishers":
			c.noPublishers = true
		case "--tsa-roots":
			if v, err = value(); err == nil {
				c.tsaRoots = append(c.tsaRoots, v)
			}
		case "--tsa-intermediates":
			if v, err = value(); err == nil {
				c.tsaInter = append(c.tsaInter, v)
			}
		case "--timeout":
			if v, err = value(); err == nil {
				var ms uint64
				ms, err = strconv.ParseUint(v, 10, 32)
				if err == nil && ms == 0 {
					err = fmt.Errorf("--timeout must be a positive number of milliseconds")
				}
				c.timeout = time.Duration(ms) * time.Millisecond
			}
		case "--json":
			c.json = true
		case "--allow-unchecked":
			c.policy.AllowUnchecked = true
		case "--require":
			if v, err = value(); err == nil {
				for _, id := range strings.Split(v, ",") {
					if id = strings.TrimSpace(id); id != "" {
						c.policy.Require = append(c.policy.Require, id)
					}
				}
			}
		case "--require-rung":
			if v, err = value(); err == nil {
				c.policy.RequireRungs = append(c.policy.RequireRungs, v)
			}
		case "--version":
			c.showVersion = true
		case "--help":
			return nil, errHelp
		default:
			return nil, fmt.Errorf("unknown flag %s", name)
		}
		if err != nil {
			return nil, err
		}
	}
	if c.publishers != "" && c.noPublishers {
		return nil, fmt.Errorf("--publishers and --no-publishers are exclusive")
	}
	if c.path == "" && !c.showVersion {
		return nil, fmt.Errorf("no bundle given")
	}
	return c, nil
}

func readCerts(paths []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		n := 0
		for {
			var blk *pem.Block
			blk, data = pem.Decode(data)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			// A certificate the auditor supplies is an input this build must
			// read in full, its key included: one whose key it cannot use
			// is refused, never dropped (Verification §3.1).
			if !rfc3161.KeyImplemented(c) {
				return nil, fmt.Errorf("%s: a certificate whose public-key algorithm this build does not implement", p)
			}
			out = append(out, c)
			n++
		}
		if n == 0 {
			return nil, fmt.Errorf("%s: no PEM certificate", p)
		}
	}
	return out, nil
}

// chainPrefix splits [eip155:<id>=]<rest>.
func chainPrefix(flag, spec string) (chain, rest string, err error) {
	if !strings.HasPrefix(spec, "eip155:") {
		return "", spec, nil
	}
	chain, rest, ok := strings.Cut(spec, "=")
	if !ok {
		return "", "", fmt.Errorf("%s %q: expected eip155:<id>=<value>", flag, spec)
	}
	if n, ok := new(big.Int).SetString(strings.TrimPrefix(chain, "eip155:"), 10); !ok || n.Sign() <= 0 {
		return "", "", fmt.Errorf("%s %q: bad chain", flag, spec)
	}
	return chain, rest, nil
}

// manifestSource names where the manifest came from, for the text report.
type manifestSource string

const (
	manifestPinned manifestSource = "pinned in this release"
	manifestFile   manifestSource = "from --publishers"
	manifestNone   manifestSource = "none: --no-publishers"
)

// options builds the verifier's inputs from the flags. Every error is a
// usage error: an input the auditor named and the command could not read is
// refused, never passed on as absent.
func options(c *config) (bundle.Options, manifestSource, error) {
	opts := bundle.Options{Timeout: c.timeout}
	src := manifestPinned
	switch {
	case c.noPublishers:
		src = manifestNone
	case c.publishers != "":
		data, err := os.ReadFile(c.publishers)
		if err != nil {
			return opts, src, err
		}
		if opts.Manifest, err = jsonv.Parse(data); err != nil {
			return opts, src, fmt.Errorf("--publishers %s: not JSON: %v", c.publishers, err)
		}
		opts.ManifestBytes = data
		src = manifestFile
	default:
		var err error
		if opts.Manifest, err = jsonv.Parse(publishers.Pinned); err != nil {
			return opts, src, fmt.Errorf("the pinned publisher manifest: %v", err)
		}
		opts.ManifestBytes = publishers.Pinned
	}

	roots, err := readCerts(c.tsaRoots)
	if err != nil {
		return opts, src, fmt.Errorf("--tsa-roots: %v", err)
	}
	inter, err := readCerts(c.tsaInter)
	if err != nil {
		return opts, src, fmt.Errorf("--tsa-intermediates: %v", err)
	}
	opts.Trust = rfc3161.Trust{Roots: roots, Intermediates: inter}

	opts.Sources.ByChain = map[string]evm.HeaderSource{}
	add := func(flag, chain string, s evm.HeaderSource) error {
		if chain == "" {
			if opts.Sources.Any != nil {
				return fmt.Errorf("more than one header source without a chain prefix")
			}
			opts.Sources.Any = s
			return nil
		}
		if _, dup := opts.Sources.ByChain[chain]; dup {
			return fmt.Errorf("%s: a second header source for %s", flag, chain)
		}
		opts.Sources.ByChain[chain] = s
		return nil
	}
	for _, spec := range c.rpcs {
		chain, url, err := chainPrefix("--evm-rpc", spec)
		if err != nil {
			return opts, src, err
		}
		s, err := evm.NewRPCSource(url, c.confirmations, c.acceptNonFinal)
		if err != nil {
			return opts, src, err
		}
		s.NoLookup = c.noLookup
		if err := add("--evm-rpc", chain, s); err != nil {
			return opts, src, err
		}
	}
	for _, spec := range c.headerFiles {
		chain, path, err := chainPrefix("--evm-header-file", spec)
		if err != nil {
			return opts, src, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return opts, src, err
		}
		s, err := evm.ParseStaticSource(data)
		if err != nil {
			return opts, src, fmt.Errorf("--evm-header-file %s: %v", path, err)
		}
		if err := add("--evm-header-file", chain, s); err != nil {
			return opts, src, err
		}
	}
	return opts, src, nil
}

// Run runs the command and returns its exit code (Verification §6.6), or
// report.ExitUsageError for arguments or inputs it cannot use.
func Run(args []string, stdout, stderr io.Writer) int {
	c, err := parseArgs(args)
	if err == errHelp {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "tzun-verify: %v\n\n%s", err, usage)
		return report.ExitUsageError
	}
	if c.showVersion {
		fmt.Fprintf(stdout, "tzun-verify %s\npinned publisher manifest sha256 %s\n", Version, publishers.SHA256())
		return 0
	}
	opts, src, err := options(c)
	if err != nil {
		fmt.Fprintf(stderr, "tzun-verify: %v\n", err)
		return report.ExitUsageError
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		fmt.Fprintf(stderr, "tzun-verify: %v\n", err)
		return report.ExitBundle
	}
	res := bundle.Verify(data, opts)
	exit := report.ExitCode(res.Report, c.policy)
	// A report that has no canonical form cannot be written, whatever the
	// output format, and exits 2 (Verification §6.5).
	out, err := res.Report.Canonical(true)
	if err != nil {
		fmt.Fprintf(stderr, "tzun-verify: the report cannot be written: %v\n", err)
		return report.ExitBundle
	}
	if c.json {
		stdout.Write(out)
		fmt.Fprintln(stdout)
		return exit
	}
	writeText(stdout, res, src, exit)
	return exit
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:4] + "…" + h[len(h)-4:]
}

func writeText(w io.Writer, res *bundle.Result, src manifestSource, exit int) {
	manifest := "none"
	if m, ok := res.Report.Inputs.Get("publisherManifest"); ok && m.Kind == jsonv.String {
		manifest = "sha256 " + short(m.S)
	}
	header := []string{fmt.Sprintf("tzun-verify %s · publisher list %s (%s)", Version, manifest, src)}
	if res.Report.Readable() {
		rec := "Record"
		if res.Sequence != nil && res.Sequence.Kind == jsonv.Number {
			rec += " " + res.Sequence.Raw
		}
		if res.ChainID != "" {
			rec += fmt.Sprintf(", chain %q", res.ChainID)
		}
		if res.Digest != "" {
			rec += " · digest " + short(res.Digest)
		}
		header = append(header, rec+" · bundle b1")
	}
	var summary []string
	if a := res.Anchor; a != nil {
		if a.P != nil {
			summary = append(summary, fmt.Sprintf("  P = %x  (compare: the publication's Input Data)", a.P))
		}
	}
	if res.Report.Readable() {
		if e := res.ExistedBy; e != nil {
			summary = append(summary, fmt.Sprintf("Existed by  %s (%s, %s)", e.At.UTC().Format("2006-01-02 15:04:05Z"), e.Source, e.Check))
		} else {
			summary = append(summary, "Existed by  not proven by this verification")
		}
	}
	if a := res.Anchor; a != nil {
		line := "Anchor      "
		switch {
		case a.Valid != nil && *a.Valid:
			parts := []string{}
			if a.Publication == "evm-calldata" {
				parts = append(parts, "public ledger")
			} else {
				parts = append(parts, "RFC 3161 timestamp only (existed-by, origin not authenticated)")
			}
			if a.Network != "" {
				parts = append(parts, a.Network)
			}
			if a.Namespace != nil {
				parts = append(parts, *a.Namespace)
			}
			if a.OriginAuthenticated {
				parts = append(parts, "publisher authenticated")
			} else {
				parts = append(parts, "publisher not authenticated")
			}
			line += strings.Join(parts, " · ")
		case a.Valid != nil:
			line += "FAILED: " + a.Reason
		default:
			line += "not decided: " + a.Reason
			if a.Namespace != nil {
				line += " · " + *a.Namespace
			}
		}
		summary = append(summary, line)
	}
	report.WriteText(w, res.Report, header, summary, exit)
}
