package bundle

import (
	"sort"

	"github.com/TzunAI/tzun-verify/internal/anchor"
	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/report"
	"github.com/TzunAI/tzun-verify/internal/rfc3161"
)

// timeLayout is how the report writes an instant: UTC, milliseconds.
const timeLayout = "2006-01-02T15:04:05.000Z"

// inputsOf is the report's inputs block (Verification §6.2): what
// the auditor supplied, named so that a reader can tell which inputs
// produced the report without the report carrying them. Trust roots by the
// SHA-256 of their DER, sorted; header sources by chain (null for one
// serving any chain) with the finality each declares, sorted; the manifest
// by the SHA-256 of its bytes.
func inputsOf(opts Options) *jsonv.Value {
	roots := make([]string, 0, len(opts.Trust.Roots))
	for _, c := range opts.Trust.Roots {
		roots = append(roots, sha256Hex(c.Raw))
	}
	sort.Strings(roots)
	trust := report.Arr()
	for _, r := range roots {
		trust.A = append(trust.A, report.S(r))
	}

	sources := report.Arr()
	if s := opts.Sources.Any; s != nil {
		sources.A = append(sources.A, report.Obj("chain", report.Null(), "finality", s.Finality().JSON()))
	}
	chains := make([]string, 0, len(opts.Sources.ByChain))
	for c := range opts.Sources.ByChain {
		chains = append(chains, c)
	}
	sort.Strings(chains)
	for _, c := range chains {
		sources.A = append(sources.A, report.Obj("chain", report.S(c), "finality", opts.Sources.ByChain[c].Finality().JSON()))
	}

	manifest := report.Null()
	switch {
	case opts.Manifest != nil && opts.ManifestBytes != nil:
		manifest = report.S(sha256Hex(opts.ManifestBytes))
	case opts.Manifest != nil:
		// A caller that passes a parsed manifest without its bytes: name it
		// by its canonical form, the bytes it would have in a file written
		// canonically.
		if b, err := canonical.Serialize(opts.Manifest); err == nil {
			manifest = report.S(sha256Hex(b))
		}
	}
	return report.Obj(
		"trustAnchors", trust,
		"evmHeaderSources", sources,
		"publisherManifest", manifest,
		"frameOrigins", report.Null(),
		"vkeys", report.Null(),
		"mdsRoots", report.Null(),
	)
}

// existedBy is the earliest proven bound (Verification §6.4): the
// record's own anchor, the newer anchor, or the record's RFC 3161 token
// once both its rows hold. On a tie the first in that order is named.
func (v *verification) existedBy() *ExistedBy {
	var best *ExistedBy
	offer := func(e *ExistedBy) {
		if e != nil && (best == nil || e.At.Before(best.At)) {
			best = e
		}
	}
	fromAnchor := func(a *anchor.Verdict, check string) *ExistedBy {
		if a == nil || a.Valid == nil || !*a.Valid || a.ExistedBy == nil {
			return nil
		}
		return &ExistedBy{At: a.ExistedBy.At, Source: a.ExistedBy.Source, Check: check}
	}
	offer(fromAnchor(v.res.Anchor, anchor.IDAnchor))
	offer(fromAnchor(v.res.Newer, anchor.IDNewer))
	if v.recordTS != nil {
		offer(&ExistedBy{At: v.recordTS.GenTime, Source: "record-timestamp", Check: rfc3161.IDRecordTrust})
	}
	return best
}

// agree returns the one value two verdicts give, or nil when neither gives
// one or they give different ones.
func agree(a, b *string) *string {
	switch {
	case a == nil:
		return b
	case b == nil || *a == *b:
		return a
	}
	return nil
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// summarize derives the summary from the rows and verdicts
// (Verification §6.4). The anchor origin is the domain's anchor
// log, which both the record's anchor and the newer anchor publish under:
// it is authenticated when either authenticates it, and the network and
// namespace are the ones they give, or null when they disagree. Sign-off
// members stay null: this build derives no mode, rung, key kind or actor.
func summarize(r *Result) *jsonv.Value {
	var network, namespace *string
	authenticated := false
	var verdicts []*anchor.Verdict
	for _, a := range []*anchor.Verdict{r.Anchor, r.Newer} {
		if a != nil {
			verdicts = append(verdicts, a)
		}
	}
	for i, a := range verdicts {
		authenticated = authenticated || a.OriginAuthenticated
		if i == 0 {
			network, namespace = nonEmpty(a.Network), a.Namespace
			continue
		}
		network, namespace = agree(network, nonEmpty(a.Network)), agree(namespace, a.Namespace)
	}
	existed := report.Null()
	if e := r.ExistedBy; e != nil {
		existed = report.Obj("at", report.S(e.At.UTC().Format(timeLayout)), "source", report.S(e.Source), "check", report.S(e.Check))
	}
	return report.Obj(
		"mode", report.Null(),
		"coverage", report.Null(),
		"manifestEnforced", report.Null(),
		"rungs", report.Arr(),
		"keyKind", report.Null(),
		"keyAssurance", report.Null(),
		"uv", report.Null(),
		"actorBound", report.Null(),
		"existedBy", existed,
		"anchorNetwork", report.SOrNull(network),
		"anchorNamespace", report.SOrNull(namespace),
		"anchorOriginAuthenticated", report.B(authenticated),
		"outcomes", report.CountsJSON(r.Report.Checks),
	)
}
