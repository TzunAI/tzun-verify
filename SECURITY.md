# Security policy

tzun-verify tells an auditor whether a Tzun evidence record is what it
claims to be. A defect that makes it report a forged, altered or unanchored
record as verified is a security defect here even when no stranger can
exploit it, so please report those the same way.

## Reporting a vulnerability

**Please do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting on this repository:
**Security → Advisories → Report a vulnerability**
([direct link](https://github.com/TzunAI/tzun-verify/security/advisories/new)).
If you cannot use it, open an issue that asks for a private channel and says
nothing about the problem itself.

Please include, as far as you can:

- the version (`tzun-verify --version`) or commit, and the command you ran;
- what tzun-verify reported, what it should have reported, and the section
  of the specification that says so (`Record §3.2`, as the README cites);
- a minimal reproduction: a proof bundle, a test or a conformance vector
  case. Leave personal data out of it.

### What to expect

| Stage | Target |
|---|---|
| We acknowledge your report | within **3 business days** |
| We confirm or dispute it, with our reasoning | within **10 business days** |
| A fix or a documented mitigation for a confirmed high-severity issue | within **90 days** of confirmation |

We will tell you if any of those slip. With your permission we credit you in
the advisory; tell us if you would rather not be named.

## Scope

**In scope**: this repository, which is the `tzun-verify` command and its
packages, the pinned conformance vectors and publisher manifest, and the
build and release scripts.

Particularly interesting to us:

- a bundle that tzun-verify reports as verified when the specification says
  it must not be: a record whose digest does not match, an inclusion proof
  for another record or another tree, a checkpoint or an anchor that does
  not match what was published;
- a check reported as passed that was not performed, or reported as not
  applicable where the specification says it applies;
- a timestamp token, signature or anchor accepted for a record it was not
  made for;
- two runs on the same input that disagree, or a release binary that does
  not rebuild to the same bytes.

**Out of scope here**: the specification's own text (start a discussion),
the Tzun SDKs and hosted services, which are not in this repository,
dependency advisories with no reachable call path (tell us anyway, and
expect a lower severity), and scanner output without a demonstrated impact.

## Supported versions

Until the first release, the `main` branch. After it, the latest release.

## Safe harbour

We will not pursue or support legal action under computer-misuse,
anti-circumvention or similar laws against anyone who reports in good faith
under this policy, who avoids privacy violations and service degradation,
and who gives us reasonable time to remediate before disclosing publicly.

This safe harbour grants no licence under any patent or patent application.
The code's own licence is in [`LICENSE`](LICENSE).
