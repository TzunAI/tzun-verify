# tzun-verify

[![CI](https://github.com/TzunAI/tzun-verify/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TzunAI/tzun-verify/actions/workflows/ci.yml?query=branch%3Amain)
[![public hygiene](https://github.com/TzunAI/tzun-verify/actions/workflows/public-hygiene.yml/badge.svg?branch=main)](https://github.com/TzunAI/tzun-verify/actions/workflows/public-hygiene.yml?query=branch%3Amain)
[![Licence: BSD-3-Clause-Clear](https://img.shields.io/badge/licence-BSD--3--Clause--Clear-blue)](LICENSE)

The standalone verifier for Decision Evidence Object (DEO) proof bundles. It
checks a Tzun evidence record without any Tzun code and without asking Tzun:
it recomputes the record's digest, checks its inclusion in the anchored log,
recomputes the value published on chain, and compares it with the public
ledger through any Ethereum node the auditor chooses.

It is written in Go on stock third-party libraries (transparency logs,
checkpoint notes, RFC 3161 timestamps, Ethereum), from the DEO specification
published at [spec.tzun.ai](https://spec.tzun.ai/), and it shares no code
with the Tzun SDKs. The conformance vectors in `testdata/vectors` state the
result every implementation of that specification must give, and this
repository's tests hold tzun-verify to each of them.

## Specification

The specification is published at [spec.tzun.ai](https://spec.tzun.ai/).
This repository holds no copy of its text, only its own pinned copy of the
conformance vectors (below). Where this README, the code or its comments differ from
the specification, the specification governs, and the difference is a defect
here (Specs §7).

The code, the tests, the vectors' descriptive text and this README cite it as
`<Name> §<n>` (Specs §8.3): `Record §3.2` is section 3.2 of the Record
document at the version below, at https://spec.tzun.ai/record/1.0/#s3-2
(Specs §8.2). A bare `§n` in a comment is a section of the document that
comment, or its package's comment, names. This build implements these
versions:

| Name | Document | Version | What it specifies | URL |
|---|---|---|---|---|
| Specs | The DEO verification specification | none (the index) | The documents and their versions, the conventions (the RFC 2119 keywords among them), the conformance vectors, what conformance means, and how the pages are addressed and cited | https://spec.tzun.ai/ |
| Record | DEO Record Format 1.0 | 1.0 | Envelope and payload, the hashed field set of eleven names, canonical serialization, `canonicalDigest`, the chain link, the decider and agent descriptors, contributions, links to other records, the signature expectation and the mandate form, the record's own RFC 3161 token, and size limits | https://spec.tzun.ai/record/1.0/ |
| Verification | DEO Verification 1.0 | 1.0 | The four row outcomes, the check catalogue (row ids and reasons, the decider, contribution, link and mandate rows included), the report JSON and the exit codes | https://spec.tzun.ai/verification/1.0/ |
| Bundle | DEO Proof Bundle b1 | b1 | The `b1` bundle, how a verifier reads it, and the layout of its conformance corpus | https://spec.tzun.ai/bundle/b1/ |
| Anchor | tzun-anchor/1 | 1 | Checkpoint bodies and origins, the published value P, the publication kinds, the record artifact, the publisher manifest, and the verification steps, the RFC 3161 token checks included | https://spec.tzun.ai/anchor/1/ |
| Tree | RFC 6962 tree profile, revision 2 | 2 | The tree math, the proofs and the hash encoding | https://spec.tzun.ai/tree/2/ |
| Vectors | DEO conformance vectors 1.0 | 1.0 | The conformance vectors, as one archive with its SHA-256 | https://spec.tzun.ai/vectors/1.0/ |

A version's address is permanent, and each page states its version's status
(Specs §8.4). Record 1.0 and Verification 1.0 are Drafts, revised in place
while they are: this build follows their revision of 1 October 2026, under
which the hashed field set of `v1.0` has eleven names (Record §4.1). A record
hashed under an earlier draft's set does not verify under it: its digest is a
mismatch, and `record.digest` names the set it recomputes under
(Verification §4.3).

### The conformance vectors

`testdata/vectors` is the pinned copy of the conformance vectors that hold
under the revised text. The archive published at
https://spec.tzun.ai/vectors/1.0/ predates the revision: Specs §5 names the
parts of it the revision supersedes, and it has no vectors for the members
Record §6 to §9 add. It is to be rebuilt from vectors written under the
revised text. Until then the text governs (Specs §7), this copy is the one
this build is held to, and the two hold different files: the SHA-256 the
Vectors page gives is the archive's, not this copy's.

`testdata/vectors/SOURCE.json` is this repository's own record: the SHA-256
of every file of the copy, and where the files come from. The tests fail on a
file that differs from it, and on a file it does not list (How it is held to
account, below). The copy leaves out, as the published archive does, the
cases of material this version does not verify: custody material, model
descriptors, and the rule a store applies to records captured before 0.7.0.

## What it checks

The rows of a report, in report order (Verification §4.1). Their ids and
reasons are the check catalogue of Verification §4 and Anchor §10.7.

| Row | What it decides |
|---|---|
| `bundle` | The file is JSON, `bundleVersion` is `b1`, `profile` is `record`, and every b1 slot is there (null when empty) with the type Bundle §3.1 gives it; every carried checkpoint body parses and names the origin it sits under, so checkpoints of two logs are never compared; a record bundle carries at most two checkpoints per log; no member name a row id would carry (of the bundle, `extensions`, `envelope.payload`, `nonRepudiation` or `anchoring`) holds a lone surrogate, so every report can be written (Bundle §4 step 9). An absent or unknown version or profile abstains on the whole bundle; anything else wrong is `malformed_bundle`. When this row fails it is the report's only row, and the exit code is 2. |
| `subject` | The bundle's `subject` names the envelope's evidence id and its stored digest. |
| `record.digest` | `integrity.canonicalDigest`, recomputed from the payload by the DEO v1.0 canonical serializer over the eleven names of Record §4.1: `action`, `aiOutput`, `aiSystemId`, `capturedAt`, `contributions`, `decider`, `evidenceId`, `links`, `reason`, `sequenceNumber` and `signoffExpectation`. An absent key is hashed as null. A digest computed over any other set reads `digest_mismatch`; when an earlier draft's set (`0.7`, `before-0.7`) reproduces it, the fact `fieldSet` names that set, which explains the mismatch and never excuses it. An envelope version other than `e1` abstains (`unsupported_envelope_version`), and so does a schema other than `v1.0`. |
| `record.chainLink` | `integrity.chainLink` against `chain.predecessor`: the predecessor is the record numbered one below, and the link is SHA-256 over the two stored digests as hex text. A chain's first record has no link. |
| `custody.ledger` | Never `checked-correct`: this version does not verify custody material. `not_applicable` when the bundle carries none: a null `custody` slot, or one whose `entries` is an empty array, and no hashed entry (one with an `entryHash`) in the envelope's `custodyChain`. Otherwise the row abstains, `unsupported_artifact`, rather than passing custody material unexamined (Verification §4.3, Bundle §6). A hashed `custodyChain` entry mirrors a ledger row: beside a slot with no rows, it names a row the bundle left out. |
| `ts.record.token` / `ts.record.trust` | The record's own RFC 3161 token over its digest, by the steps of Anchor §10.5, then its path to a root the auditor supplied. A key or an algorithm this build does not implement (Libraries, below) makes the check whose step needs it `not-checked`, `missing_dependency`, never `checked-wrong`; a valid path decides the trust row first. `authority` is the first common name of the signer's subject as it stands, or the empty string. |
| `signoff.expectation` | The record's hashed `signoffExpectation` against the sign-off material it carries, by the table of Verification §5, the first matching rule deciding. It needs no key and no signature: it reads which challenge an assertion presented and a batch's inclusion proof. A session sign-off (a `signoff` block whose statement's mode is `session`, or that carries `sessionSeq`, with or without an assertion) on a record whose expectation is null or the policy form is `session_signoff_not_expected`; a sign-off that binds nothing, `signoff_unbound`; a session record's sign-off removed, `signoff_stripped`; another session's statement, `statement_digest_mismatch`; another slot, `session_seq_mismatch`; a value outside the grammar of Record §9.2, `malformed_signoff_expectation`. Under the policy form, when no carried assertion binds the record, the row is `not-checked`, `signature_missing`: that signature may still come. Under the mandate form (rows 17 to 24), the record's `mandate` block: its statement, an assertion whose digest is the record's `mandateAssertion` and that presents the statement's challenge, and a document the statement names; `confirmation_missing` (not checked) while a confirmation is owed. A mandate block on a record of another form is `mandate_not_expected` (row 1a). `blocked_by:record.digest` unless the digest holds: the expectation is authenticated by the digest alone. |
| `signoff.key` | If `signoff.expectation` failed, `blocked_by:signoff.expectation`; `signature_missing` when `signoff.expectation` reads `signature_missing` and the record carries no assertion; an abstention when the `credentials` slot is filled, since this build verifies no WebAuthn signature; `absent` when no assertion is carried; otherwise `not_in_bundle:credential`, because no b1 slot carries the key (Verification §4.5). |
| `decider`, `decider.freshness` | Who decided (Record §6, Verification §4.9): the member's grammar, its kind (an unknown one abstains), the consistency of kind, agent reference and scheme, agreement with the expectation's form, the scheme (an unknown one abstains), and human decision material bound to an agent kind (`material_unverified`). Facts: `kind`, `scheme`, `level` (`human-asserted` or `agent-asserted`: no signature proves it in this version), `levelUndetermined` and `committed`. The finalized-block reference is asked of the auditor's header source for its chain, under the shared deadline: the block at that height must be canonical, final and have that hash. Facts `blockTime`, `captureLag`, `finality`. |
| `contributions`, `contributions.binding`, `contributions.pipeline` | The steps that led to the decision (Record §7, Verification §4.10): the grammar, the step chain, the decider as the deciding actor and the decision as its output; then the process: every input declared, each review bound to the proposal it covers, the decision bound to the last proposal. A named pipeline abstains. |
| `links`, `links[<i>]`, `links[<i>].edge` | The record's relations to other records (Record §8, Verification §4.11): the grammar, the order, the list-level rules, each relation's attribute profile and record-local rules. A bundle carries no target, so a relation with a target rule reads `not_in_bundle:link_target`; a relation this build does not register abstains; and every edge abstains, `unsupported_link_edge`, since no edge proof exists in this version. A record with links therefore exits 4 unless the auditor allows it (below). |
| `mandate.issuance`, `mandate.scope`, `mandate.limits`, `mandate.key`, `mandate.assertionTimestamp` | Mandates (Record §9.6 to §9.9, Verification §4.12): an issuance record's material holds together; a record decided under a mandate lies within its document's scope (agents, systems, actions, models, predicates, confirmation) and limits (`slot`, `totals`); the principal's key, which no b1 slot carries, is never decided; a timestamp over the assertion abstains. |
| `anchor` | The anchor as a whole: `anchorValid` of Anchor §10.6. |
| `anchor.spec` | Step 1: `anchorSpec` is `tzun-anchor/1` and `merkleSpec` is `rfc6962`. Anything else abstains. |
| `anchor.checkpoint` | Step 2: the artifact's shape, both checkpoint bodies (by the grammar of Anchor §4.2 and by the stock C2SP parser), both proofs. |
| `anchor.origin` | Step 2b: both origins are Tzun origins of one domain, and the log is the record's chain's. |
| `anchor.leafIndex` | Step 3: `leafIndex = sequenceNumber − 1`. |
| `anchor.inclusion` | Step 4: the digest is at its index in the log checkpoint (RFC 6962). |
| `anchor.anchorInclusion` | Step 5: the log checkpoint is in the anchor checkpoint. |
| `anchor.publication[i]` | Step 6, each publication's dispatch. |
| `anchor.evm.tx[i]` | An `evm-calldata/1` publication, offline: the transaction's type and signature, the sender against the publisher manifest, the signed chain id, calldata = P and, when the bundle carries them, the header and the transactions-trie proof, walked in order from `transactionsRoot` with every node used once. |
| `anchor.evm.canonical[i]` | The auditor's own node confirms the block is canonical and final, and places the transaction in it. |
| `anchor.tsa.token[i]` / `anchor.tsa.trust[i]` | An `rfc3161/1` publication: a timestamp over P from a timestamping certificate, then its path to a supplied root. |
| `anchor.newer` | When an evidence-log checkpoint carries any of `logPath`, `anchorLeafIndex`, `anchorSize` and `anchorPath`: that checkpoint's own anchor, checked as a `tzun-anchor/1` artifact assembled from them, the anchor-log checkpoint whose size is `anchorSize`, and that checkpoint's publications (Bundle §7.5). |
| `anchor.consistency[<origin>]` | One per origin whose bodies the bundle carries or an authenticated anchor names (Anchor §10.8, Bundle §7.6). Every carried body must be one `anchor` or `anchor.newer` authenticated, with one checkpoint per log as with two; otherwise the row is blocked by `anchor` until the record's own anchor holds, and by `anchor.newer` after that. Two authenticated bodies are compared; an origin with fewer and none unauthenticated has no row. |
| `anchor.pending` | The bundle's `anchorPending` slot: not anchored yet. |
| `extension[<key>]` | An extension with a value, such as a `witness/1` cosignature: abstains, on that key only. |
| `relatedRecords`, `policy` | A reserved slot this build does not read, filled (any value but null): abstains, `unsupported_slot`. |
| `payload.<name>` | A payload member outside the twelve of Record §2.2, whatever its value: it is not hashed, so it abstains, `unsupported_member` (Verification §4.7). A payload that still carries `aiBom`, `humanAction` or `humanReason` is reported this way. |
| `member[<key>]` | Any top-level member outside the b1 slots, `bundleVersion` and `profile`: abstains, `unsupported_member` (Bundle §3.3). |
| `ts.assertion.token`, `nonRepudiation.<member>` | Envelope material present that no row above verifies (an assertion timestamp, an unknown artifact, a legacy `blockchainAnchor` beside an anchor, a `confirmation` the record does not owe): abstains (Verification §4.7). |

**Not verified by this build** (Specs §4): custody material, WebAuthn
signatures and every sign-off row other than `signoff.expectation` and
`signoff.key`, the reserved slots `credentials`, `relatedRecords` and
`policy`, extensions, chain-profile bundles, who a decider is beyond what the
record states, agent descriptors, pipeline definitions, link targets and
edges and the rules of relations it does not know, who signed a mandate and
whether it was in force (Verification §4.8). Each one a bundle carries is
reported, as an abstention or a NOT CHECKED line, and unless it reads
`not_applicable` (a custody slot with no entries, beside a `custodyChain`
that mirrors no ledger row) it holds the exit code at 4 or above
(Verification §4.8, §6.6). Stored summaries are never an input:
`exporter`, the envelope's `attestationStatus` and
`nonRepudiation.rfc3161Metadata` are not read, and every fact is re-derived
(Verification §1).

## Outcomes, and what NOT CHECKED means

Every row has one of four outcomes (Verification §2.1):

| Printed | Outcome | Meaning |
|---|---|---|
| `OK` | `checked-correct` | Decided, and it holds. |
| `FAIL` | `checked-wrong` | Decided, and it fails. |
| `NOT CHECKED` | `not-checked` | This verifier could not decide it, and the reason says why: an input you did not supply (`input_not_supplied:evm_header_source`), material the bundle does not carry (`not_in_bundle:tx_proof`), a node that did not answer in time, or a prerequisite that was not decided (`blocked_by:<row>`). |
| `ABSTAIN` | `abstain` | The artifact names a construction or version this verifier does not implement (`unsupported_anchor_spec`, a future tag). |

NOT CHECKED is not a failure and not a pass. There is no overall VALID: the
exit code turns the outcomes into one number, and `--require` lets an
auditor's own regime decide what must be checked.

Offline, from the bundle alone, the on-chain facts stay NOT CHECKED: a signed
transaction, a block header and a trie proof prove that the publisher key
signed a transaction carrying P, not that it was mined, when, or on which
network. Only your own node, through `--evm-rpc`, can confirm that.

## Exit codes

Verification §6.6:

| Code | Meaning |
|---|---|
| 0 | Nothing wrong; every row whose artifact is in the bundle is correct; every `--require` is met |
| 1 | At least one row is wrong |
| 2 | The bundle could not be read, the `bundle` row is not correct (the bundle was abstained on as a whole, is `malformed_bundle`, or met `bundle_verifier_error`), or the report could not be written |
| 3 | A `--require`d row is not correct, or a `--require-rung` is not met |
| 4 | Something present in the bundle was abstained on or not checked, and `--allow-unchecked` was not passed (or, under `--allow-unchecked-reason`, its reason is not one of those listed) |

Precedence: 2, then 1, then 3, then 4, then 0. `absent`, `not_applicable`
and a row blocked by a wrong row never trigger 4 (the wrong row gives 1
first); a row blocked by any other row does. Exit 4 exists so that a
forged future version tag, which makes a verifier abstain instead of fail,
never reads as success to a script that looks only at the exit code. An
error in the invocation (an unknown flag, an input that cannot be read) exits
64.

**Exit 0 does not mean anchored.** A record with no anchor artifact reads
`absent` on every anchor row, and `absent` does not trigger 4, so a record
stripped of its anchor, its record timestamp and its anchoring exits 0 if
nothing else is wrong. Pass `--require anchor` when your regime needs an
anchor (`--require anchor.newer` when the record's envelope does not hold
its artifact yet), and `--require ts.record.trust` when it needs the
record's own timestamp trusted.

## Install

A GitHub release holds tzun-verify's binary for Linux x86_64 and arm64,
macOS on Intel and Apple silicon, and Windows x86_64, each built
reproducibly and attested (below). Packages for npm (#2), PyPI (#3) and
Homebrew (#4) are planned; none is published yet.

The macOS binaries are not notarized. A file downloaded with a web browser
is quarantined by Gatekeeper and will not open until the quarantine is
removed (`xattr -d com.apple.quarantine tzun-verify`); curl does not
quarantine what it downloads.

### From a GitHub release

Each release is a `v<version>` tag, and its GitHub release holds, for
linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64:

- the binary, `tzun-verify_<version>_<os>_<arch>` (`.exe` on Windows);
- an archive holding it, named `tzun-verify`, with this README, `LICENSE`,
  `NOTICE` and `LICENSE-THIRD-PARTY`: `tzun-verify_<version>_<os>_<arch>.tar.gz`
  (`.zip` on Windows);

and `LICENSE-THIRD-PARTY` on its own, one `SHA256SUMS` over every file, and
a build provenance attestation (GitHub artifact attestations) for every
file. RELEASING.md lists the names. A release's notes list the
specification versions it implements and the SHA-256 of the publisher
manifest it pins.

Download the archive for your platform and `SHA256SUMS`, check the archive
against `SHA256SUMS` and against its attestation, then unpack it:

```
v=0.1.0 p=linux_amd64      # or linux_arm64, darwin_amd64, darwin_arm64
base=https://github.com/TzunAI/tzun-verify/releases/download/v$v
curl -fsSLO "$base/tzun-verify_${v}_$p.tar.gz"
curl -fsSLO "$base/SHA256SUMS"
grep " tzun-verify_${v}_$p.tar.gz\$" SHA256SUMS | sha256sum --check   # macOS: shasum -a 256 --check
gh attestation verify "tzun-verify_${v}_$p.tar.gz" --repo TzunAI/tzun-verify \
  --signer-workflow TzunAI/tzun-verify/.github/workflows/release.yml \
  --source-ref "refs/tags/v$v" --deny-self-hosted-runners
tar -xzf "tzun-verify_${v}_$p.tar.gz" tzun-verify
./tzun-verify --version
```

- `sha256sum --check` prints `OK` when the file is the one `SHA256SUMS`
  names. On Windows, compare `(Get-FileHash tzun-verify_<version>_windows_amd64.zip).Hash`
  in PowerShell with its line in `SHA256SUMS`, ignoring case.
- `gh attestation verify` (the GitHub CLI, logged in) checks that GitHub
  signed a provenance attestation for exactly these bytes, made by this
  repository's release workflow from the tag `v<version>` on a
  GitHub-hosted runner. It reads the attestation from GitHub; `SHA256SUMS`
  alone only shows the download matches the release page.
- The bare binaries check the same way; they need `chmod +x` before they
  run.

Every file can also be rebuilt: on a clean checkout of the tag, with the
pinned toolchain, GNU tar, gzip and zip, `scripts/release-artifacts.sh
"$(mktemp -d)/dist" v<version>` writes the release's files and a
`SHA256SUMS` that must equal the release's, line for line.

## How to run it

To build it yourself instead, use the pinned toolchain (go.mod: Go 1.27.1) and
the release flags:

```
CGO_ENABLED=0 go build -trimpath -buildvcs=false -tags purego -o tzun-verify ./cmd/tzun-verify
```

`go install github.com/TzunAI/tzun-verify/cmd/tzun-verify@v<version>` builds
the same code with your toolchain's default flags, so its bytes are not a
release binary's.

Then:

```
tzun-verify record-42.json                                    # offline
tzun-verify --evm-rpc https://ethereum-sepolia-rpc.publicnode.com record-42.json
tzun-verify --evm-rpc eip155:11155111=https://… record-42.json # a node for one chain
tzun-verify --evm-header-file eip155:11155111=headers.json record-42.json  # headers you exported
tzun-verify --json record-42.json                             # the tzun-verify-report/1 JSON
tzun-verify --allow-unchecked record-42.json                  # exit 0 despite NOT CHECKED lines
tzun-verify --allow-unchecked-reason unsupported_link_edge record-42.json  # only those may stay unchecked
tzun-verify --require 'anchor,anchor.evm.canonical[*]' record-42.json
```

| Flag | What it supplies |
|---|---|
| `--evm-rpc [eip155:<id>=]<url>` | Your header source. Without a chain prefix it serves whichever chain the manifest names, and its own chain id is checked against the transaction's. It is trusted for canonicality and finality, and for nothing else. |
| `--confirmations <n>` | Count a block final at depth n instead of the chain's `finalized` tag, which is the default. Below 64 blocks is not finality on Ethereum and is refused unless you also pass `--accept-non-final`. The report states the mode either way. |
| `--evm-header-file [eip155:<id>=]<file.json>` | A header source you wrote, for an audit with no network: `{"chainId", "finality": "finalized" or {"confirmations": n}, "finalizedBlockNumber", "blocks": [{"number", "hash", "timestamp"}]}`. It is taken at its word, as any header source is: it has no block at a height it does not list, and looks no transaction up. A member it does not know is refused. |
| `--no-tx-lookup` | Never ask the node for the transaction. Without a trie proof in the bundle, nothing then places it in its block. |
| `--publishers <manifest.json>` | The publisher manifest to trust. The default is the manifest pinned in this release (`publishers/publishers.json`), whose address is https://tzun.ai/anchors/publishers.json; `--version` prints the SHA-256 of its bytes, which is how the report names it and what to compare with a copy fetched from that address. A file that is not JSON is refused. |
| `--no-publishers` | Trust no publisher manifest: every EVM publication is then NOT CHECKED, `no_expectation:publisher`. |
| `--tsa-roots <file.pem>`, `--tsa-intermediates <file.pem>` | RFC 3161 trust roots and intermediates. A certificate this build cannot read in full, its key included, is refused with exit 64, never dropped (Verification §3.1). |
| `--timeout <ms>` | One deadline shared by every call to your node (default 30000). |
| `--allow-unchecked-reason <reason>[,<reason>…]` | The scoped allowance: a row left unchecked for one of these reasons does not lead to exit 4, and any other unchecked row still does (repeatable). `--allow-unchecked-reason unsupported_link_edge` accepts a record whose links are all in order but whose edges this version cannot prove, and still exits 4 on a confirmation owed or a stray payload member. |

A switch (`--json`, `--allow-unchecked`, `--accept-non-final`,
`--no-publishers`, `--no-tx-lookup`, `--version`) takes no value:
`--allow-unchecked=false` is a usage error (exit 64), so a wrapper that
passes `--allow-unchecked=${ALLOW:-false}` stops instead of failing open.

**The manifest pinned in this build is empty.** Every EVM publication reads
NOT CHECKED, `no_expectation:publisher`, unless you pass `--publishers`.

## What it prints

This build, offline, on corpus case `links-derived-from`: a record anchored
on a local test chain, whose two links name the record it derives from (no
public node knows its transaction; long values shortened):

```
$ tzun-verify --publishers publishers.json record.json
tzun-verify 0.1.0 · publisher list sha256 1cf3…c9d2 (from --publishers)
Record 7, chain "beta" · digest 3ab2…0003 · bundle b1
  OK          bundle
  OK          subject
  OK          record.digest
  OK          record.chainLink
  NOT CHECKED custody.ledger           not_applicable
  OK          ts.record.token
  NOT CHECKED ts.record.trust          no_matching_trust_anchor
  OK          signoff.expectation
  NOT CHECKED signoff.key              absent
  OK          decider
                kind=human level=human-asserted scheme=acct
  NOT CHECKED decider.freshness        absent
  NOT CHECKED contributions            absent
  NOT CHECKED contributions.binding    absent
  OK          links
                count=2 extensions=0 relations=["derivedFrom","root"]
  OK          links[0]
                targetHeld=false
  ABSTAIN     links[0].edge            unsupported_link_edge
  OK          links[1]
                targetHeld=false
  ABSTAIN     links[1].edge            unsupported_link_edge
  NOT CHECKED anchor                   publication_not_checked
  OK          anchor.spec
  OK          anchor.checkpoint
  OK          anchor.origin
                chainChecked=true namespace=test originAuthenticated=false
  OK          anchor.leafIndex
                leafIndexChecked=true
  OK          anchor.inclusion
  OK          anchor.anchorInclusion
  OK          anchor.publication[0]
  OK          anchor.evm.tx[0]
                sender=0x9965…a4dc signedChainId=31337 transactionId=0x5a83…b9a9 txType=2
  NOT CHECKED anchor.evm.canonical[0]  input_not_supplied:evm_header_source
  NOT CHECKED anchor.newer             publication_not_checked
  NOT CHECKED anchor.consistency[test.bundle-b1.tzun/514d…d8bc/anchors]  blocked_by:anchor
  NOT CHECKED anchor.consistency[test.bundle-b1.tzun/514d…d8bc/evidence/62657461]  blocked_by:anchor
  P = 40041f0f…2ea9ed  (compare: the publication's Input Data)
Existed by  not proven by this verification
Anchor      not decided: publication_not_checked · test
Result      18 correct · 0 wrong · 11 not checked · 2 abstained        exit 4
```

With a header source (`--evm-rpc`) the publication, `anchor`, `anchor.newer`
and both consistency rows are decided too.

## The report

`--json` prints a `tzun-verify-report/1` report in DEO canonical form, in
the shape of Verification §6:

```
{ reportVersion, bundleVersion, subject,
  inputs: { trustAnchors: [SHA-256 of each root's DER, sorted],
            evmHeaderSources: [{ chain, finality }],
            publisherManifest: SHA-256 of the manifest file's bytes | null,
            frameOrigins, vkeys, mdsRoots },
  checks: [ { id, outcome, reason?, facts? } ],
  summary: { mode, coverage, manifestEnforced, rungs, keyKind, keyAssurance, uv, actorBound,
             existedBy: { at, source, check } | null,
             anchorNetwork, anchorNamespace, anchorOriginAuthenticated,
             outcomes: { checked-correct, checked-wrong, not-checked, abstain } },
  checkedAt }
```

The summary is derived from the rows, never read from the bundle. Its
sign-off members stay null: this build derives no mode, rung, key kind or
actor. `existedBy` is the earliest bound the report proves: the record's
anchor, the newer anchor, or the record's own timestamp. `checkedAt` is left
out of comparisons. The inputs name what the verifier was given by
fingerprint and digest only: a header source by its chain (null for one with
no chain prefix) and the finality it declares, never its URL, since a URL
can hold an API key. The manifest is named by the SHA-256 of its file's bytes
(Verification §6.2).

## Libraries

| Job | Library | Pin |
|---|---|---|
| Merkle proofs | github.com/transparency-dev/merkle | main at fbbcd741 (`v0.0.3-0.20260921095310-fbbcd741c3d1`): its v0.0.2 tag accepts five invalid consistency proofs |
| Checkpoint bodies | github.com/transparency-dev/formats `log.Checkpoint` | v0.1.1 |
| Ethereum transactions, sender recovery, RLP | github.com/ethereum/go-ethereum | v1.17.6, built without cgo. The trie proof is walked by this repository (`internal/evm/trie.go`), in order. |
| RFC 3161 and CMS | github.com/digitorus/timestamp, github.com/digitorus/pkcs7, over Go's crypto/x509 | the 2026-09-14 commits. Beyond them, and so `missing_dependency` on the check whose step needs them (Anchor §10.5 step 5): a signer named by subjectKeyIdentifier; a key on a curve other than P-224, P-256, P-384 and P-521, or given by explicit parameters; a DSA key; an MD5 signature; a CMS signature algorithm the CMS library does not map, such as RSASSA-PSS. A certificate that no step needs is not examined. |
| JSON | this repository's `internal/jsonv` | keeps number text, lone surrogates and member order, which `encoding/json` does not |

## How it is held to account

Its correctness does not rest on reading the Go:

1. **The conformance vectors.** `internal/corpus` runs every file of
   `testdata/vectors` (Specs §5) and asserts the result each entry states.
   - Independent transcriptions of the RFCs and of the specification:
     `merkle-rfc6962-vectors.json`, `merkle-consistency-vectors.json`,
     `checkpoint-vectors.json` and `evidence-log-origin-vectors.json`.
   - Output of Tzun's reference implementation, with the expected results
     stated from the specification: `v1.0-canonical-vectors.json`,
     `v1.0-integrity-vectors.json`, `v1.0-worked-example-vectors.json`,
     `anchor-e2e-vectors.json`, `evm-anchor-vectors.json`,
     `signoff-expectation-vectors.json`, `decider-vectors.json`,
     `contributions-vectors.json`, `links-vectors.json`,
     `mandate-vectors.json`, `agent-descriptor-vectors.json`,
     `store-generation-vectors.json`, `cross-sdk-parity-vectors.json` and the
     b1 bundle corpus `bundle-b1/`. These show that implementations agree;
     where one differs from the text, the text decides (Specs §7), and the
     differences found so far are listed below.
   - The record-rule files are replayed as a verifier of one record reads
     them: the decider, contributions and links rows on each stated payload
     (the links cases that name the records a verifier holds, through a
     resolver), the mandate document, statement, assertion digest,
     predicates, scope, limits and issuance row, and the cross-implementation
     cases through the command. The parts that state a writer's own refusals,
     or what a store does across records, are named in the runner and left
     out.
   - `checkpoint-vectors.json`'s artifact cases are compared check by check
     (Anchor §10.7: ids, order, reasons and facts), and
     `signoff-expectation-vectors.json`'s envelopes run through the command,
     each in a bundle, against the answer each states.
   - The bundle corpus runs through the command itself, as Bundle §13.3
     describes: each case's `inputs.json` becomes the flags an auditor would
     pass; the JSON report, inputs included, must equal
     `expected-report.json`, and the exit code `expected-exit`.
   - `testdata/vectors/SOURCE.json` records the SHA-256 of every vector file.
     The runner fails on a file that differs from it, and on a file it does
     not list.
2. **Every b1 case matches exactly, report and exit code** (Specs §6). That
   includes both rows of the record's own timestamp: the corpus's test
   authority holds to every step of Anchor §10.5, and each `record-token-*`
   case carries a token that fails one step, or sits at the edge of one.

   Timestamps from public authorities (FreeTSA and Sectigo) pass as well
   (`internal/rfc3161`, `TestRealAuthorityTokens`), and so does corpus case
   `anchored-with-newer` with its record token replaced by either of them,
   run through the command with both public roots and the checks an auditor
   requires: exit 0, every other row as the corpus states it
   (`internal/corpus/realtsa_test.go`). Both responses are over that case's
   record digest, so a corpus regenerated with a new digest needs new ones;
   the test says how to request them.
3. **Rules the corpus does not pin** are tested from the specification:
   `internal/corpus/signoff_test.go` (`signoff.key`, and binding rules the
   vectors do not separate), `internal/corpus/anchoring_test.go`
   (Anchor §10.8 without a composed anchor, an unauthenticated body,
   carried bodies that do not parse, the predecessor),
   `internal/corpus/custody_test.go` (a hashed `custodyChain` entry whose
   ledger row the bundle leaves out), and each package's own tests.
4. **No Tzun imports.** `scripts/check-no-tzun-imports.sh` fails CI if any
   package the build or the tests link, or any module in the build list,
   comes from the TzunAI organisation. CI also refuses a `go.mod` that
   `go mod tidy` would change.
5. **Reproducible builds.** `scripts/reproducible-build.sh` builds twice, from
   two copies of the tree at different paths, with fresh build caches and
   fresh module caches at different paths, and requires identical binaries;
   CI prints the SHA-256. The release flags include `-tags purego`: without
   it, an assembly file that gnark-crypto (linked through go-ethereum)
   `#include`s from another package keeps the module cache's absolute path in
   the binary, which `-trimpath` does not rewrite. Built this way the binary
   is the same with the tree, the module cache and the Go installation at
   any path. Anyone can rebuild a release and compare its SHA-256.
6. **Mutation testing.** `scripts/mutation-test.sh` removes or weakens one
   check at a time in a copy of the tree (each proof step, each item of
   Anchor §10.4, each rule of Anchor §10.5, the canonical form and the hashed
   field set, the grammar of Record §9.2, the table of Verification §5,
   `signoff.key`, each rule of the decider, contribution, link and mandate
   rows, the payload rows, the exit codes and the scoped allowance, the bundle
   frame, join and composition, the authentication rule of Anchor §10.8, the
   trie walk) and requires the test suite to fail.
7. **The release gate.** `scripts/release-gate.sh` runs on every `v*` tag,
   and anyone can run it on a clone: the reproducible build for every target
   a release publishes, every mutation killed, and the third-party licences
   current for those targets (License, below).
8. **Public hygiene.** `scripts/check-public-hygiene.sh` checks that the
   tree, every commit message and every pull request's title and body refer
   only to this repository and to public places, the specification at
   spec.tzun.ai among them (`.github/workflows/public-hygiene.yml`; `scripts/test-public-hygiene.sh`
   tests the check itself). `git config core.hooksPath .githooks` runs it on
   each commit message before the commit is made.
9. **Licences.** `scripts/check-spdx-headers.sh` fails CI if a Go file, a
   test included, does not begin with its SPDX licence line; `reuse lint`
   fails it if any file lacks its copyright or its licence; and
   `scripts/third-party-licenses.sh --check` fails it if
   `third_party/LICENSE-THIRD-PARTY` no longer holds the licences of the
   modules a release links (License, below).
10. **Release provenance.** `.github/workflows/release.yml` makes every
   release file on two machines, from two clean checkouts of the tag, and
   stops the release unless every file, binaries and archives, is identical
   byte for byte across the two. On each machine
   `scripts/reproducible-build.sh` builds every binary twice and requires
   the two builds to agree. Every file is listed in `SHA256SUMS` and has a
   GitHub build provenance attestation ("Install"; RELEASING.md).
11. **Planned:** an external security review.

## Choices this build makes

The specification fixes the row ids, reasons and report. Where it leaves a
choice to the verifier, this build makes these:

- the `--evm-header-file` format: the header-source format of Bundle §13.2,
  as a file;
- the bounds of the RFC 3161 path search, which Verification §4.4 allows
  (256 candidate certificates, 1,024 signature checks, 65,536
  issuer-to-subject comparisons, 10 certificates a path): a token that
  exceeds them has not shown a path to a supplied root,
  `no_matching_trust_anchor`;
- exit code 64 for an error in the invocation (Verification §6.6);
- a pinned default publisher manifest, which `--publishers` replaces and
  `--no-publishers` removes (Verification §3.1);
- `--allow-unchecked-reason` as the flag of the regime's scoped allowance.

## Where the vectors and the text differ

The revised text and the vectors written with it were drafted together, and
in these places they still name a thing differently. This build gives the
vectors' answer, so that its reports equal those of the reference
implementation, until the text is revised:

- the facts of a failed row: `failedStep` and `failedDigest` on
  `contributions` and `contributions.binding` (the text names `step` and
  `digest`), `rule` and `failedLink` on `malformed_links` (the text names
  `index`), `kind` and `scheme` on a `decider` row that fails or abstains,
  `slot` and `totals` on a failed `mandate.limits`, and no `rel` on a link
  of an unknown relation;
- the rule names of the target and record-local rules (Record §8.3):
  `ratifies_decider_human`, `ratifies_target_not_human`,
  `reviews_distinct_decider` and `supersedes_same_system`, and the rule of a
  link record, which the `links` row reports as `subject_link`;
- every `links[<i>].edge` row abstains, also when `links` does not hold;
- `mandate.issuance` names the link `signer` on its own, after `statement`;
- an approval counts only from a review bound to the proposal it covers, and
  the fact `models` lists model digests in the order the steps name them;
- an ES256 assertion signature in non-minimal DER is read for its value; a
  reader of a mandate document does not apply the writer's rules on
  delegation and on the order of the validity window;
- when the digest does not hold, `decider.freshness` and
  `contributions.binding` are blocked by `record.digest`;
- in a link record, the fact `missing` on a link row that reads a record
  the bundle does not hold names the subject before the target.

Anchor §10.4 item 13 is one place this build keeps the text: a window that
excludes the sender at the block time a source confirms fails
`anchor.evm.tx`, and `anchor.evm.canonical` stays correct, where
`evm-anchor-vectors.json` blocks it.

`custody.ledger` is one place this build reads Verification §4.3 together
with Bundle §6 and Specs §4, which say custody material is never passed
over and never counts as a pass, rather than by its first rule alone. That
rule names only the `custody` slot, so a bundle whose custody row was
removed, while the envelope's `custodyChain` still carries the row's hashed
mirror entry, would read `not_applicable` and exit 0. This build abstains
on it, `unsupported_artifact`, exit 4 (`internal/corpus/custody_test.go`).
The reference implementation, which verifies custody material, reports that
bundle `checked-wrong` and exits 1, with a reason Verification §2.3 does not
list; the vectors pinned here leave its custody cases out.

Where the vectors state no answer, this build keeps the text too, and its
report can differ from the reference implementation's, in some cases in its
exit code:

- `mandate.key` is reported for a record that carries an issuance block,
  blocked by `mandate.issuance` when that row fails, and blocked by
  `signoff.expectation` when the expectation of the mandate form fails
  (Verification §4.12);
- a confirmation the record does not owe has the row
  `nonRepudiation.confirmation` (Verification §4.7);
- a step `aiBom` that is neither null nor an object makes the contributions
  malformed (Record §7.1);
- assertion text is decoded as Record §9.3 decodes it: trailing `=`
  removed, CR and LF skipped, and any other character outside the alphabet
  refused;
- the `mandate.scope` fact `failed` lists the failed constraints as names;
- when the digest does not hold, `mandate.scope` and `mandate.limits` are
  blocked by `signoff.expectation`, and a links list of 1 to 256 elements
  still has its `links[<i>]` rows, blocked by `links`; a list longer than
  256 has no per-link rows;
- when both `decision_unbound` and `decided_output_differs` hold,
  `decision_unbound` is reported, as the text orders them, and the fact
  `approvals` is carried whenever the record is decided, also when
  `contributions.binding` fails;
- an issuance block of the wrong type fails the link `document`, the first
  link that needs it;
- a decider object without a `freshness` member is not one whose freshness
  is null, so `decider.freshness` is blocked by `decider`;
- a sign-off block of any JSON type is a block, so a per-record assertion
  beside a block that is not an object binds nothing, and the `decider` row
  has no `levelUndetermined`;
- a payload member name holding a lone surrogate makes the bundle
  unreadable (Bundle §4 step 9).

## Layout

```
cmd/tzun-verify      the command's entry point
internal/cli        the flags, the inputs they build and the text report
internal/jsonv      strict JSON reading
internal/canonical  the DEO v1.0 canonical serializer, the hashed field sets, record digest, chain link
internal/grammar    the value rules the record members share (Record §1.2)
internal/decider    the decider and a step's actor, and the decider row
internal/contrib    contributions, output and step digests, and their rows
internal/links      links, the relation registry, and their rows
internal/mandate    the mandate document, statement, assertion digest, predicates, scope, limits, issuance
internal/agent      the agent descriptor tzun-agent/1 and its digest
internal/merkle     RFC 6962 proofs through transparency-dev/merkle
internal/checkpoint checkpoint bodies, origins and origin binding
internal/manifest   the publisher manifest
internal/evm        evm-calldata/1, the ordered trie-proof walk, the JSON-RPC header source
internal/rfc3161    rfc3161/1, and the record's own token
internal/anchor     the anchor verification of Anchor §10.3 to §10.8
internal/bundle     the b1 bundle: its frame, record, sign-off, record-rule, anchoring and summary rows
internal/report     outcomes, the report, the text output and exit codes
internal/corpus     the conformance vector runner and spec-derived cases (tests only)
internal/testpki    a throwaway RFC 3161 PKI and token builder (tests only)
publishers          the pinned publisher manifest
scripts             CI, release-gate, release, licence and public-hygiene scripts
.githooks           the commit-message hook of the public-hygiene check
testdata/vectors    the pinned copy of the conformance vectors (Specs §5)
LICENSES            the licence texts: BSD-3-Clause-Clear, CC0-1.0 for the vectors, and the note on the timestamp authorities' test files
third_party         the licences of the third-party code in a release binary (scripts/third-party-licenses.sh writes them)
```

## Questions, problems and contributions

Questions and ideas go to
[Discussions](https://github.com/TzunAI/tzun-verify/discussions), and a
wrong result or a crash to an [issue](https://github.com/TzunAI/tzun-verify/issues/new/choose).
A security problem is reported privately, as [`SECURITY.md`](SECURITY.md)
says. [`CONTRIBUTING.md`](CONTRIBUTING.md) lists the checks a change must
pass.

## License

tzun-verify is licensed under the BSD 3-Clause Clear License (`LICENSE`).
Every Go file says so in its first line, as an SPDX licence identifier
(`BSD-3-Clause-Clear`). No patent licence, express or implied, is granted
by the licence; its text says so.

The conformance vectors in `testdata/vectors` are licensed under CC0-1.0
(`LICENSES/CC0-1.0.txt`).

Four test files in `internal/rfc3161/testdata` are not Tzun's and are under
neither licence: the root certificates of the public timestamp authorities
Free TSA and Sectigo, and a timestamp response from each, kept as published
(the Sectigo root re-encoded as PEM) and as received.
`LICENSES/LicenseRef-Timestamp-Authority-Material.txt` says what each file
is and where it came from. No release binary contains them.

A release binary also contains the Go standard library and runtime and the
modules the build links, each under its own licence: go-ethereum's library
under the GNU Lesser General Public License, version 3 or later, and the
others under the BSD, MIT, ISC and Apache licences.
`third_party/LICENSE-THIRD-PARTY` holds each of those licences as its module
ships it, and a release publishes it beside the binaries;
`scripts/third-party-licenses.sh` writes it, and CI fails when it is not
current.

`NOTICE` holds the copyright notice. The repository follows the REUSE
specification (https://reuse.software/): each file's copyright and licence
are in its own header or in `REUSE.toml`, and `reuse lint`, which CI runs,
checks that every file has both.
