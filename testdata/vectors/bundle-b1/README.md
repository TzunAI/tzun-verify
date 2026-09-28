# The b1 conformance corpus

Cases for `b1` record bundles, one directory each. Bundle §13 gives the
files of a case, the format of `inputs.json` and how a verifier replays a
case; Specs §6 states what conformance across the corpus requires.
`index.json` names every case, its expected exit code, and the one thing it
tests.

## The data

- Every bundle holds a record of one store, anchored on a local development
  chain: anvil, CAIP-2 chain `eip155:31337`, whose finalized block trails its
  head by two. The store's anchor origin is
  `test.bundle-b1.tzun/9029134276e6ed9c2815ff9b190a410a/anchors`, a test
  origin (Anchor §4.3.4), and its publisher is anvil's development
  account 5, `0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc`. No network registry
  names `eip155:31337`, so `anchorNetwork` is `null` in every report.
- Record timestamps are RFC 3161 tokens from a test authority whose root,
  "Tzun Corpus Test Root CA", exists only for this corpus. A case that trusts
  a root supplies that one in `trustAnchorsPem`. Apart from the
  `record-token-*` cases, every token passes each step of Anchor §10.5.
- In every case the chain's block times are earlier than the tokens'
  `genTime`. The bound `summary.existedBy` names therefore follows the order
  of Verification §6.4: the record's anchor when `anchor` holds, the
  newer anchor when only `anchor.newer` holds, and the record's timestamp
  when neither does. Each of the three appears in some case.
- Digests, origins, transaction ids, block numbers, block times and `genTime`
  values are those of the run the corpus comes from. Every outcome, reason and
  exit code is stated from the specification.

## The cases

Grouped by what they exercise; the exit code follows each name.

**Anchored records.** `anchored-with-newer` (0): the record's own anchor,
the newer anchor and both consistency proofs, every input supplied.
`anchored-latest-epoch` (0), `anchored-log-unchanged` (0) and
`artifact-not-filled` (0): the other shapes of Bundle §7.3 and §7.5.

**Inputs withheld or relaxed.** `anchored-offline` (4),
`anchored-offline-allow-unchecked` (0), `anchored-no-header-source` (4),
`anchored-not-final` (4), `timestamp-untrusted` (4).

**The record's own token, one step of Anchor §10.5 each.**
`record-token-not-der` (1), `record-token-digest-algorithms-malformed` (1),
`record-token-unreadable-certificate` (1),
`record-token-no-signing-certificate` (1), `record-token-no-timestamping-eku`
(1), `record-token-issuer-name-reencoded` (4).

**Unanchored records.** `unanchored-awaiting-epoch` (4),
`unanchored-allow-unchecked` (0), `unanchored-awaiting-finality` (4),
`unanchored-pending-stripped` (0),
`unanchored-pending-stripped-require-anchor` (3).

**The record altered.** `tampered-payload` (1), `envelope-version-unknown`
(4), `rewrite-and-reseat` (1), `subject-mismatch` (1).

**The anchor altered.** `transplanted-leaf` (1), `transplanted-chain` (1),
`tampered-log-path` (1), `tampered-anchor-path` (1),
`forged-future-anchor-spec` (4), `artifact-stripped` (4).

**Publications.** `fabricated-header-offline` (4),
`fabricated-header-with-source` (1), `manifest-chain-mismatch` (1),
`sender-not-publisher` (1).

**Carried checkpoints and consistency.** `consistency-proof-tampered` (1),
`consistency-proof-missing` (4), `newer-anchor-tampered` (1), `split-view`
(1), `carried-checkpoints-contradict` (4),
`checkpoints-of-two-logs-under-one-key` (2).

**Sign-off.** `signed-record` (4), `signature-stripped` (4), `session-record`
(4), `session-signoff-stripped` (1), `session-signoff-transplanted` (1),
`session-signoff-without-assertion` (1),
`policy-session-signoff-without-assertion` (1), `junk-batch-signoff` (1).

**Material this version does not read.** `witness-extension` (4),
`related-records-filled` (4), `policy-filled` (4), `unknown-member` (4).

**Bundles read as a whole.** `bundle-version-unknown` (2),
`bundle-version-absent` (2), `bundle-chain-profile` (2),
`bundle-unreadable` (2).

## Cases to read with care

- `unanchored-pending-stripped` exits 0 with no anchor at all: exit code 4
  counts artifacts that are present and undecided, and this one is missing
  (Verification §6.6).
  `unanchored-pending-stripped-require-anchor` is the same bundle under a
  regime that requires `anchor`, and exits 3. For a record whose envelope
  does not hold its artifact yet, as in `artifact-not-filled`, the row to
  require is `anchor.newer`.
- `session-signoff-stripped` exits 1 with or without `allowUnchecked`: a
  session record's missing sign-off is a finding, not an unchecked artifact
  (Verification §5).

Where an expected report and the specification disagree, the specification
governs, and the corrected report names the section it follows (Specs §7).
