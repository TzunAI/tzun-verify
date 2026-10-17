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
  `test.bundle-b1.tzun/514db935932b4483edc610595839d8bc/anchors`, a test
  origin (Anchor §4.3.4), and its publisher is anvil's development
  account 5, `0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc`. No network registry
  names `eip155:31337`, so `anchorNetwork` is `null` in every report.
- Every record is a `v1.0` record of the hashed field set of Record §4.1:
  `action` and `reason`, a `decider` (a human under `acct` unless a case
  names another), and `contributions` and `links` that are `null` unless a
  case carries them. So every report has the rows `decider`,
  `decider.freshness`, `contributions`, `contributions.binding` and `links`
  of Verification §4.9 to §4.11, between `signoff.key` and `anchor`.
- Record timestamps are RFC 3161 tokens from a test authority whose root,
  "Tzun Corpus Test Root CA", exists only for this corpus. A case that trusts
  a root supplies that one in `trustAnchorsPem`. The `anchor-token-*` cases
  give the record's anchor a second publication, an `rfc3161/1` token over
  its P from a second test authority, under "Tzun Corpus Anchor Test Root
  CA", and supply both roots unless the case withholds them. Apart from the
  `record-token-*` cases and the second publication of
  `anchor-token-other-value` and `anchor-token-not-der`, every token passes
  each step of Anchor §10.5.
- In every case the chain's block times are earlier than the tokens'
  `genTime`. The bound `summary.existedBy` names therefore follows the order
  of Verification §6.4: the record's anchor when `anchor` holds, the
  newer anchor when only `anchor.newer` holds, and the record's timestamp
  when neither does. Each of the three appears in some case.
- Digests, origins, transaction ids, block numbers, block times and `genTime`
  values are those of the run the corpus comes from. Every outcome, reason and
  exit code is stated from the specification.
- `regime.allowUnchecked` in `inputs.json` is `true` or `false`, or a list of
  reasons: the scoped allowance, under which only rows left unchecked for one
  of those reasons stop counting toward exit code 4.

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
`record-token-unreadable-certificate` (1), `record-token-signer-off-curve`
(1), `record-token-no-signing-certificate` (1),
`record-token-no-timestamping-eku` (1), `record-token-issuer-name-reencoded`
(4), `record-token-signer-unassigned-curve` (4),
`record-token-intermediate-unassigned-curve` (4) and
`record-token-unneeded-certificate-unassigned-curve` (0). The signer
subjects that shape the fact `authority` (Anchor §10.5 step 4, §10.7):
`record-token-authority-first-cn`, `-multi-valued-rdn`, `-specials`,
`-line-feed`, `-utf8-string`, `-bmp-string`, `-teletex-string`, `-empty-cn`,
`-no-cn` and `-empty-subject`, each (0).

**A second publication, a timestamp over P (Anchor §10.5, §10.6).**
`anchor-token-trusted` (0): both roots supplied, `anchor.tsa.token[1]` and
`anchor.tsa.trust[1]` hold. `anchor-token-no-roots` (4): no root supplied;
steps 1 to 3 need none, so the token check still holds and the trust check
is `no_matching_trust_anchor`. `anchor-token-other-value` (1): the token is
over the record's digest instead of P, `imprint_mismatch`.
`anchor-token-not-der` (1): its `TSTInfo` in a constructed (BER) OCTET
STRING, `malformed_publication`. In the last two, one false publication
makes the record's anchor false, and `existedBy` comes from `anchor.newer`.

**Unanchored records.** `unanchored-awaiting-epoch` (4),
`unanchored-allow-unchecked` (0), `unanchored-awaiting-finality` (4),
`unanchored-pending-stripped` (0),
`unanchored-pending-stripped-require-anchor` (3).

**The record altered.** `tampered-payload` (1),
`tampered-payload-artifact-stripped` (1),
`payload-name-lone-surrogate-fffd-digest` (1), `envelope-version-unknown`
(4), `rewrite-and-reseat` (1), `subject-mismatch` (1).

**The anchor altered.** `transplanted-leaf` (1), `transplanted-chain` (1),
`tampered-log-path` (1), `tampered-anchor-path` (1),
`forged-future-anchor-spec` (4), `artifact-stripped` (4).

**Publications.** `fabricated-header-offline` (4),
`fabricated-header-with-source` (1), `manifest-chain-mismatch` (1),
`sender-not-publisher` (1), and a manifest entry whose `validFrom` falls
half a millisecond either side of a block's second, read to its full
precision (Anchor §9): `manifest-valid-from-fraction-late` (1),
`manifest-valid-from-fraction-early` (0).

**Carried checkpoints and consistency.** `consistency-proof-tampered` (1),
`consistency-proof-missing` (4), `newer-anchor-tampered` (1), `split-view`
(1), `carried-checkpoints-contradict` (4),
`checkpoints-of-two-logs-under-one-key` (2).

**Sign-off.** `signed-record` (4), `signature-stripped` (4), `session-record`
(4), `session-signoff-stripped` (1), `session-signoff-transplanted` (1),
`session-signoff-without-assertion` (1),
`policy-session-signoff-without-assertion` (1), `junk-batch-signoff` (1).

**The decider, contributions and links.** `decider-agent` (0): an agent's
own decision. `contributions-single-model` (0): a decision on one model call,
a list of one step. `contributions-decided-output-differs` (1): the output
decided on is not the one proposed (`contributions.binding`).
`links-derived-from` (4): a record with links, whose every edge abstains;
`links-derived-from-allow-unchecked` (0) under the allowance, and
`links-derived-from-allow-unchecked-scoped` (0) under the scoped allowance of
`unsupported_link_edge`.

**Custody (Verification §4.3, Bundle §6).** `custody-ledger` (4): a custody
row an operator recorded after capture, and the envelope's mirror entry of
it. This version verifies no custody material, so `custody.ledger` abstains,
`unsupported_artifact`. `custody-row-removed` (1): the row left out and its
mirror entry kept, `mirror_entry_unexpected`.
`custody-row-and-mirror-removed` (0): both left out, `not_applicable`.

**Material this version does not read.** `witness-extension` (4),
`related-records-filled` (4), `policy-filled` (4), `unknown-member` (4),
`nonrepudiation-unread-members` (4), `subject-extra-member` (0).

**Bundles read as a whole.** `bundle-version-unknown` (2),
`bundle-version-absent` (2), `bundle-chain-profile` (2),
`bundle-unreadable` (2), and a lone surrogate in a member name a row id
would carry (Bundle §4 step 9): `member-name-lone-surrogate` (2),
`extension-name-lone-surrogate` (2), `nonrepudiation-name-lone-surrogate`
(2).

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
- `links-derived-from` exits 4 although every link holds: no edge is verified
  in this version, so every `links[<i>].edge` row abstains (Verification
  §4.11). A bundle holds no target record, so each link reports
  `targetHeld` `false`.
- `custody-row-and-mirror-removed` exits 0 although a custody row was
  removed: nothing a bundle carries commits to the ledger, so a row left out
  together with its mirror entry leaves no trace (Verification §4.3). And
  `custody-ledger` exits 4 although nothing in it is wrong: custody material
  is never passed over unexamined.

Where an expected report and the specification disagree, the specification
governs, and the corrected report names the section it follows (Specs §7).
