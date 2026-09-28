#!/usr/bin/env bash
# Mutation testing: each mutation below removes or weakens one check of the
# verifier, and the test suite must then fail. A mutation the suite does not
# notice ("survived") is a check nothing tests, and fails this script.
#
#   scripts/mutation-test.sh [-j <parallel jobs>]
#
# Every mutation runs in its own copy of the committed tree, never in the
# working tree. A mutation whose text no longer appears in its file fails the
# script too, so the list is kept in step with the code.
set -euo pipefail
cd "$(dirname "$0")/.."

jobs=4
if [[ "${1:-}" == "-j" ]]; then jobs="$2"; fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git ls-files -z | tar --null -T - -cf "$work/tree.tar"

python3 - "$work" "$jobs" <<'PY'
import concurrent.futures, os, subprocess, sys, tarfile

work, jobs = sys.argv[1], int(sys.argv[2])

# (file, text, replacement, what the mutation removes)
M = [
    ("internal/checkpoint/checkpoint.go", "[AEIMQUYcgkosw048]=)", "[A-Za-z0-9+/]=)", "canonical base64 in a body"),
    ("internal/checkpoint/checkpoint.go", "if err != nil || size > MaxSize {", "if err != nil {", "the 2^53 - 1 size bound"),
    ("internal/checkpoint/checkpoint.go", "c < 0x21 || c > 0x7E || c == '/' || c == '+'", "c < 0x21 || c > 0x7E || c == '/'", "no '+' in an origin segment"),
    ("internal/checkpoint/checkpoint.go", "bytes.IndexByte(b, 0) >= 0 || ", "bytes.IndexByte(b, 0) < -1 || ", "no 0x00 byte in a chain segment"),
    ("internal/checkpoint/checkpoint.go", "if hex.EncodeToString(b) != seg {", "if false {", "lowercase chain segment"),
    ("internal/checkpoint/checkpoint.go", " || !utf8.Valid(b) {\n\t\treturn \"\", false", " {\n\t\treturn \"\", false", "strict UTF-8 in a chain segment"),
    ("internal/checkpoint/checkpoint.go", " || ao.Prefix != lo.Prefix", "", "one domain prefix"),
    ("internal/checkpoint/checkpoint.go", "lo.Kind == KindAnchors || ", "", "a log origin that is not an anchor origin"),
    ("internal/checkpoint/checkpoint.go", "if !IsPlatformNamespace(lo.Namespace) {", "if false {", "chain_id_mismatch for a store's other source-log kind"),
    ("internal/checkpoint/checkpoint.go", "return ns == PlatformNamespace || ns == TestPlatformNamespace", "return strings.HasSuffix(ns, PlatformNamespace)", "only the platform's exact namespaces are opaque"),
    ("internal/checkpoint/checkpoint.go", "return ns == PlatformNamespace || ns == TestPlatformNamespace", "return ns == PlatformNamespace", "the test platform namespace is opaque too"),
    ("internal/checkpoint/checkpoint.go", "if !chainOK || lo.ChainID != *chainID {", "if !chainOK {", "the chain segment spells the chain id"),
    ("internal/anchor/anchor.go", "shapeOK := len(a.O) == len(members)", "shapeOK := true", "exactly the nine members"),
    ("internal/anchor/anchor.go", "if s.Kind != jsonv.Number || float64(leafIndex) != s.N-1 {", "if s.Kind != jsonv.Number {", "step 3, leafIndex = sequenceNumber - 1"),
    ("internal/anchor/anchor.go", "if !merkle.VerifyInclusion(in.Digest,", "if false && !merkle.VerifyInclusion(in.Digest,", "step 4"),
    ("internal/anchor/anchor.go", "if !merkle.VerifyInclusion(checkpoint.Digest(logBody.Raw),", "if false && !merkle.VerifyInclusion(checkpoint.Digest(logBody.Raw),", "step 5"),
    ("internal/anchor/anchor.go", "if okA && checkpoint.IsTestOrigin(anchorBody.Origin) {", "if false {", "anchorNamespace test"),
    ("internal/anchor/anchor.go", "\tcase anyFalse:\n\t\tv.Valid = boolp(false)\n", "", "a false publication makes the anchor false"),
    ("internal/anchor/anchor.go", "\tif anyFalse {\n\t\treturn finishOrigin", "\tif false {\n\t\treturn finishOrigin", "no facts from a lying artifact"),
    ("internal/anchor/anchor.go", "if e == nil || e.Kind != jsonv.Object {", "if e == nil {", "a publication that is not an object"),
    ("internal/anchor/newer.go", "if a.Size == b.Size {", "if false {", "split view"),
    ("internal/evm/evm.go", "if p.txID != nil && *p.txID != computedID {", "if false {", "keccak(raw) = transactionId"),
    ("internal/evm/evm.go", "if !bytes.Equal(tx.Data(), in.P) {", "if false {", "calldata = P"),
    ("internal/evm/evm.go", "\tif len(bySender) == 0 {\n\t\tr.txFail(ReasonSenderMismatch)", "\tif false {\n\t\tr.txFail(ReasonSenderMismatch)", "the sender is a manifest publisher"),
    ("internal/evm/evm.go", "if signed != nil && en.ChainID.Cmp(signed) == 0 {", "if true {", "the signed chain id is the entry's"),
    ("internal/evm/evm.go", "if !ok || crypto.Keccak256Hash(p.header) != p.blockHash || ", "if !ok || ", "the header hashes to blockHash"),
    ("internal/evm/evm.go", "if len(items) < headerFields {", "if len(items) < 12 {", "a header has at least fifteen fields"),
    ("internal/evm/evm.go", "if depth > maxRLPDepth {", "if depth > maxRLPDepth+1 {", "lists at most 64 deep"),
    ("internal/evm/evm.go", "\tif !rlpDepthOK(b) {\n\t\treturn nil, false\n\t}\n", "", "the depth limit on a header"),
    ("internal/evm/trie.go", "\t\tif !rlpDepthOK(node) {", "\t\tif false {", "the depth limit on a trie node"),
    ("internal/evm/evm.go", "if root.kind != rlp.String || len(root.val) != 32 {", "if root.kind != rlp.String {", "a 32-byte transactions root"),
    ("internal/evm/evm.go", " || (len(it.val) > 0 && it.val[0] == 0)", "", "no leading zero byte in a header integer"),
    ("internal/evm/evm.go", "if err != nil || !bytes.Equal(val, p.raw) {", "if err != nil || val == nil {", "the trie proof yields the raw transaction"),
    ("internal/evm/evm.go", "if !anyValid(matching, int64(h.time)) {", "if false {", "the window at the header's time"),
    ("internal/evm/evm.go", "if srcChain.Cmp(signed) != 0 {", "if false {", "the source's chain"),
    ("internal/evm/evm.go", "if p.blockNum > finalized {", "if p.blockNum > finalized+1_000_000 {", "finality"),
    ("internal/evm/evm.go", "if blk.Hash != p.blockHash {", "if false {", "the canonical block's hash"),
    ("internal/evm/evm.go", "if len(valid) == 0 {\n\t\tr.Tx.Outcome, r.Tx.Reason = report.Wrong, ReasonSenderMismatch", "if false {\n\t\tr.Tx.Outcome, r.Tx.Reason = report.Wrong, ReasonSenderMismatch", "the window at the confirmed block time"),
    ("internal/evm/evm.go", "\tcase *lk.Sender != sender:\n\t\tnotChecked(ReasonInconsistent)\n\t\treturn\n", "", "a lookup naming another sender"),
    ("internal/evm/evm.go", "if inclusion == \"\" {", "if false {", "something must place the transaction"),
    ("internal/manifest/manifest.go", "if hour > 23 || minute > 59 || sec > 59 {", "if hour > 23 || minute > 59 || sec > 60 {", "no leap second"),
    ("internal/manifest/manifest.go", "\t\t\tfrom++ // a block time is whole, so it must reach the next second\n", "", "validFrom at full precision"),
    ("internal/manifest/manifest.go", "day > daysIn(year, month)", "day > 31", "the day exists in its month"),
    ("internal/rfc3161/rfc3161.go", "!bytes.Equal(mi.HashedMessage, imprint) {", "false {", "the imprint is P, or the record's digest"),
    ("internal/rfc3161/rfc3161.go", "\tif !timestampingOnly(t.signer) {\n\t\treturn ReasonVerificationFailed\n\t}\n", "", "a timestamping-only critical EKU"),
    ("internal/rfc3161/rfc3161.go", "\tif bound == 0 {\n\t\treturn ReasonVerificationFailed\n\t}\n", "", "the signingCertificate binding"),
    ("internal/rfc3161/rfc3161.go", "if !c.BasicConstraintsValid || !c.IsCA {", "if false {", "CA intermediates"),
    ("internal/rfc3161/rfc3161.go", "if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0 {", "if false {", "keyCertSign on intermediates"),
    ("internal/rfc3161/rfc3161.go", "&& i-1 > c.MaxPathLen {", "&& false {", "pathLenConstraint"),
    ("internal/rfc3161/rfc3161.go", "if !bytes.Equal(id.certHash, hashCert(id.hash, t.signer.Raw)) {", "if false {", "the certHash names the signer"),
    ("internal/rfc3161/rfc3161.go", "(!bytes.Equal(id.issuer, t.signer.RawIssuer) || id.serial == nil || id.serial.Cmp(t.signer.SerialNumber) != 0)", "false", "the issuerSerial names the signer"),
    ("internal/rfc3161/rfc3161.go", "if n != 1 || !ok2 || !ctOID.Equal(oidTSTInfo) {", "if n != 1 || !ok2 {", "the content-type attribute names TSTInfo"),
    ("internal/rfc3161/rfc3161.go", "if n != 1 || !ok2 || !ctOID.Equal(oidTSTInfo) {", "if !ok2 && n > 0 || !ctOID.Equal(oidTSTInfo) && n > 0 {", "a content-type attribute is required"),
    ("internal/rfc3161/rfc3161.go", "|| lenient && sig == sigUnchecked) || !validAt(next, gen) {", "|| lenient && sig == sigUnchecked) {", "every certificate valid at genTime"),
    ("internal/rfc3161/rfc3161.go", "if !(sig == sigHolds || lenient && sig == sigUnchecked) || !validAt(next, gen) {", "if !validAt(next, gen) {", "each issuer's signature on a valid path"),
    ("internal/rfc3161/rfc3161.go", "\t\tif n.depth > 0 && isRoot(n.c) {\n\t\t\treturn trustReached\n", "\t\tif false {\n\t\t\treturn trustReached\n", "verification_failed when a path reaches a root"),
    ("internal/rfc3161/rfc3161.go", "if len(cands) > maxCandidates {", "if false {", "the bound on the certificates a search considers"),
    ("internal/canonical/canonical.go", "sort.SliceStable(members, func(i, j int) bool { return LessUTF16(members[i].Key, members[j].Key) })", "sort.SliceStable(members, func(i, j int) bool { return members[i].Key < members[j].Key })", "UTF-16 key order"),
    ("internal/canonical/canonical.go", "\t\tif v.Lone {\n\t\t\treturn ErrLoneSurrogate\n\t\t}\n", "", "refusing a lone surrogate"),
    ("internal/canonical/canonical.go", "case k <= n && n <= 21:", "case k <= n && n <= 22:", "the 1e21 threshold"),
    ("internal/canonical/canonical.go", "\t\t\tfv = &jsonv.Value{Kind: jsonv.Null}\n", "\t\t\tcontinue\n", "an absent hashed field reads as null"),
    ("internal/jsonv/jsonv.go", "\t\t\t\t\tout = appendWTF8(out, u)\n\t\t\t\t\tlone = true\n", "\t\t\t\t\tout = utf8.AppendRune(out, 0xFFFD)\n", "keeping a lone high surrogate"),
    ("internal/jsonv/jsonv.go", "f != math.Trunc(f) || f < 0 || f > maxSafe", "f < 0 || f > maxSafe", "an integral value"),
    ("internal/report/report.go", "\tcase Abstain:\n\t\treturn true\n", "\tcase Abstain:\n\t\treturn false\n", "exit 4 for an abstention"),
    ("internal/report/report.go", "return c.Reason != \"not_applicable\" && c.Reason != \"absent\"", "return false", "exit 4 for a present, unchecked artifact"),
    ("internal/report/report.go", "return c.Reason != \"not_applicable\" && c.Reason != \"absent\"", "return c.Reason != \"not_applicable\"", "absent is not an unchecked artifact"),
    ("internal/bundle/bundle.go", "if s, ok := member(root, \"bundleVersion\").Str(); !ok || s != Version {", "if s, ok := member(root, \"bundleVersion\").Str(); !ok && s != Version {", "the bundle version"),
    ("internal/bundle/bundle.go", "if s, ok := member(root, \"profile\").Str(); !ok || s != \"record\" {", "if false {", "the record profile"),
    ("internal/bundle/bundle.go", "\t\tif !root.Has(slot) {\n", "\t\tif !root.Has(slot) && false {\n", "every b1 slot is present"),
    ("internal/bundle/bundle.go", "cps.Kind != jsonv.Array || len(cps.A) > 2", "cps.Kind != jsonv.Array", "at most two checkpoints per log"),
    ("internal/bundle/bundle.go", "\t\t\tif m.Value.Kind != jsonv.Null {\n\t\t\t\tv.add(report.Check{ID: \"extension[\"", "\t\t\tif false {\n\t\t\t\tv.add(report.Check{ID: \"extension[\"", "an extension with a value abstains"),
    ("internal/bundle/bundle.go", "out = append(out, report.Check{ID: \"nonRepudiation.\" + m.Key,", "_ = append(out, report.Check{ID: \"nonRepudiation.\" + m.Key,", "an unread nonRepudiation member is not passed over"),
    ("internal/bundle/record.go", "|| sid != pid || string(sd) != string(ed) {", "|| sid != pid || (string(sd) != string(ed) && false) {", "the subject names the stored digest"),
    ("internal/bundle/record.go", "if !okStored || d != hex.EncodeToString(stored) {", "if !okStored || (d != hex.EncodeToString(stored) && false) {", "the recomputed digest equals the stored one"),
    ("internal/bundle/record.go", "if !ok || strings.ToLower(got) != want {", "if !ok || (strings.ToLower(got) != want && false) {", "the chain link"),
    ("internal/bundle/record.go", "if !ok1 || !ok2 || pseq != seq-1 {", "if !ok1 || !ok2 || (pseq != seq-1 && false) {", "the predecessor is the previous record"),
    ("internal/bundle/record.go", "r := rfc3161.VerifyRecordToken(tok, v.digest, v.opts.Trust)", "r := rfc3161.VerifyRecordToken(tok, make([]byte, 32), v.opts.Trust)", "the record timestamp is over the record's digest"),
    ("internal/bundle/anchoring.go", "if tx := evm.TxID(raw); tx == \"\" || tx != strings.ToLower(id) {", "if tx := evm.TxID(raw); tx == \"\" || (tx != strings.ToLower(id) && false) {", "joining by keccak(raw) = transactionId"),
    ("internal/bundle/anchoring.go", "if b, ok := checkpoint.ParseString(bodyOf(a)); ok && b.Size == size {", "if b, ok := checkpoint.ParseString(bodyOf(a)); ok && (b.Size == size || true) {", "the newer anchor checkpoint is the one at anchorSize"),
    ("internal/bundle/anchoring.go", "put(\"leafIndex\", report.N(seq-1))", "put(\"leafIndex\", report.N(seq))", "the newer anchor is over the record's own leaf"),
    ("internal/bundle/signoff.go", "\tif v.digest == nil {\n\t\treturn report.BlockedBy(IDSignoffExpectation, IDDigest)", "\tif false {\n\t\treturn report.BlockedBy(IDSignoffExpectation, IDDigest)", "the expectation is only as good as the digest"),
    ("internal/bundle/record.go", "if s, ok := member(v.env, \"envelopeVersion\").Str(); !ok || s != EnvelopeVersion {", "if false {", "the envelope version"),
    ("internal/bundle/record.go", "return report.Check{ID: IDCustody, Outcome: report.Abstain, Reason: ReasonUnsupported}", "return report.Check{ID: IDCustody, Outcome: report.NotChecked, Reason: ReasonNA}", "custody material is never passed over"),
    ("internal/bundle/record.go", "slot == nil || entries != nil", "entries != nil", "a null custody slot carries no custody material"),
    ("internal/bundle/anchoring.go", "\t\t\tif !authentic[b.Raw] {\n\t\t\t\tunauthenticated = true", "\t\t\tif !authentic[b.Raw] && false {\n\t\t\t\tunauthenticated = true", "every carried body is authenticated before a comparison"),
    ("internal/bundle/anchoring.go", "\t\tcase unauthenticated && !anchorOK:\n", "\t\tcase unauthenticated && !anchorOK && false:\n", "blocked by anchor while the record's anchor does not hold"),
    ("internal/bundle/anchoring.go", "\t\tcase len(o.authentic) >= 2:\n", "\t\tcase len(o.authentic) >= 1:\n", "no row with one authenticated body"),
    ("internal/bundle/bundle.go", "!ok || b.Origin != m.Key {", "!ok || (b.Origin != m.Key && false) {", "a checkpoint sits under its own origin"),
    ("internal/bundle/bundle.go", "!ok || b.Origin != m.Key {", "b.Origin != m.Key && ok {", "every carried checkpoint body parses"),
    ("internal/bundle/bundle.go", "\t\tif member(v.root, slot) != nil {\n", "\t\tif s := member(v.root, slot); s != nil && len(s.O) > 0 {\n", "a filled slot, even an empty object, is not passed over"),
    ("internal/bundle/bundle.go", "\t\tif !recordMembers[m.Key] {\n", "\t\tif false {\n", "a member a record bundle does not have"),
    ("internal/bundle/signoff.go", "\treturn m.get && m.presented == challenge(perRecordDomain", "\treturn m.presented == challenge(perRecordDomain", "a per-record assertion is a webauthn.get"),
    ("internal/bundle/signoff.go", "\tcase v.presentsPerRecord(m):\n", "\tcase false:\n", "a per-record signature over the record binds it"),
    ("internal/bundle/signoff.go", "if mode, _ := member(st, \"mode\").Str(); mode != \"batch\" {", "if false {", "a batch sign-off's statement is a batch statement"),
    ("internal/bundle/signoff.go", "if !ok || m.presented != challenge(statementDomain, sd) {", "if !ok || (m.presented != challenge(statementDomain, sd) && false) {", "the assertion presented the batch statement's challenge"),
    ("internal/bundle/signoff.go", "\treturn merkle.VerifyInclusion(v.digest, index, size, path, root)", "\treturn merkle.VerifyInclusion(v.digest, index, size, path, root) || true", "the batch proof puts the record under the statement's root"),
    ("internal/bundle/signoff.go", "\tif member(m.block, \"sessionSeq\") != nil {\n\t\treturn true", "\tif false {\n\t\treturn true", "a block that carries sessionSeq is a session sign-off"),
    ("internal/bundle/signoff.go", "\t\tcase m.session():\n\t\t\treturn set(report.Wrong, ReasonSessionNotExpected)\n\t\tcase m.carried() && !v.bindsBatch(m):", "\t\tcase false:\n\t\t\treturn set(report.Wrong, ReasonSessionNotExpected)\n\t\tcase m.carried() && !v.bindsBatch(m):", "a session sign-off on a record that names no session"),
    ("internal/bundle/signoff.go", "\t\tcase m.session():\n\t\t\treturn set(report.Wrong, ReasonSessionNotExpected)\n\t\tcase m.assertion == nil:", "\t\tcase false:\n\t\t\treturn set(report.Wrong, ReasonSessionNotExpected)\n\t\tcase m.assertion == nil:", "a session sign-off on a policy record"),
    ("internal/bundle/signoff.go", "\tcase \"none\":\n\t\tswitch {\n\t\tcase m.session():", "\tcase \"none\":\n\t\tswitch {\n\t\tcase m.carried() && m.session():", "a session block under null counts without an assertion"),
    ("internal/bundle/signoff.go", "\tcase \"policy\":\n\t\tswitch {\n\t\tcase m.session():", "\tcase \"policy\":\n\t\tswitch {\n\t\tcase m.carried() && m.session():", "a session block under a policy counts without an assertion"),
    ("internal/bundle/signoff.go", "\t\tcase m.carried() && !v.bindsBatch(m):\n", "\t\tcase false:\n", "a carried sign-off that binds nothing"),
    ("internal/bundle/signoff.go", "\t\tcase m.assertion == nil:\n\t\t\treturn set(report.NotChecked, ReasonSignatureMissing)", "\t\tcase false:\n\t\t\treturn set(report.NotChecked, ReasonSignatureMissing)", "a policy record without an assertion awaits its signature"),
    ("internal/bundle/signoff.go", "\tif m.block == nil {\n\t\treturn set(report.Wrong, ReasonSignoffStripped)", "\tif false {\n\t\treturn set(report.Wrong, ReasonSignoffStripped)", "a session record's block stripped"),
    ("internal/bundle/signoff.go", "!ok || sd != exp.statementDigest {", "!ok || (sd != exp.statementDigest && false) {", "the session statement's digest"),
    ("internal/bundle/signoff.go", "!ok || seq != exp.sessionSeq {", "!ok || (seq != exp.sessionSeq && false) {", "the session slot"),
    ("internal/bundle/signoff.go", "\tcase m.assertion == nil:\n\t\treturn set(report.Wrong, ReasonSignoffStripped)", "\tcase false:\n\t\treturn set(report.Wrong, ReasonSignoffStripped)", "a session record's assertion stripped"),
    ("internal/bundle/signoff.go", "\tcase m.presented != challenge(statementDomain, exp.statementDigest):\n", "\tcase false:\n", "the session assertion presented its statement's challenge"),
    ("internal/bundle/signoff.go", "\t\t\tif _, ok := m.Value.Uint53(); !ok {\n\t\t\t\treturn \"\", false", "\t\t\tif false {\n\t\t\t\treturn \"\", false", "a statement's numbers are safe integers"),
    ("internal/bundle/signoff.go", "if m.KeyLone || !printableASCII(m.Key) {", "if m.KeyLone {", "a statement's keys are printable ASCII"),
    ("internal/bundle/signoff.go", "return expectation{form: \"policy\"}, ok && isLowerHex64(pd)", "return expectation{form: \"policy\"}, ok && (isLowerHex64(pd) || true)", "the policy digest's grammar"),
    ("internal/bundle/signoff.go", "!isLowerHex64(sd) || seq == 0 {", "!isLowerHex64(sd) {", "a session slot is at least 1"),
    ("internal/bundle/signoff.go", "\tcase exp.Outcome == report.Wrong:\n", "\tcase false:\n", "signoff.key is blocked when the expectation fails"),
    ("internal/bundle/signoff.go", "\tcase exp.Reason == ReasonSignatureMissing && m.assertion == nil:\n", "\tcase false:\n", "signoff.key reads signature_missing"),
    ("internal/bundle/signoff.go", "\tcase member(v.root, \"credentials\") != nil:\n", "\tcase false:\n", "a filled credentials slot abstains"),
    ("internal/anchor/anchor.go", "Reason: ReasonLeafIndexMismatch, Facts: checkedFact(true)}", "Reason: ReasonLeafIndexMismatch}", "a failing step 3 states leafIndexChecked"),
    ("internal/evm/trie.go", "\t\tif !bytes.Equal(crypto.Keccak256(node), want) {", "\t\tif !bytes.Equal(crypto.Keccak256(node), want) && false {", "each proof node is the one its parent references"),
    ("internal/evm/trie.go", "\t\t\tif used != len(nodes) {", "\t\t\tif false {", "every proof node is used"),
    ("internal/rfc3161/rfc3161.go", "\tif skiSigner(s) {", "\tif false {", "a signer named by subjectKeyIdentifier is missing_dependency"),
    ("internal/rfc3161/rfc3161.go", "if !ok || len(fields) <= spkiAt || !keyNotImplemented(fields[spkiAt].FullBytes) {", "if true {", "a key on a curve this build does not implement is not a decoding failure"),
    ("internal/rfc3161/rfc3161.go", "\tcase asn1.TagSequence, asn1.TagNull:\n\t\treturn true", "\tcase asn1.TagSequence, asn1.TagNull:\n\t\treturn false", "explicit and implicit curve parameters are not decoding failures"),
    ("internal/rfc3161/rfc3161.go", "\t\t\tif curve.Equal(c) {", "\t\t\tif curve.Equal(c) && false {", "a point off a curve this build implements does not decode"),
    ("internal/rfc3161/rfc3161.go", "\t\tif readable {\n\t\t\tstock = append(stock, e.FullBytes)", "\t\tif readable || true {\n\t\t\tstock = append(stock, e.FullBytes)", "a certificate no step needs is not handed to the CMS library"),
    ("internal/rfc3161/rfc3161.go", "\tif !KeyImplemented(t.signer) {\n\t\treturn false\n\t}\n", "", "a signer key this build does not implement is missing_dependency"),
    ("internal/rfc3161/rfc3161.go", "\t\tif t.signerInf.SignatureAlgorithm.Algorithm.Equal(oid) {", "\t\tif t.signerInf.SignatureAlgorithm.Algorithm.Equal(oid) || true {", "a CMS signature algorithm the library does not map is missing_dependency"),
    ("internal/rfc3161/rfc3161.go", "errors.As(err, &insecure) ||", "(errors.As(err, &insecure) && false) ||", "an MD5 signature is missing_dependency"),
    ("internal/rfc3161/rfc3161.go", "\t\t\tif isMissingDependency(err) {\n\t\t\t\tv = sigUnchecked", "\t\t\tif false {\n\t\t\t\tv = sigUnchecked", "a signature this build cannot check is not a failed one"),
    ("internal/rfc3161/rfc3161.go", "\t\tif unchecked {", "\t\tif unchecked && false {", "a path valid but for signatures this build cannot check is missing_dependency"),
    ("internal/rfc3161/rfc3161.go", "if r := search(false); r != \"\" {", "if r := search(true); r != \"\" {", "a valid path decides before an unchecked one"),
    ("internal/rfc3161/rfc3161.go", "\tcase trustUnchecked:\n", "\tcase \"never\":\n", "trust not-checked, missing_dependency"),
    ("internal/rfc3161/rfc3161.go", "\tfor _, a := range c.Subject.Names {\n\t\tif a.Type.Equal(oidCommonName) {\n\t\t\ts, _ := a.Value.(string)\n\t\t\treturn s\n\t\t}\n\t}\n", "\tif c.Subject.CommonName != \"\" {\n\t\treturn c.Subject.CommonName\n\t}\n", "authority is the first common name, an empty one kept"),
    ("internal/rfc3161/rfc3161.go", "\t\t}\n\t}\n\treturn \"\"\n}", "\t\t}\n\t}\n\treturn c.Subject.String()\n}", "authority is empty without a common name"),
    ("internal/cli/cli.go", "\t\t\tif !rfc3161.KeyImplemented(c) {", "\t\t\tif false {", "a supplied certificate whose key this build does not implement is refused"),
    ("internal/bundle/bundle.go", "\t\tif loneKey(obj) {", "\t\tif loneKey(obj) && false {", "a lone surrogate in a name a row id would carry"),
    ("internal/cli/cli.go", "\t\t\tif hasVal {\n\t\t\t\treturn nil, fmt.Errorf(\"%s takes no value", "\t\t\tif false {\n\t\t\t\treturn nil, fmt.Errorf(\"%s takes no value", "a switch takes no value"),
    ("internal/report/report.go", "\tif !r.Readable() {\n\t\treturn ExitBundle\n\t}\n", "", "exit 2"),
]

with tarfile.open(os.path.join(work, "tree.tar")) as t:
    base = os.path.join(work, "base")
    t.extractall(base, filter="data")

def run(i):
    f, old, new, what = M[i]
    d = os.path.join(work, f"m{i}")
    subprocess.run(["cp", "-r", base, d], check=True)
    p = os.path.join(d, f)
    src = open(p).read()
    if old not in src:
        return i, "stale", ""
    open(p, "w").write(src.replace(old, new, 1))
    # errors="replace": a failing test may print bytes that are not UTF-8.
    r = subprocess.run(["go", "test", "-count=1", "./..."], cwd=d, capture_output=True, text=True,
                       errors="replace", env={**os.environ, "CGO_ENABLED": "0"})
    if "build failed" in r.stdout + r.stderr or "[setup failed]" in r.stdout:
        return i, "nobuild", (r.stdout + r.stderr)[-400:]
    return i, ("killed" if r.returncode != 0 else "survived"), ""

bad = 0
with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
    for i, status, detail in sorted(ex.map(run, range(len(M)))):
        f, _, _, what = M[i]
        print(f"{status:9} {f}: {what}")
        if status != "killed":
            bad += 1
            if detail:
                print("          " + detail.replace("\n", "\n          "))
print(f"{len(M) - bad} of {len(M)} mutations killed")
sys.exit(1 if bad else 0)
PY
