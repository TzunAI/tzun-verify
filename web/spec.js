// Where the page links into the specification.
//
// A citation is "<Name> §<n>" (Specs §8.3): "Record §3.2" is section 3.2 of
// the Record document at the version this build implements, at
// https://spec.tzun.ai/record/1.0/#s3-2 (Specs §8.2). SPEC_DOCS is the
// README's Specification table; the page's tests hold the two to each other.

export const SPEC_DOCS = {
  Specs: 'https://spec.tzun.ai/',
  Record: 'https://spec.tzun.ai/record/1.0/',
  Verification: 'https://spec.tzun.ai/verification/1.0/',
  Bundle: 'https://spec.tzun.ai/bundle/b1/',
  Anchor: 'https://spec.tzun.ai/anchor/1/',
  Tree: 'https://spec.tzun.ai/tree/2/',
  Vectors: 'https://spec.tzun.ai/vectors/1.0/',
};

const CITE = /^([A-Z][a-z]+) §(\d+(?:\.\d+)*)$/;

// citeURL is the address of a citation, or null for one that names no
// document of SPEC_DOCS.
export function citeURL(cite) {
  const m = CITE.exec(cite);
  if (!m || !Object.hasOwn(SPEC_DOCS, m[1])) return null;
  return `${SPEC_DOCS[m[1]]}#s${m[2].replaceAll('.', '-')}`;
}

// The sections each row cites, by row id, as the README's "What it checks"
// table and the code cite them: the section that defines the row's check
// first.
const ROWS = [
  [/^bundle$/, ['Bundle §4', 'Bundle §3.1']],
  [/^subject$/, ['Bundle §5.1']],
  [/^record\.digest$/, ['Verification §4.3', 'Record §4']],
  [/^record\.chainLink$/, ['Verification §4.3']],
  [/^custody\.ledger$/, ['Verification §4.3']],
  [/^ts\.record\.token$/, ['Anchor §10.5']],
  [/^ts\.record\.trust$/, ['Anchor §10.5', 'Verification §4.4']],
  [/^signoff\.expectation$/, ['Verification §5', 'Record §6.2']],
  [/^signoff\.key$/, ['Verification §4.5']],
  [/^anchor$/, ['Anchor §10.6', 'Anchor §10.7']],
  [/^anchor\.(spec|checkpoint|origin|leafIndex|inclusion|anchorInclusion)$/, ['Anchor §10.3', 'Anchor §10.7']],
  [/^anchor\.publication\[\d+\]$/, ['Anchor §10.3', 'Anchor §10.7']],
  [/^anchor\.evm\.(tx|canonical)\[\d+\]$/, ['Anchor §10.4']],
  [/^anchor\.tsa\.(token|trust)\[\d+\]$/, ['Anchor §10.5']],
  [/^anchor\.newer$/, ['Bundle §7.5']],
  [/^anchor\.consistency\[.+\]$/, ['Anchor §10.8', 'Bundle §7.6']],
  [/^anchor\.pending$/, ['Bundle §7.7']],
  [/^extension\[.+\]$/, ['Bundle §9']],
  [/^(relatedRecords|policy)$/, ['Bundle §8']],
  [/^member\[.+\]$/, ['Bundle §3.3']],
  [/^(ts\.assertion\.token|nonRepudiation\..+)$/, ['Verification §4.7']],
];

// citesFor returns the sections a row cites: its check's sections, and
// Verification §2.2 when it is blocked by another row.
export function citesFor(id, reason) {
  const out = [];
  for (const [rx, cites] of ROWS) {
    if (rx.test(id)) {
      out.push(...cites);
      break;
    }
  }
  if (typeof reason === 'string' && reason.startsWith('blocked_by:')) out.push('Verification §2.2');
  return out;
}

// The sections the rest of the page cites.
export const PAGE_CITES = {
  outcomes: 'Verification §2.1',
  exit: 'Verification §6.6',
  report: 'Verification §6',
  inputs: 'Verification §6.2',
  existedBy: 'Verification §6.4',
  regime: 'Verification §3.2',
  trustInputs: 'Verification §3.1',
  manifest: 'Anchor §9',
  timestamps: 'Anchor §10.5',
  headerSource: 'Anchor §10.4',
  bundle: 'Bundle §4',
};
