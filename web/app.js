// The browser page of tzun-verify.
//
// It turns what the auditor chooses into the flags they would type, hands
// those flags and the bytes of every file they name to the verifier compiled
// to WebAssembly (cmd/tzun-verify-wasm), and shows the report it returns.
// The verification, the report and the exit code are the command's own. No
// file leaves the browser. The only requests after the page has loaded are
// the ones the verifier makes, through fetch, to the endpoint the auditor
// names, and the page states that endpoint before any is made.

import { citeURL, citesFor, PAGE_CITES } from './spec.js';

const $ = (id) => document.getElementById(id);
const decoder = new TextDecoder();

// el builds an element: attributes, then children, each a node or text.
// Text is only ever set as text, never parsed as markup.
function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    e.append(c instanceof Node ? c : String(c));
  }
  return e;
}

function citeLinks(cites) {
  const out = [];
  for (const c of cites) {
    const url = citeURL(c);
    if (!url) continue;
    if (out.length) out.push(' · ');
    out.push(el('a', { href: url, class: 'cite', target: '_blank', rel: 'noopener noreferrer' }, c));
  }
  return out;
}

async function sha256(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('');
}

function size(n) {
  if (n < 1024) return `${n} bytes`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// quote writes a word as a POSIX shell reads it.
function quote(s) {
  return /^[A-Za-z0-9@%+=:,./_-]+$/.test(s) ? s : `'${s.replaceAll("'", "'\\''")}'`;
}

// fileWord writes a file name as a word of the command: a name that starts
// with "-" is written ./-name, so that the command reads it as a file, not
// as a flag.
function fileWord(name) {
  return quote(name.startsWith('-') ? `./${name}` : name);
}

async function readFile(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  return { name: file.name, bytes, sha: await sha256(bytes) };
}

// The auditor's choices.
const state = {
  api: null,
  // The Go runtime, and a promise that settles once it has exited.
  go: null,
  exited: null,
  stopped: false,
  bundle: null,
  manifest: null,
  roots: [],
  inters: [],
  running: false,
  // The object URLs of the last report's downloads, released on the next.
  urls: [],
};

// Each input's reads are numbered, and only the latest is taken: a large
// file still being read never replaces one chosen after it. Verify waits
// while any is being read.
const reads = { bundle: 0, manifest: 0, roots: 0, inters: 0 };
const reading = new Map();
const readErrors = {};

// A bundle this large may need more memory than WebAssembly gives the
// verifier; the page says so when one is chosen.
const LARGE_BUNDLE = 32 * 1024 * 1024;

// The Go runtime writes what it says on dying (fatal error: out of memory,
// an unrecovered panic) to standard error, which wasm_exec.js hands to
// console.log, followed by its goroutines. The page keeps the start of it,
// to show if the verifier stops; the console has the rest.
let runtimeStderr = '';
if (globalThis.fs && typeof globalThis.fs.writeSync === 'function') {
  const writeSync = globalThis.fs.writeSync.bind(globalThis.fs);
  globalThis.fs.writeSync = (fd, buf) => {
    if (fd === 2 && runtimeStderr.length < 4096) runtimeStderr += new TextDecoder().decode(buf);
    return writeSync(fd, buf);
  };
}

// ---- The verifier ----

async function loadVerifier() {
  const status = $('verifier-status');
  try {
    if (typeof Go !== 'function') throw new Error('wasm_exec.js did not load');
    const res = await fetch('tzun-verify.wasm');
    if (!res.ok) throw new Error(`tzun-verify.wasm: HTTP ${res.status}`);
    const bytes = await res.arrayBuffer();
    const go = new Go();
    const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
    state.go = go;
    // run settles when the Go program exits, which it only does when it
    // dies: out of memory, most likely.
    state.exited = go.run(instance).then(verifierStopped, verifierStopped);
    const api = globalThis.tzunVerify;
    if (!api || typeof api.run !== 'function' || go.exited) throw new Error('the verifier did not start');
    state.api = api;
    const wasmSha = await sha256(bytes);
    if (state.stopped) return;
    status.textContent = `Verifier ready · ${api.version}`;
    status.classList.add('ready');
    $('build-version').textContent = `tzun-verify ${api.version}`;
    $('build-sha').replaceChildren(', ', el('span', { class: 'nowrap' }, `${size(bytes.byteLength)}, SHA-256 `), el('code', { class: 'hash', title: wasmSha }, wasmSha));
    $('pinned-sha').textContent = api.pinnedManifestSHA256;
    try {
      const pinned = JSON.parse(decoder.decode(api.pinnedManifest));
      const pubs = pinned && pinned.publishers;
      $('pinned-empty').hidden = !(pubs && typeof pubs === 'object' && Object.keys(pubs).length === 0);
    } catch {
      $('pinned-empty').hidden = true;
    }
  } catch (err) {
    status.textContent = `The verifier could not load: ${err.message}`;
    status.classList.add('failed');
  }
  update();
}

// verifierStopped is called once the Go program has exited. Nothing can
// run in it again: the page says so, and verifies nothing more until it
// is reloaded.
function verifierStopped() {
  state.api = null;
  state.stopped = true;
  const status = $('verifier-status');
  status.textContent = 'The verifier stopped · reload the page';
  status.classList.remove('ready');
  status.classList.add('failed');
  update();
}

// ---- Inputs ----

// The hosts an http (not https) endpoint may name: the ones the page's
// Content-Security-Policy lets it reach, a node on this machine.
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1']);

// endpoint reads an --evm-rpc value as the page can use it: an https URL,
// or http to a node on this machine, with no user name or password, which
// the browser's fetch refuses to send. shown is the URL as the report view
// writes it: without its path and query, which can carry a key.
function endpoint(spec) {
  let chain = null;
  let url = spec;
  const m = /^(eip155:[0-9]+)=(.*)$/s.exec(spec);
  if (m) [, chain, url] = m;
  let u;
  try {
    u = new URL(url);
  } catch {
    return { error: 'That is not a URL.' };
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return { error: 'The endpoint must be an http or https URL.' };
  if (u.username || u.password) {
    return { error: 'This page cannot use a URL with a user name or password in it: the browser refuses to send them. Use an endpoint that takes its key in the path, or the command.' };
  }
  if (u.protocol === 'http:' && u.hostname === '[::1]') {
    return { error: 'Over plain http this page reaches a node on this machine at localhost or 127.0.0.1, not [::1], which a Content-Security-Policy cannot name.' };
  }
  if (u.protocol === 'http:' && !LOCAL_HOSTS.has(u.hostname)) {
    return { error: `Over plain http this page reaches only a node on this machine, at localhost or 127.0.0.1. Use https for ${u.host}.` };
  }
  const bare = u.pathname === '/' && !u.search && !u.hash;
  return { chain, url, host: u.host, origin: u.origin, shown: bare ? url : `${u.origin}/…` };
}

// plan is the verification the choices describe: the flags, the files
// they name, the command a shell would run, and what still stops it.
function plan() {
  const form = $('form');
  const args = [];
  // shown is the command as the auditor would type it; ran is the same
  // command as the report view writes it, the endpoint without its path
  // and query.
  const shown = ['tzun-verify'];
  const ran = ['tzun-verify'];
  const files = {};
  // names maps the name each file is handed to the verifier by back to the
  // file's own name, for the messages the page shows.
  const names = [];
  let missing = null;
  const flag = (name) => {
    args.push(name);
    shown.push(name);
    ran.push(name);
  };
  const value = (name, v, display = v) => {
    args.push(name, v);
    shown.push(name, quote(v));
    ran.push(name, quote(display));
  };
  // file names a file by its role, so that two files of one name never meet.
  const file = (name, role, f, i = 0) => {
    const key = `${role}/${i}/${f.name}`;
    files[key] = f.bytes;
    names.push([key, f.name]);
    args.push(name, key);
    shown.push(name, fileWord(f.name));
    ran.push(name, fileWord(f.name));
  };

  switch (form.elements.manifest.value) {
    case 'file':
      if (state.manifest) file('--publishers', 'publishers', state.manifest);
      else missing = 'Choose a manifest file, or another manifest.';
      break;
    case 'none':
      flag('--no-publishers');
      break;
  }
  state.roots.forEach((f, i) => file('--tsa-roots', 'tsa-roots', f, i));
  state.inters.forEach((f, i) => file('--tsa-intermediates', 'tsa-intermediates', f, i));

  let rpc = null;
  if (form.elements.network.value === 'rpc') {
    const spec = $('rpc').value.trim();
    if (!spec) {
      missing ??= 'Name the endpoint, or verify offline.';
    } else {
      rpc = endpoint(spec);
      if (rpc.error) missing ??= rpc.error;
      value('--evm-rpc', spec, rpc.error ? spec : `${rpc.chain ? `${rpc.chain}=` : ''}${rpc.shown}`);
    }
    const conf = $('confirmations').value.trim();
    if (conf) value('--confirmations', conf);
    if ($('accept-non-final').checked) flag('--accept-non-final');
    if ($('no-tx-lookup').checked) flag('--no-tx-lookup');
    const timeout = $('timeout').value.trim();
    if (timeout) value('--timeout', timeout);
  }

  for (const id of $('require').value.split(',')) {
    if (id.trim()) value('--require', id.trim());
  }
  if ($('allow-unchecked').checked) flag('--allow-unchecked');

  if (state.bundle) {
    const key = `bundle/0/${state.bundle.name}`;
    files[key] = state.bundle.bytes;
    names.push([key, state.bundle.name]);
    args.push(key);
    shown.push(fileWord(state.bundle.name));
    ran.push(fileWord(state.bundle.name));
  } else {
    shown.push('<bundle.json>');
    ran.push('<bundle.json>');
    missing = 'Choose a bundle first.';
  }
  const failed = Object.values(readErrors).find(Boolean);
  if (failed) missing = failed;
  if (reading.size) missing = `Reading ${[...reading.values()].join(', ')}…`;
  names.sort((a, b) => b[0].length - a[0].length);
  return { args, files, names, command: shown.join(' '), ranCommand: ran.join(' '), rpc, missing };
}

function networkNotice(p) {
  const box = $('network-notice');
  if ($('form').elements.network.value !== 'rpc') {
    box.className = 'notice offline';
    box.replaceChildren(
      el('p', {}, el('strong', {}, 'Offline. '), 'This verification makes no network request. It checks everything but the on-chain lookup: ',
        el('code', {}, 'anchor.evm.canonical'), ' reads NOT CHECKED (', el('code', {}, 'input_not_supplied:evm_header_source'),
        ', unless a row before it blocks it), and the anchor rows that need it are not decided.'),
      el('p', { class: 'small' }, 'A signed transaction, a block header and a trie proof in the bundle show that the publisher key signed a transaction carrying the published value, not that it was mined, when, or on which network. Only your own node can confirm that.'),
    );
    return;
  }
  if (!p.rpc || p.rpc.error) {
    box.className = 'notice pending';
    box.replaceChildren(el('p', {}, p.rpc ? p.rpc.error : 'Name the endpoint. Nothing is sent until you press Verify.'));
    return;
  }
  const noLookup = $('no-tx-lookup').checked;
  const lookups = noLookup ? [] : [', and ', el('code', {}, 'eth_getTransactionByHash'), ' for each publication\'s transaction'];
  box.className = 'notice rpc';
  box.replaceChildren(
    el('p', {}, 'When you press Verify, this page sends JSON-RPC requests to'),
    el('p', { class: 'endpoint' }, el('code', { id: 'rpc-shown' }, p.rpc.url)),
    el('p', {}, 'and to no other host: ', el('code', {}, 'eth_chainId'), ', ', el('code', {}, 'eth_getBlockByNumber'),
      ' for the finalized block and for each block a publication names', ...lookups,
      `. The node sees those block numbers${noLookup ? '' : ' and transaction ids'}, and your IP address; it never sees the bundle. It is trusted for canonicality and finality, and for nothing else. The report names it by its chain and finality, never by its URL.`),
    el('p', { class: 'small' }, 'A redirect to another address is refused, not followed. The node must accept requests from this page (CORS): a node that does not reads as unavailable. A local geth node needs ',
      el('code', {}, '--http.corsdomain'), ' naming this page\'s origin.'),
  );
}

function update() {
  const p = plan();
  $('command').textContent = p.command;
  networkNotice(p);
  const button = $('verify');
  const ready = state.api && !p.missing && !state.running;
  button.disabled = !ready;
  if (state.running) button.textContent = 'Verifying…';
  else if (p.rpc && !p.rpc.error) button.textContent = `Verify and ask ${p.rpc.host}`;
  else button.textContent = 'Verify offline';
  if (state.stopped) $('why').textContent = 'The verifier stopped. Reload the page to verify again.';
  else $('why').textContent = !state.api ? 'Waiting for the verifier to load.' : p.missing || '';
}

function facts(dl, f) {
  dl.hidden = false;
  dl.replaceChildren(
    el('dt', {}, 'File'), el('dd', {}, f.name),
    el('dt', {}, 'Size'), el('dd', {}, size(f.bytes.byteLength)),
    el('dt', {}, 'SHA-256'), el('dd', {}, el('code', { class: 'hash' }, f.sha)),
  );
}

// readLatest reads files for an input. It returns their contents, or null
// when a later choice on the same input has replaced them or one could not
// be read.
async function readLatest(which, files) {
  const seq = ++reads[which];
  if (files.length) reading.set(which, files.map((f) => f.name).join(', '));
  else reading.delete(which);
  readErrors[which] = null;
  update();
  let got = null;
  let error = null;
  try {
    got = await Promise.all(files.map(readFile));
  } catch (err) {
    error = `${files.map((f) => f.name).join(', ')} could not be read: ${err.message}`;
  }
  if (seq !== reads[which]) return null;
  reading.delete(which);
  readErrors[which] = error;
  return got;
}

async function takeBundle(file) {
  if (!file) return;
  const got = await readLatest('bundle', [file]);
  if (got) {
    [state.bundle] = got;
    $('drop-title').textContent = file.name;
    $('drop-note').textContent = 'Drop another bundle, or choose one, to replace it. Read in this browser; never uploaded.';
    $('drop').classList.add('chosen');
    facts($('bundle-facts'), state.bundle);
    $('bundle-large').hidden = state.bundle.bytes.byteLength <= LARGE_BUNDLE;
  }
  update();
}

async function takeManifest(file) {
  const got = await readLatest('manifest', file ? [file] : []);
  if (got) {
    state.manifest = got[0] ?? null;
    if (state.manifest) {
      $('form').elements.manifest.value = 'file';
      facts($('manifest-facts'), state.manifest);
    } else {
      $('manifest-facts').hidden = true;
    }
  }
  update();
}

async function takeCerts(input, which) {
  const got = await readLatest(which, Array.from(input.files));
  if (!got) {
    update();
    return;
  }
  state[which] = got;
  const list = $('tsa-list');
  const items = [];
  for (const [label, fs] of [['Root', state.roots], ['Intermediate', state.inters]]) {
    for (const f of fs) {
      items.push(el('li', {}, el('span', { class: 'k' }, label), ' ', f.name, ' ', el('code', { class: 'hash', title: f.sha }, `sha256 ${f.sha.slice(0, 12)}…`)));
    }
  }
  list.replaceChildren(...items);
  list.hidden = items.length === 0;
  update();
}

// ---- The report ----

const OUTCOMES = {
  'checked-correct': { label: 'OK', cls: 'ok', meaning: 'Decided, and it holds.' },
  'checked-wrong': { label: 'FAIL', cls: 'fail', meaning: 'Decided, and it fails.' },
  'not-checked': { label: 'NOT CHECKED', cls: 'nc', meaning: 'This verifier could not decide it; the reason says why.' },
  abstain: { label: 'ABSTAIN', cls: 'abstain', meaning: 'The artifact names a construction or version this verifier does not implement.' },
};

// The exit codes of Verification §6.6, and 64 for an invocation error.
const EXITS = {
  0: ['Nothing wrong', 'Every row whose artifact is in the bundle is correct, and every requirement is met.'],
  1: ['Something is wrong', 'At least one row is wrong.'],
  2: ['The bundle could not be read', 'The bundle row is not correct: the bundle was abstained on as a whole, is malformed_bundle, or met bundle_verifier_error; or the report could not be written.'],
  3: ['A requirement is not met', 'A row your regime requires is not correct, or a required rung is not met.'],
  4: ['Not everything present was checked', 'Something present in the bundle was abstained on or not checked, and unchecked rows were not allowed.'],
  64: ['The inputs were refused', 'An error in the invocation: an input that cannot be read or used. Nothing was verified.'],
};

// breakable is text with a line-break opportunity after each . : / [ _ and
// =, so that a long row id or reason wraps at its parts, not mid-word.
function breakable(text) {
  const out = [];
  for (const part of String(text).split(/(?<=[.:/[_=])/)) {
    if (out.length) out.push(el('wbr'));
    out.push(part);
  }
  return out;
}

function factText(v) {
  return typeof v === 'string' ? v : JSON.stringify(v);
}

function short(h) {
  return typeof h === 'string' && h.length > 12 ? `${h.slice(0, 4)}…${h.slice(-4)}` : String(h);
}

function download(name, type, bytes) {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  state.urls.push(url);
  return el('a', { href: url, download: name, class: 'button' }, `Download ${name}`);
}

function renderRows(checks, offline) {
  const body = checks.map((c) => {
    const o = OUTCOMES[c.outcome] || { label: c.outcome, cls: 'nc', meaning: '' };
    const factList = c.facts
      ? Object.keys(c.facts).sort().map((k) => el('span', { class: 'fact' }, breakable(`${k}=${factText(c.facts[k])}`)))
      : [];
    const notes = [];
    if (offline && c.reason === 'input_not_supplied:evm_header_source') notes.push(el('span', { class: 'row-note' }, 'skipped: offline'));
    return el('tr', { class: `row ${o.cls}`, 'data-id': c.id },
      el('td', { class: 'outcome', 'data-label': 'Outcome' }, el('span', { class: `badge ${o.cls}`, title: o.meaning }, o.label)),
      el('td', { class: 'id', 'data-label': 'Row' }, el('code', {}, breakable(c.id))),
      el('td', { class: 'reason', 'data-label': 'Reason' },
        c.reason ? el('code', {}, breakable(c.reason)) : el('span', { class: 'none' }, '—'),
        notes,
        factList.length ? el('span', { class: 'facts-line' }, factList) : null),
      el('td', { class: 'spec', 'data-label': 'Specification' }, citeLinks(citesFor(c.id, c.reason))),
    );
  });
  return el('table', { class: 'rows', id: 'rows' },
    el('caption', { class: 'visually-hidden' }, 'Every row of the report, in report order'),
    el('thead', {}, el('tr', {},
      el('th', { scope: 'col', class: 'col-outcome' }, 'Outcome'),
      el('th', { scope: 'col', class: 'col-id' }, 'Row'),
      el('th', { scope: 'col', class: 'col-reason' }, 'Reason and facts'),
      el('th', { scope: 'col', class: 'col-spec' }, 'Specification'))),
    el('tbody', {}, body),
  );
}

// ranLine is the command the run was, as the report view writes it.
function ranLine(run, attrs = {}) {
  return el('p', { class: 'ran' }, el('span', { class: 'k' }, 'Ran '), el('code', attrs, run.command),
    run.redacted ? el('span', { class: 'small' }, ' (the endpoint without its path and query, which can carry a key)') : null);
}

// renderError shows a run that made no report: the command refused its
// inputs (exit 64), or the verifier stopped and gave no exit code at all.
function renderError(out, run) {
  const known = Object.hasOwn(EXITS, out.exit);
  let meaning = EXITS[out.exit];
  if (!known && out.stopped) {
    meaning = ['The verifier stopped', 'It stopped before it finished, and gave no exit code. WebAssembly gives it at most 4 GB of memory, and a browser may give it less; a bundle that needs more stops it. The command-line tzun-verify has no such limit. Reload the page to verify again.'];
  } else if (!known) {
    meaning = ['The verifier failed', 'It gave no exit code and no report.'];
  }
  let stderr = decoder.decode(out.stderr);
  for (const [key, name] of run.names) stderr = stderr.replaceAll(key, name);
  return [
    el('div', { class: `verdict ${known ? `exit-${out.exit}` : 'exit-none'}` },
      el('p', { class: 'exit-code', id: 'exit-code' }, known ? `exit ${out.exit}` : 'no exit code'),
      el('div', {},
        el('h2', { id: 'result-title' }, meaning[0]),
        el('p', { id: 'exit-meaning' }, meaning[1]),
        known ? el('p', { class: 'cites' }, citeLinks([PAGE_CITES.exit])) : null)),
    el('pre', { class: 'stderr' }, stderr || 'No report was made.'),
    ranLine(run),
  ];
}

function renderReport(out, report, run) {
  const exit = out.exit;
  const meaning = EXITS[exit] || [`Exit ${exit}`, ''];
  const s = report.summary || {};
  const counts = s.outcomes || {};
  const anchorRow = report.checks.find((c) => c.id === 'anchor');
  const unchecked = report.checks.filter((c) => c.outcome !== 'checked-correct' && c.outcome !== 'checked-wrong');

  const notes = [];
  if (run.offline) {
    notes.push(el('p', { class: 'note' }, el('strong', {}, 'Offline. '), 'The on-chain lookup was skipped and no network request was made. Rows that need your node read NOT CHECKED; everything else was checked.'));
  } else {
    notes.push(el('p', { class: 'note' }, el('strong', {}, 'Header source. '), 'This verification asked the node at ', el('code', {}, run.rpc.origin), ' and no other host.'));
    if (report.checks.some((c) => c.reason === 'evm_header_source_unavailable')) {
      notes.push(el('p', { class: 'note warn', id: 'node-unavailable' }, el('strong', {}, 'The node could not be asked. '),
        'If the command reaches it, it may not accept requests from this page (CORS), or it redirected elsewhere, which this page refuses. The browser\'s console says which.'));
    }
  }
  if (exit === 0 && anchorRow && anchorRow.outcome !== 'checked-correct') {
    notes.push(el('p', { class: 'note warn', id: 'not-anchored' }, el('strong', {}, 'Exit 0 does not mean anchored. '),
      `The anchor row reads ${OUTCOMES[anchorRow.outcome]?.label ?? anchorRow.outcome}${anchorRow.reason ? `, ${anchorRow.reason}` : ''}. When your regime needs an anchor, require `, el('code', {}, 'anchor'), ' in step 5.'));
  }
  if (exit === 0 && run.allowUnchecked && unchecked.length) {
    notes.push(el('p', { class: 'note' }, el('strong', {}, 'Unchecked rows allowed. '), `${unchecked.length} rows were not checked or abstained on; they are all listed below.`));
  }

  const existed = s.existedBy ? `${s.existedBy.at} (${s.existedBy.source}, ${s.existedBy.check})` : 'not proven by this verification';
  let anchor = 'no anchor decided';
  if (anchorRow) {
    if (anchorRow.outcome === 'checked-correct') {
      anchor = ['holds', s.anchorNetwork, s.anchorNamespace, s.anchorOriginAuthenticated ? 'publisher authenticated' : 'publisher not authenticated'].filter(Boolean).join(' · ');
    } else if (anchorRow.outcome === 'checked-wrong') {
      anchor = `FAILED: ${anchorRow.reason}`;
    } else {
      anchor = `not decided: ${anchorRow.reason}${s.anchorNamespace ? ` · ${s.anchorNamespace}` : ''}`;
    }
  }
  const subject = report.subject || {};
  const manifest = report.inputs && report.inputs.publisherManifest;
  const summary = el('dl', { class: 'summary' },
    el('dt', {}, 'Record'), el('dd', {}, subject.evidenceId ? el('code', {}, subject.evidenceId) : '—'),
    el('dt', {}, 'Digest'), el('dd', {}, subject.canonicalDigest ? el('code', { class: 'hash', title: subject.canonicalDigest }, subject.canonicalDigest) : '—'),
    el('dt', {}, 'Rows'), el('dd', { id: 'counts' }, `${counts['checked-correct'] ?? 0} correct · ${counts['checked-wrong'] ?? 0} wrong · ${counts['not-checked'] ?? 0} not checked · ${counts.abstain ?? 0} abstained`),
    el('dt', {}, 'Existed by'), el('dd', {}, existed, ' ', citeLinks([PAGE_CITES.existedBy])),
    el('dt', {}, 'Anchor'), el('dd', {}, anchor),
    el('dt', {}, 'Manifest'), el('dd', {}, manifest ? el('code', { class: 'hash', title: manifest }, `sha256 ${short(manifest)}`) : 'none'),
  );

  const legend = el('ul', { class: 'legend' }, Object.values(OUTCOMES).map((o) => el('li', {}, el('span', { class: `badge ${o.cls}` }, o.label), ' ', o.meaning)));

  const text = decoder.decode(out.text);
  return [
    el('div', { class: `verdict exit-${exit}` },
      el('p', { class: 'exit-code', id: 'exit-code' }, `exit ${exit}`),
      el('div', {},
        el('h2', { id: 'result-title' }, meaning[0]),
        el('p', { id: 'exit-meaning' }, meaning[1]),
        el('p', { class: 'small' }, 'Precedence: 2, then 1, then 3, then 4, then 0. There is no overall VALID: the exit code turns the outcomes into one number, and your regime decides what must be checked. ', citeLinks([PAGE_CITES.exit])))),
    summary,
    ...notes,
    el('h3', {}, 'Rows ', el('span', { class: 'cites' }, citeLinks([PAGE_CITES.outcomes]))),
    legend,
    renderRows(report.checks, run.offline),
    el('div', { class: 'downloads' },
      download('tzun-verify-report.json', 'application/json', out.stdout),
      download('tzun-verify-report.txt', 'text/plain', out.text)),
    el('details', { class: 'more' }, el('summary', {}, 'The text report, as the command prints it'), el('pre', { class: 'text-report', id: 'text-report' }, text)),
    ranLine(run, { id: 'ran' }),
  ];
}

async function verify(event) {
  event.preventDefault();
  const p = plan();
  if (!state.api || p.missing || state.running) return;
  const run = {
    command: p.ranCommand,
    redacted: p.ranCommand !== p.command,
    names: p.names,
    offline: !p.rpc,
    rpc: p.rpc,
    allowUnchecked: $('allow-unchecked').checked,
  };
  state.running = true;
  update();
  const result = $('result');
  // A run that has not settled when the Go program exits never will.
  const stopped = () => ({
    exit: null,
    stopped: true,
    stdout: new Uint8Array(),
    text: new Uint8Array(),
    // What the runtime said, up to the goroutines it lists.
    stderr: new TextEncoder().encode(runtimeStderr.split(/\n\s*\n/)[0].trim() || 'The Go runtime exited.'),
  });
  let out;
  try {
    out = await Promise.race([state.api.run(['--json', ...p.args], p.files), state.exited.then(stopped)]);
  } catch (err) {
    out = state.go.exited ? stopped() : { exit: null, stdout: new Uint8Array(), text: new Uint8Array(), stderr: new TextEncoder().encode(String(err && err.message || err)) };
  }
  state.running = false;
  update();
  let report = null;
  if (out.stdout.byteLength) {
    try {
      report = JSON.parse(decoder.decode(out.stdout));
    } catch {
      report = null;
    }
  }
  for (const url of state.urls.splice(0)) URL.revokeObjectURL(url);
  result.replaceChildren(...(report ? renderReport(out, report, run) : renderError(out, run)));
  result.dataset.exit = out.exit == null ? 'none' : String(out.exit);
  result.hidden = false;
  result.focus({ preventScroll: true });
  result.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
}

// ---- Wiring ----

function wire() {
  for (const p of document.querySelectorAll('[data-cites]')) {
    p.replaceChildren(...citeLinks(p.dataset.cites.split('|')));
  }
  const form = $('form');
  form.addEventListener('submit', verify);
  form.addEventListener('input', update);
  form.addEventListener('change', update);
  $('bundle-file').addEventListener('change', (e) => takeBundle(e.target.files[0]));
  $('manifest-file').addEventListener('change', (e) => takeManifest(e.target.files[0]));
  $('tsa-roots').addEventListener('change', (e) => takeCerts(e.target, 'roots'));
  $('tsa-inters').addEventListener('change', (e) => takeCerts(e.target, 'inters'));
  // Typing an endpoint chooses it. Focus alone does not, so that Tab
  // passes through the field on its way to Verify with Offline still
  // chosen. The form's own input listener then updates the page.
  $('rpc').addEventListener('input', () => {
    if ($('rpc').value.trim()) form.elements.network.value = 'rpc';
  });

  // A file dropped anywhere but the drop zone would make the browser open
  // it and leave the page.
  const drop = $('drop');
  for (const type of ['dragover', 'drop']) {
    window.addEventListener(type, (e) => {
      if (!drop.contains(e.target)) e.preventDefault();
    });
  }
  drop.addEventListener('dragover', (e) => {
    e.preventDefault();
    drop.classList.add('over');
  });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    takeBundle(e.dataTransfer.files[0]);
  });
  update();
}

wire();
loadVerifier();
