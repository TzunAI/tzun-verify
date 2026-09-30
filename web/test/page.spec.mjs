// The browser page, driven as an auditor would drive it, on cases of the b1
// conformance corpus (testdata/vectors/bundle-b1). The verifier's own
// conformance is held to account by the Go tests, under Go and under
// js/wasm; these hold the page to it: the report the page gets is the one
// the corpus states, every row is shown with its outcome, reason and
// sections, nothing is sent anywhere offline, and the node the auditor
// names is the only host asked, through the browser's fetch.

import { test, expect } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { citeURL, citesFor, SPEC_DOCS } from '../spec.js';

const here = dirname(fileURLToPath(import.meta.url));
const web = join(here, '..');
const repo = join(web, '..');
const corpus = join(repo, 'testdata', 'vectors', 'bundle-b1');
const shots = process.env.SCREENSHOT_DIR || join(web, 'test-results', 'screenshots');
mkdirSync(shots, { recursive: true });

const LABELS = { 'checked-correct': 'OK', 'checked-wrong': 'FAIL', 'not-checked': 'NOT CHECKED', abstain: 'ABSTAIN' };

function corpusCase(name) {
  const dir = join(corpus, name);
  const json = (f) => JSON.parse(readFileSync(join(dir, f), 'utf8'));
  return {
    name,
    bundle: join(dir, 'bundle.json'),
    inputs: json('inputs.json'),
    expected: json('expected-report.json'),
    exit: Number(readFileSync(join(dir, 'expected-exit'), 'utf8').trim()),
  };
}

// canonical writes a JSON value the way the corpus runner writes the
// manifest file (sorted members, no space), so the report names it by the
// digest the corpus expects.
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}

function manifestFile(c) {
  return { name: 'publishers.json', mimeType: 'application/json', buffer: Buffer.from(canonical(c.inputs.publisherManifest)) };
}

function rootsFile(c) {
  return { name: 'roots.pem', mimeType: 'application/x-pem-file', buffer: Buffer.from(c.inputs.trustAnchorsPem.map((p) => `${p}\n`).join('')) };
}

function withoutCheckedAt(report) {
  const { checkedAt, ...rest } = report;
  expect(checkedAt).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  return rest;
}

// open loads the page and waits for the verifier. It records every request
// and every console error, warning and page error.
async function open(page) {
  const seen = { requests: [], problems: [] };
  page.on('request', (r) => seen.requests.push({ url: r.url(), method: r.method() }));
  page.on('console', (m) => {
    if (m.type() === 'error' || m.type() === 'warning') seen.problems.push(m.text());
  });
  page.on('pageerror', (e) => seen.problems.push(e.message));
  await page.goto('/');
  await expect(page.locator('#verifier-status')).toHaveText(/^Verifier ready · /, { timeout: 60_000 });
  return seen;
}

async function chooseBundle(page, c) {
  await page.locator('#bundle-file').setInputFiles(c.bundle);
  await expect(page.locator('#bundle-facts')).toContainText('bundle.json');
}

async function runVerification(page) {
  await expect(page.locator('#verify')).toBeEnabled();
  await page.locator('#verify').click();
  await expect(page.locator('#exit-code')).toBeVisible({ timeout: 60_000 });
}

// reportOf is the JSON report the page offers for download: the verifier's
// standard output, byte for byte.
async function reportOf(page) {
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('a[download="tzun-verify-report.json"]').click(),
  ]);
  return JSON.parse(readFileSync(await download.path(), 'utf8'));
}

// expectRows holds the table to the report: one row per check, in order,
// each with its outcome, reason, facts and the sections it cites.
async function expectRows(page, checks) {
  const rows = page.locator('#rows tbody tr');
  await expect(rows).toHaveCount(checks.length);
  const shown = await rows.evaluateAll((trs) => trs.map((tr) => ({
    id: tr.dataset.id,
    badge: tr.querySelector('.badge').textContent,
    reason: tr.querySelector('td.reason > code')?.textContent ?? null,
    facts: Array.from(tr.querySelectorAll('.fact'), (f) => f.textContent),
    links: Array.from(tr.querySelectorAll('td.spec a'), (a) => a.href),
  })));
  checks.forEach((c, i) => {
    const s = shown[i];
    expect(s.id).toBe(c.id);
    expect(s.badge).toBe(LABELS[c.outcome]);
    expect(s.reason).toBe(c.reason ?? null);
    const facts = c.facts ? Object.keys(c.facts).sort().map((k) => `${k}=${typeof c.facts[k] === 'string' ? c.facts[k] : JSON.stringify(c.facts[k])}`) : [];
    expect(s.facts).toEqual(facts);
    const links = citesFor(c.id, c.reason).map(citeURL);
    expect(links.length, `${c.id} cites no section`).toBeGreaterThan(0);
    expect(s.links).toEqual(links);
  });
}

async function screenshots(page, which) {
  await page.setViewportSize({ width: 1280, height: 900 });
  // From the top, so that the sticky header is drawn where it belongs.
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: join(shots, `wasm-desktop-${which}.png`), fullPage: true });
  await page.setViewportSize({ width: 375, height: 812 });
  await page.evaluate(() => window.scrollTo(0, 0));
  // Nothing wider than the screen: no sideways scrolling at 375 px.
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  await page.screenshot({ path: join(shots, `wasm-mobile-${which}.png`), fullPage: true });
  await page.setViewportSize({ width: 1280, height: 900 });
}

function sameOrigin(seen, baseURL) {
  const origin = new URL(baseURL).origin;
  return seen.requests.filter((r) => new URL(r.url).origin !== origin);
}

test('offline, a pass: anchored-offline-allow-unchecked gives the corpus report and exit 0', async ({ page, baseURL }) => {
  const c = corpusCase('anchored-offline-allow-unchecked');
  expect(c.exit).toBe(0);
  const seen = await open(page);
  await chooseBundle(page, c);
  await page.locator('input[name="manifest"][value="none"]').check();
  await page.locator('#allow-unchecked').check();
  await expect(page.locator('#network-notice')).toContainText('This verification makes no network request');
  await expect(page.locator('#command')).toHaveText('tzun-verify --no-publishers --allow-unchecked bundle.json');

  const before = seen.requests.length;
  await runVerification(page);
  expect(seen.requests.slice(before), 'requests while verifying offline').toEqual([]);

  await expect(page.locator('#exit-code')).toHaveText('exit 0');
  await expect(page.locator('#exit-meaning')).toHaveText('Every row whose artifact is in the bundle is correct, and every requirement is met.');
  await expect(page.locator('#result')).toContainText('The on-chain lookup was skipped');
  await expect(page.locator('#not-anchored')).toContainText('Exit 0 does not mean anchored');
  const report = await reportOf(page);
  expect(withoutCheckedAt(report)).toEqual(c.expected);
  await expectRows(page, c.expected.checks);
  await expect(page.locator('#counts')).toHaveText('13 correct · 0 wrong · 9 not checked · 0 abstained');
  await expect(page.locator('#text-report')).toContainText('exit 0');

  expect(sameOrigin(seen, baseURL), 'requests to another origin').toEqual([]);
  await screenshots(page, 'pass');
  expect(seen.problems).toEqual([]);
});

test('offline, a failure: tampered-payload fails record.digest, exit 1', async ({ page, baseURL }) => {
  const c = corpusCase('tampered-payload');
  expect(c.exit).toBe(1);
  const seen = await open(page);
  await chooseBundle(page, c);
  await page.locator('#manifest-file').setInputFiles(manifestFile(c));
  await expect(page.locator('input[name="manifest"][value="file"]')).toBeChecked();
  await page.locator('#tsa-roots').setInputFiles(rootsFile(c));
  await expect(page.locator('#tsa-list')).toContainText('roots.pem');

  const before = seen.requests.length;
  await runVerification(page);
  expect(seen.requests.slice(before), 'requests while verifying offline').toEqual([]);

  await expect(page.locator('#exit-code')).toHaveText('exit 1');
  await expect(page.locator('#exit-meaning')).toHaveText('At least one row is wrong.');
  // Offline, every row is the corpus's: each one that needs the node is
  // blocked by the failed digest first. Only the inputs differ: no header
  // source.
  const report = withoutCheckedAt(await reportOf(page));
  expect(report.checks).toEqual(c.expected.checks);
  expect(report.summary).toEqual(c.expected.summary);
  expect(report.inputs).toEqual({ ...c.expected.inputs, evmHeaderSources: [] });
  await expectRows(page, c.expected.checks);
  const digest = page.locator('#rows tr[data-id="record.digest"]');
  await expect(digest.locator('.badge')).toHaveText('FAIL');
  await expect(digest.locator('td.reason')).toContainText('digest_mismatch');
  await expect(digest.locator('td.spec a').first()).toHaveAttribute('href', 'https://spec.tzun.ai/verification/1.0/#s4-3');

  expect(sameOrigin(seen, baseURL), 'requests to another origin').toEqual([]);
  await screenshots(page, 'fail');
  expect(seen.problems).toEqual([]);
});

const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'content-type', 'Access-Control-Allow-Methods': 'POST' };

// mockNode answers JSON-RPC at every address under endpoint from a corpus
// case's header source, and returns the methods it is asked.
async function mockNode(page, c, endpoint) {
  const [[chain, source]] = Object.entries(c.inputs.headerSources);
  const hex = (n) => `0x${n.toString(16)}`;
  const block = (n) => {
    const b = source.blocks.find((x) => x.number === n);
    return b ? { number: hex(b.number), hash: b.hash, timestamp: hex(b.timestamp) } : null;
  };
  const methods = [];
  await page.route(`${endpoint}**`, async (route) => {
    if (route.request().method() === 'OPTIONS') return route.fulfill({ status: 204, headers: CORS });
    const call = route.request().postDataJSON();
    methods.push(call.method);
    let result = null;
    if (call.method === 'eth_chainId') result = hex(Number(chain.split(':')[1]));
    else if (call.method === 'eth_getBlockByNumber') result = call.params[0] === 'finalized' ? block(source.finalizedBlockNumber) ?? { number: hex(source.finalizedBlockNumber), hash: `0x${'00'.repeat(32)}`, timestamp: '0x0' } : block(Number(call.params[0]));
    return route.fulfill({ status: 200, headers: CORS, contentType: 'application/json', body: JSON.stringify({ jsonrpc: '2.0', id: call.id, result }) });
  });
  return methods;
}

// chooseRPC makes the choices of an RPC verification of a corpus case:
// its manifest and roots, and the endpoint, with no transaction lookup,
// since the corpus's header sources look none up.
async function chooseRPC(page, c, rpc) {
  await chooseBundle(page, c);
  await page.locator('#manifest-file').setInputFiles(manifestFile(c));
  await page.locator('#tsa-roots').setInputFiles(rootsFile(c));
  await page.locator('input[name="network"][value="rpc"]').check();
  await page.locator('#rpc').fill(rpc);
  await page.locator('details.more summary').first().click();
  await page.locator('#no-tx-lookup').check();
}

test('the node the auditor names, through fetch: anchored-with-newer, exit 0', async ({ page }) => {
  const c = corpusCase('anchored-with-newer');
  const [[chain]] = Object.entries(c.inputs.headerSources);
  const endpoint = 'https://rpc.invalid/';
  // A JSON-RPC node that answers from the case's header source.
  const methods = await mockNode(page, c, endpoint);

  const seen = await open(page);
  await chooseRPC(page, c, `${chain}=${endpoint}`);

  // The endpoint is stated before any request is made.
  await expect(page.locator('#rpc-shown')).toHaveText(endpoint);
  await expect(page.locator('#verify')).toHaveText('Verify and ask rpc.invalid');
  await expect(page.locator('#command')).toHaveText(`tzun-verify --publishers publishers.json --tsa-roots roots.pem --evm-rpc ${chain}=${endpoint} --no-tx-lookup bundle.json`);
  expect(seen.requests.filter((r) => r.url.startsWith(endpoint))).toEqual([]);
  await page.evaluate(() => window.scrollTo(0, 0));
  const box = await page.locator('section[aria-labelledby="h-network"]').boundingBox();
  await page.screenshot({ path: join(shots, 'wasm-desktop-rpc-notice.png'), fullPage: true, clip: { x: box.x - 16, y: box.y - 16, width: box.width + 32, height: box.height + 32 } });

  await runVerification(page);
  await expect(page.locator('#exit-code')).toHaveText(`exit ${c.exit}`);
  const report = await reportOf(page);
  expect(withoutCheckedAt(report)).toEqual(c.expected);
  await expectRows(page, c.expected.checks);
  expect(methods.length).toBeGreaterThan(0);
  expect(new Set(methods)).toEqual(new Set(['eth_chainId', 'eth_getBlockByNumber']));
  const hosts = new Set(seen.requests.map((r) => new URL(r.url).origin));
  hosts.delete(new URL(page.url()).origin);
  expect([...hosts]).toEqual(['https://rpc.invalid']);
  expect(seen.problems).toEqual([]);
});

test('an input the verifier cannot use is refused: exit 64 and its message', async ({ page }) => {
  const c = corpusCase('anchored-offline');
  const seen = await open(page);
  await chooseBundle(page, c);
  await page.locator('#manifest-file').setInputFiles({ name: 'broken.json', mimeType: 'application/json', buffer: Buffer.from('{publishers') });
  await runVerification(page);
  await expect(page.locator('#exit-code')).toHaveText('exit 64');
  // The message names the file by its own name, as the command line does.
  await expect(page.locator('#result .stderr')).toHaveText('tzun-verify: --publishers broken.json: not JSON: jsonv: offset 1: expected a string key\n');
  await expect(page.locator('#result .cites a')).toHaveAttribute('href', 'https://spec.tzun.ai/verification/1.0/#s6-6');
  expect(seen.problems).toEqual([]);
});

test('the command line writes a file name that starts with - as ./-name', async ({ page }) => {
  const c = corpusCase('anchored-offline');
  await open(page);
  await page.locator('#bundle-file').setInputFiles({ name: '-h', mimeType: 'application/json', buffer: readFileSync(c.bundle) });
  await expect(page.locator('#bundle-facts')).toContainText('-h');
  await expect(page.locator('#command')).toHaveText('tzun-verify ./-h');
  await runVerification(page);
  await expect(page.locator('#exit-code')).toHaveText(/^exit [0-4]$/);
  await expect(page.locator('#ran')).toHaveText('tzun-verify ./-h');
});

test('keyboard only: Tab passes the endpoint field and reaches Verify with Offline still chosen', async ({ page }) => {
  const c = corpusCase('anchored-offline');
  await open(page);
  await chooseBundle(page, c);
  const offline = page.locator('input[name="network"][value="offline"]');
  await offline.focus();
  const trail = [];
  for (let i = 0; i < 12 && trail.at(-1) !== 'verify'; i++) {
    await page.keyboard.press('Tab');
    trail.push(await page.evaluate(() => document.activeElement.id));
  }
  expect(trail).toContain('rpc');
  expect(trail.at(-1)).toBe('verify');
  await expect(offline).toBeChecked();
  await expect(page.locator('#verify')).toHaveText('Verify offline');
  await page.keyboard.press('Enter');
  await expect(page.locator('#exit-code')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#result')).toContainText('The on-chain lookup was skipped');

  // Typing an endpoint is what chooses it.
  await page.locator('#rpc').focus();
  await expect(offline).toBeChecked();
  await page.keyboard.type('https://rpc.invalid/');
  await expect(page.locator('input[name="network"][value="rpc"]')).toBeChecked();
  await expect(page.locator('#verify')).toHaveText('Verify and ask rpc.invalid');
});

test('the file chosen last is the one verified, however long the first takes to read', async ({ page }) => {
  const c = corpusCase('anchored-offline');
  // Reading slow.json takes two seconds, as a large bundle can.
  await page.addInitScript(() => {
    const arrayBuffer = Blob.prototype.arrayBuffer;
    Blob.prototype.arrayBuffer = async function () {
      const b = await arrayBuffer.call(this);
      if (this.name === 'slow.json') await new Promise((r) => setTimeout(r, 2000));
      return b;
    };
  });
  await open(page);
  const bytes = readFileSync(c.bundle);
  await page.locator('#bundle-file').setInputFiles({ name: 'slow.json', mimeType: 'application/json', buffer: bytes });
  await expect(page.locator('#why')).toHaveText('Reading slow.json…');
  await expect(page.locator('#verify')).toBeDisabled();
  await page.locator('#bundle-file').setInputFiles(c.bundle);
  await expect(page.locator('#bundle-facts')).toContainText('bundle.json');
  await page.waitForTimeout(2500);
  await expect(page.locator('#drop-title')).toHaveText('bundle.json');
  await expect(page.locator('#bundle-facts')).toContainText('bundle.json');
  await expect(page.locator('#command')).toHaveText('tzun-verify bundle.json');
  await expect(page.locator('#verify')).toBeEnabled();
});

test('a large bundle is flagged when it is chosen', async ({ page }, testInfo) => {
  const big = testInfo.outputPath('big.json');
  mkdirSync(dirname(big), { recursive: true });
  writeFileSync(big, Buffer.alloc(33 * 1024 * 1024, 0x20));
  await open(page);
  await page.locator('#bundle-file').setInputFiles(big);
  await expect(page.locator('#bundle-facts')).toContainText('big.json');
  await expect(page.locator('#bundle-large')).toBeVisible();
  await chooseBundle(page, corpusCase('anchored-offline'));
  await expect(page.locator('#bundle-large')).toBeHidden();
});

test('an endpoint the page cannot reach as written is refused before anything is sent', async ({ page }) => {
  const c = corpusCase('anchored-with-newer');
  const seen = await open(page);
  await chooseBundle(page, c);
  await page.locator('input[name="network"][value="rpc"]').check();
  for (const [rpc, why] of [
    ['https://user:s3cret@rpc.invalid/', /user name or password/],
    ['http://node.lan:8545/', /only a node on this machine.*Use https for node\.lan:8545/],
    ['http://[::1]:8545/', /not \[::1\]/],
  ]) {
    await page.locator('#rpc').fill(rpc);
    await expect(page.locator('#verify')).toBeDisabled();
    await expect(page.locator('#why')).toHaveText(why);
    await expect(page.locator('#network-notice')).toHaveText(why);
    await expect(page.locator('#network-notice')).not.toContainText('s3cret');
  }
  for (const [rpc, host] of [['http://127.0.0.1:8545/', '127.0.0.1:8545'], ['http://localhost:8545', 'localhost:8545'], ['https://node.lan/', 'node.lan']]) {
    await page.locator('#rpc').fill(rpc);
    await expect(page.locator('#verify')).toHaveText(`Verify and ask ${host}`);
    await expect(page.locator('#verify')).toBeEnabled();
  }
  expect(seen.requests.filter((r) => new URL(r.url).origin !== new URL(page.url()).origin)).toEqual([]);
});

test('a redirect from the endpoint is refused, not followed', async ({ page }) => {
  const c = corpusCase('anchored-with-newer');
  const [[chain]] = Object.entries(c.inputs.headerSources);
  await page.route('https://rpc.invalid/**', (route) => route.request().method() === 'OPTIONS'
    ? route.fulfill({ status: 204, headers: CORS })
    : route.fulfill({ status: 307, headers: { ...CORS, Location: 'https://elsewhere.invalid/' } }));
  const elsewhere = await mockNode(page, c, 'https://elsewhere.invalid/');
  const seen = await open(page);
  await chooseRPC(page, c, `${chain}=https://rpc.invalid/`);
  await runVerification(page);
  expect(elsewhere).toEqual([]);
  expect(seen.requests.filter((r) => r.url.startsWith('https://elsewhere.invalid'))).toEqual([]);
  await expect(page.locator('#exit-code')).toHaveText('exit 4');
  await expect(page.locator('#rows tr[data-id="anchor.evm.canonical[0]"] td.reason > code')).toHaveText('evm_header_source_unavailable');
  await expect(page.locator('#node-unavailable')).toContainText('redirected elsewhere');
});

test('the report view names the endpoint by its origin, never its path or query', async ({ page }) => {
  const c = corpusCase('anchored-with-newer');
  const [[chain]] = Object.entries(c.inputs.headerSources);
  const methods = await mockNode(page, c, 'https://rpc.invalid/');
  await open(page);
  await chooseRPC(page, c, `${chain}=https://rpc.invalid/v1/k3y0123456789?apikey=s3cret`);
  // Before Verify the page states the whole URL it will ask.
  await expect(page.locator('#rpc-shown')).toHaveText('https://rpc.invalid/v1/k3y0123456789?apikey=s3cret');
  await runVerification(page);
  await expect(page.locator('#exit-code')).toHaveText(`exit ${c.exit}`);
  expect(methods.length).toBeGreaterThan(0);
  const result = await page.locator('#result').innerText();
  expect(result).not.toContain('s3cret');
  expect(result).not.toContain('k3y0123456789');
  await expect(page.locator('#result')).toContainText('asked the node at https://rpc.invalid and no other host');
  await expect(page.locator('#ran')).toHaveText(`tzun-verify --publishers publishers.json --tsa-roots roots.pem --evm-rpc '${chain}=https://rpc.invalid/…' --no-tx-lookup bundle.json`);
});

test('when the verifier stops, the page says so and verifies nothing more until reloaded', async ({ page }) => {
  // Keep the page's Go runtime within reach of the test.
  await page.addInitScript(() => {
    let Go;
    Object.defineProperty(globalThis, 'Go', {
      configurable: true,
      get: () => Go,
      set: (v) => {
        Go = class extends v {
          constructor() {
            super();
            globalThis.testGo = this;
          }
        };
      },
    });
  });
  const c = corpusCase('anchored-with-newer');
  const [[chain]] = Object.entries(c.inputs.headerSources);
  // A node that never answers, so that the verification is still running.
  await page.route('https://rpc.invalid/**', () => new Promise(() => {}));
  await open(page);
  await chooseRPC(page, c, `${chain}=https://rpc.invalid/`);
  await page.locator('#verify').click();
  await expect(page.locator('#verify')).toHaveText('Verifying…');
  // The Go runtime ends as it does when it runs out of memory: it writes
  // to standard error, then exits.
  await page.evaluate(() => {
    globalThis.fs.writeSync(2, new TextEncoder().encode('fatal error: out of memory\n'));
    globalThis.testGo.exited = true;
    globalThis.testGo._resolveExitPromise();
  });
  await expect(page.locator('#exit-code')).toHaveText('no exit code');
  await expect(page.locator('#result-title')).toHaveText('The verifier stopped');
  await expect(page.locator('#result .stderr')).toHaveText('fatal error: out of memory');
  // No exit code, so no section of the exit codes.
  await expect(page.locator('#result a.cite')).toHaveCount(0);
  await expect(page.locator('#verifier-status')).toHaveText('The verifier stopped · reload the page');
  await expect(page.locator('#verify')).toBeDisabled();
  await expect(page.locator('#why')).toHaveText('The verifier stopped. Reload the page to verify again.');
});

test('long file names wrap, at 375 px and at 320 px', async ({ page }) => {
  await open(page);
  // Two roots with long names that have nowhere to break, measured as soon
  // as they are chosen (the page names them while it reads them) and once
  // they are listed.
  for (const width of [375, 320]) {
    await page.setViewportSize({ width, height: 812 });
    const pem = Buffer.from('-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n');
    await page.locator('#tsa-roots').setInputFiles([
      { name: `${'r'.repeat(60)}.pem`, mimeType: 'application/x-pem-file', buffer: pem },
      { name: `${'s'.repeat(60)}.pem`, mimeType: 'application/x-pem-file', buffer: pem },
    ]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await expect(page.locator('#tsa-list li')).toHaveCount(2);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  }
});

test('the local server answers a malformed address with 400 and keeps serving', async ({ request }) => {
  expect((await request.get('/%E0%A4%A')).status()).toBe(400);
  expect((await request.get('/')).status()).toBe(200);
});

test('the page states what the README and its headers state', () => {
  // The specification documents: the README's table.
  const readme = readFileSync(join(repo, 'README.md'), 'utf8');
  const docs = {};
  for (const m of readme.matchAll(/^\| (\w+) \|[^\n]*\| (https:\/\/spec\.tzun\.ai\/[^ |]*) \|$/gm)) docs[m[1]] = m[2];
  expect(docs).toEqual(SPEC_DOCS);

  // The CSP of the meta tag is the one _headers sends, less frame-ancestors,
  // which a meta tag cannot carry.
  const html = readFileSync(join(web, 'index.html'), 'utf8');
  const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)[1];
  const header = /^\s+Content-Security-Policy: (.+)$/m.exec(readFileSync(join(web, '_headers'), 'utf8'))[1];
  expect(`${meta}; frame-ancestors 'none'`).toBe(header);
  expect(html).not.toMatch(/<script(?![^>]*\bsrc=)/);
  expect(html).not.toMatch(/\sstyle=/);

  // Every row id of every corpus report cites at least one section.
  const index = JSON.parse(readFileSync(join(corpus, 'index.json'), 'utf8'));
  for (const { name } of index.cases) {
    for (const check of corpusCase(name).expected.checks) {
      const cites = citesFor(check.id, check.reason);
      expect(cites.length, `${name}: ${check.id}`).toBeGreaterThan(0);
      for (const cite of cites) expect(citeURL(cite), cite).toMatch(/^https:\/\/spec\.tzun\.ai\/[a-z0-9./]*#s\d+(-\d+)*$/);
    }
  }
});
