// The browser page, driven as an auditor would drive it, on cases of the b1
// conformance corpus (testdata/vectors/bundle-b1). The verifier's own
// conformance is held to account by the Go tests, under Go and under
// js/wasm; these hold the page to it: the report the page gets is the one
// the corpus states, every row is shown with its outcome, reason and
// sections, nothing is sent anywhere offline, and the node the auditor
// names is the only host asked, through the browser's fetch.

import { test, expect } from '@playwright/test';
import { mkdirSync, readFileSync } from 'node:fs';
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

test('the node the auditor names, through fetch: anchored-with-newer, exit 0', async ({ page }) => {
  const c = corpusCase('anchored-with-newer');
  const [[chain, source]] = Object.entries(c.inputs.headerSources);
  const endpoint = 'https://rpc.invalid/';
  const hex = (n) => `0x${n.toString(16)}`;
  const block = (n) => {
    const b = source.blocks.find((x) => x.number === n);
    return b ? { number: hex(b.number), hash: b.hash, timestamp: hex(b.timestamp) } : null;
  };
  // A JSON-RPC node that answers from the case's header source.
  const methods = [];
  await page.route(`${endpoint}**`, async (route) => {
    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'content-type', 'Access-Control-Allow-Methods': 'POST' };
    if (route.request().method() === 'OPTIONS') return route.fulfill({ status: 204, headers: cors });
    const call = route.request().postDataJSON();
    methods.push(call.method);
    let result = null;
    if (call.method === 'eth_chainId') result = hex(Number(chain.split(':')[1]));
    else if (call.method === 'eth_getBlockByNumber') result = call.params[0] === 'finalized' ? block(source.finalizedBlockNumber) ?? { number: hex(source.finalizedBlockNumber), hash: `0x${'00'.repeat(32)}`, timestamp: '0x0' } : block(Number(call.params[0]));
    return route.fulfill({ status: 200, headers: cors, contentType: 'application/json', body: JSON.stringify({ jsonrpc: '2.0', id: call.id, result }) });
  });

  const seen = await open(page);
  await chooseBundle(page, c);
  await page.locator('#manifest-file').setInputFiles(manifestFile(c));
  await page.locator('#tsa-roots').setInputFiles(rootsFile(c));
  await page.locator('input[name="network"][value="rpc"]').check();
  await page.locator('#rpc').fill(`${chain}=${endpoint}`);
  await page.locator('details.more summary').first().click();
  // The corpus's header source looks no transaction up; neither may the node.
  await page.locator('#no-tx-lookup').check();

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
  await expect(page.locator('#result .stderr')).toContainText('broken.json: not JSON');
  expect(seen.problems).toEqual([]);
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
