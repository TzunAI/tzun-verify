#!/usr/bin/env node
'use strict';
// Tests the npm packages on this machine against the release binary for it:
//
//   node npm/test.js <packages-dir> <dist-dir> [<corpus-dir>]
//
// <packages-dir> is npm/stage.js's output (the tarballs and
// publish-order.txt), <dist-dir> the release files it was made from, and
// <corpus-dir> the b1 conformance corpus (default testdata/vectors/bundle-b1).
//
// It installs tzun-verify and this platform's package from their tarballs
// into an empty project with npm --offline and an empty npm cache, so the
// install can fetch nothing, and checks that no other platform's package came
// with them. Then every corpus case, its inputs.json turned into flags as
// internal/corpus does, runs twice, as `npx tzun-verify` and as the release
// binary, with --json and without: standard output (the JSON report's
// checkedAt aside), standard error and the exit code must be the same, and
// the JSON report must be the case's expected-report.json with its
// expected-exit. So must a few runs that are not reports (--version, --help,
// usage errors, paths with spaces and quotes), a global install, and the
// launcher's own errors when the platform package is missing or of another
// version.
//
// Last, the tarballs are served from a registry on 127.0.0.1 that holds
// nothing else, and npm installs from it as it would from npmjs.com: a bare
// `npx tzun-verify` in an empty directory, and `npm install tzun-verify`
// once for each platform (npm's --os and --cpu), which must bring exactly
// that platform's package, whose binary the launcher must pick.

const assert = require('assert');
const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { npmCli, readSums, executableFormat, OS, ARCH } = require('./stage.js');
const { PLATFORMS, binaryPath } = require('./tzun-verify/bin/tzun-verify.js');

const failures = [];
let compared = 0;

function check(what, ok, detail) {
  if (!ok) {
    failures.push(what);
    process.stdout.write('FAIL ' + what + (detail ? '\n' + detail : '') + '\n');
  }
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function spawn(cmd, args, opts) {
  const r = childProcess.spawnSync(cmd, args, Object.assign({ encoding: 'utf8', maxBuffer: 64 << 20 }, opts));
  if (r.error) throw r.error;
  return r;
}

// npmEnv keeps npm from reading any cache or configuration but the given
// cache, and from talking to anyone but the registry given.
function npmEnv(cache, registry) {
  return Object.assign({}, process.env, {
    npm_config_cache: cache,
    npm_config_offline: registry ? 'false' : 'true',
    npm_config_registry: registry || 'https://registry.npmjs.org/',
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_update_notifier: 'false',
    npm_config_userconfig: path.join(cache, 'npmrc'),
  });
}

function npm(args, cwd, cache, registry) {
  const [node, cli] = npmCli('npm-cli.js');
  const r = spawn(node, [cli].concat(args), { cwd: cwd, env: npmEnv(cache, registry) });
  if (r.status !== 0) {
    throw new Error('npm ' + args.join(' ') + ' exited ' + r.status + ':\n' + r.stdout + r.stderr);
  }
  return r;
}

// canonical serializes JSON with sorted keys, so two reports compare by
// content.
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

function withoutCheckedAt(report) {
  const copy = Object.assign({}, report);
  delete copy.checkedAt;
  return copy;
}

const CHECKED_AT = /"checkedAt":\s*"[^"]*"/;

function firstDifference(a, b) {
  const x = a.split('\n');
  const y = b.split('\n');
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if (x[i] !== y[i]) return '  line ' + (i + 1) + ':\n  npx:     ' + JSON.stringify(x[i]) + '\n  release: ' + JSON.stringify(y[i]);
  }
  return '';
}

// same runs args through npx and through the release binary and requires
// the same output and exit code.
function same(what, ctx, args, json) {
  const [node, npx] = ctx.npx;
  const viaNpm = spawn(node, [npx, '--offline', '--yes=false', 'tzun-verify'].concat(args), { cwd: ctx.app, env: npmEnv(ctx.cache) });
  const direct = spawn(ctx.ref, args, { cwd: ctx.app });
  let a = viaNpm.stdout;
  let b = direct.stdout;
  if (json) {
    check(what + ': the npx report has a checkedAt', CHECKED_AT.test(a));
    a = a.replace(CHECKED_AT, '"checkedAt":""');
    b = b.replace(CHECKED_AT, '"checkedAt":""');
  }
  compared++;
  check(what + ': exit ' + viaNpm.status + ' via npx, ' + direct.status + ' from the release binary', viaNpm.status === direct.status);
  check(what + ': standard output differs', a === b, firstDifference(a, b));
  check(what + ': standard error differs', viaNpm.stderr === direct.stderr, firstDifference(viaNpm.stderr, direct.stderr));
  return viaNpm;
}

// flags turns a case's inputs.json into tzun-verify's flags, as
// internal/corpus/bundle_test.go does.
function flags(inputs, dir) {
  const known = ['publisherManifest', 'headerSources', 'trustAnchorsPem', 'regime'];
  for (const k of Object.keys(inputs)) assert(known.includes(k), 'inputs.json: unknown member ' + k);
  const out = [];
  if (inputs.publisherManifest === null) {
    out.push('--no-publishers');
  } else {
    const f = path.join(dir, 'publishers.json');
    fs.writeFileSync(f, JSON.stringify(inputs.publisherManifest));
    out.push('--publishers', f);
  }
  Object.keys(inputs.headerSources).forEach((chain, i) => {
    const f = path.join(dir, 'headers-' + i + '.json');
    fs.writeFileSync(f, JSON.stringify(inputs.headerSources[chain]));
    out.push('--evm-header-file', chain + '=' + f);
  });
  if (inputs.trustAnchorsPem.length > 0) {
    const f = path.join(dir, 'roots.pem');
    fs.writeFileSync(f, inputs.trustAnchorsPem.map((p) => p + '\n').join(''));
    out.push('--tsa-roots', f);
  }
  for (const id of inputs.regime.require) out.push('--require', id);
  for (const r of inputs.regime.requireRung) out.push('--require-rung', r);
  if (inputs.regime.allowUnchecked) out.push('--allow-unchecked');
  return out;
}

// REGISTRY is a registry that serves the tarballs in one directory and
// nothing else, as npm's registry API does: GET /<name> is the package's
// document (its one version, tagged latest), GET /-/tarballs/<file> the
// tarball. It prints its port once it listens.
const REGISTRY = `
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const zlib = require('zlib');
const dir = process.argv[1];
function manifestOf(data) {
  const tar = zlib.gunzipSync(data);
  for (let off = 0; off + 512 <= tar.length;) {
    const name = tar.toString('utf8', off, off + 100).split('\\0')[0];
    if (name === '') break;
    const size = parseInt(tar.toString('utf8', off + 124, off + 136).split('\\0')[0].trim(), 8) || 0;
    if (name === 'package/package.json') return JSON.parse(tar.toString('utf8', off + 512, off + 512 + size));
    off += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error('no package/package.json');
}
const byName = {};
const byFile = {};
for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.tgz'))) {
  const data = fs.readFileSync(path.join(dir, file));
  const manifest = manifestOf(data);
  byName[manifest.name] = { manifest, file, data };
  byFile[file] = data;
}
const server = http.createServer((req, res) => {
  const url = decodeURIComponent(req.url.split('?')[0]);
  process.stderr.write(req.method + ' ' + url + '\\n');
  if (url.startsWith('/-/tarballs/') && byFile[url.slice(12)]) {
    res.writeHead(200, { 'content-type': 'application/octet-stream' });
    return res.end(byFile[url.slice(12)]);
  }
  const p = byName[url.slice(1)];
  if (!p) {
    res.writeHead(404, { 'content-type': 'application/json' });
    return res.end('{"error":"not found"}');
  }
  const v = p.manifest.version;
  const doc = { name: p.manifest.name, 'dist-tags': { latest: v }, versions: {} };
  doc.versions[v] = Object.assign({}, p.manifest, {
    _id: p.manifest.name + '@' + v,
    dist: {
      tarball: 'http://' + req.headers.host + '/-/tarballs/' + p.file,
      integrity: 'sha512-' + crypto.createHash('sha512').update(p.data).digest('base64'),
      shasum: crypto.createHash('sha1').update(p.data).digest('hex'),
    },
  });
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify(doc));
});
server.listen(0, '127.0.0.1', () => process.stdout.write(server.address().port + '\\n'));
`;

// startRegistry starts REGISTRY on the tarballs in dir and resolves to its
// URL and the process, whose standard error logs each request.
function startRegistry(dir) {
  return new Promise((resolve, reject) => {
    const child = childProcess.spawn(process.execPath, ['-e', REGISTRY, dir], { stdio: ['ignore', 'pipe', 'pipe'] });
    const log = [];
    child.stderr.on('data', (d) => log.push(d.toString()));
    child.stdout.once('data', (d) => resolve({ url: 'http://127.0.0.1:' + String(d).trim() + '/', child: child, log: log }));
    child.once('exit', (code) => reject(new Error('the registry exited ' + code + ': ' + log.join(''))));
  });
}

// tzunPackages lists the tzun-verify packages in a node_modules directory.
function tzunPackages(dir) {
  return fs.readdirSync(dir).filter((n) => n.startsWith('tzun-verify')).sort().join(', ');
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 2 || args.length > 3) {
    process.stderr.write('usage: node npm/test.js <packages-dir> <dist-dir> [<corpus-dir>]\n');
    process.exit(2);
  }
  const packages = path.resolve(args[0]);
  const dist = path.resolve(args[1]);
  const corpus = path.resolve(args[2] || path.join(__dirname, '..', 'testdata', 'vectors', 'bundle-b1'));

  const order = fs.readFileSync(path.join(packages, 'publish-order.txt'), 'utf8').trim().split('\n');
  const mainTarball = order[order.length - 1];
  const version = /^tzun-verify-(.+)\.tgz$/.exec(mainTarball)[1];
  const key = process.platform + '-' + process.arch;
  if (!PLATFORMS[key]) throw new Error('tzun-verify has no package for ' + key);
  const pkg = 'tzun-verify-' + key;
  const platformTarball = pkg + '-' + version + '.tgz';
  assert(order.includes(platformTarball), 'publish-order.txt does not list ' + platformTarball);
  const goos = Object.keys(OS).find((k) => OS[k] === process.platform);
  const goarch = Object.keys(ARCH).find((k) => ARCH[k] === process.arch);
  const releaseName = 'tzun-verify_' + version + '_' + goos + '_' + goarch + (goos === 'windows' ? '.exe' : '');
  // Its real path, as require.resolve reports paths under it (on macOS the
  // temporary directory is behind a symbolic link).
  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-verify-npm-')));
  const cache = path.join(tmp, 'npm-cache');
  const app = path.join(tmp, 'app');
  fs.mkdirSync(cache);
  fs.mkdirSync(app);
  process.stdout.write('== tzun-verify ' + version + ' on ' + key + ' (node ' + process.version +
    ', npm ' + npm(['--version'], tmp, cache).stdout.trim() + ')\n');

  // The release binary, as a user who downloads it would run it.
  const sums = readSums(path.join(dist, 'SHA256SUMS'));
  const ref = path.join(tmp, releaseName);
  fs.copyFileSync(path.join(dist, releaseName), ref);
  fs.chmodSync(ref, 0o755);
  check('the release binary matches SHA256SUMS', sha256(ref) === sums.get(releaseName));

  // A local install: this platform's package and the launcher, from their
  // tarballs, offline, with an empty cache.
  fs.writeFileSync(path.join(app, 'package.json'), JSON.stringify({ name: 'npm-test', version: '1.0.0', private: true }) + '\n');
  npm(['install', path.join(packages, mainTarball), path.join(packages, platformTarball)], app, cache);
  const installed = fs.readdirSync(path.join(app, 'node_modules')).filter((n) => n.startsWith('tzun-verify')).sort();
  check('installed exactly tzun-verify and ' + pkg + ' (got ' + installed.join(', ') + ')',
    installed.join(',') === ['tzun-verify', pkg].sort().join(','));
  const bin = path.join(app, 'node_modules', pkg, 'bin', PLATFORMS[key]);
  check('the installed binary is byte for byte ' + releaseName, sha256(bin) === sums.get(releaseName));
  if (process.platform !== 'win32') {
    check('the installed binary is executable', (fs.statSync(bin).mode & 0o111) === 0o111);
  }
  for (const name of installed) {
    const manifest = JSON.parse(fs.readFileSync(path.join(app, 'node_modules', name, 'package.json'), 'utf8'));
    check(name + ' has no install scripts', !manifest.scripts);
  }

  const ctx = { app: app, cache: cache, ref: ref, npx: npmCli('npx-cli.js') };

  // Every corpus case, JSON and text.
  const cases = fs.readdirSync(corpus).filter((n) => fs.statSync(path.join(corpus, n)).isDirectory()).sort();
  assert(cases.length > 0, corpus + ' has no cases');
  for (const name of cases) {
    const dir = path.join(corpus, name);
    const inputsDir = path.join(tmp, 'inputs', name);
    fs.mkdirSync(inputsDir, { recursive: true });
    const f = flags(JSON.parse(fs.readFileSync(path.join(dir, 'inputs.json'), 'utf8')), inputsDir);
    const bundle = path.join(dir, 'bundle.json');
    const r = same(name + ' --json', ctx, f.concat(['--json', bundle]), true);
    const expectedExit = Number(fs.readFileSync(path.join(dir, 'expected-exit'), 'utf8').trim());
    check(name + ': exit ' + r.status + ', expected-exit ' + expectedExit, r.status === expectedExit);
    let report = null;
    try {
      report = JSON.parse(r.stdout);
    } catch (err) {
      check(name + ': the report is not JSON', false, r.stdout + r.stderr);
    }
    if (report) {
      const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected-report.json'), 'utf8'));
      check(name + ': the report is not expected-report.json',
        canonical(withoutCheckedAt(report)) === canonical(withoutCheckedAt(expected)));
    }
    same(name, ctx, f.concat([bundle]), false);
  }
  process.stdout.write('corpus: ' + cases.length + ' cases, each with and without --json\n');

  // Runs that print no report, and arguments a shell would mangle.
  const spaced = path.join(tmp, 'a dir with spaces', 'bündle «1».json');
  fs.mkdirSync(path.dirname(spaced), { recursive: true });
  fs.copyFileSync(path.join(corpus, cases[0], 'bundle.json'), spaced);
  same('--version', ctx, ['--version'], false);
  same('--help', ctx, ['--help'], false);
  same('no arguments', ctx, [], false);
  same('an unknown flag', ctx, ['--no-such-flag', spaced], false);
  same('a switch with a value', ctx, ['--allow-unchecked=false', spaced], false);
  same('a path with spaces', ctx, ['--no-publishers', spaced], false);
  same('a path that does not exist', ctx, [path.join(tmp, 'no such dir', 'x.json')], false);
  // Quotes and shell characters go to the launcher unchanged; npx itself runs
  // its command through a shell, so these go through the launcher alone.
  const odd = path.join(tmp, 'it\'s "quoted" $HOME `x` & | ; %PATH% !x', 'b.json');
  const launcher = path.join(app, 'node_modules', 'tzun-verify', 'bin', 'tzun-verify.js');
  for (const a of [[odd], ['--publishers', odd, spaced], ['--require', 'anchor,anchor.evm.canonical[*]', spaced]]) {
    const viaLauncher = spawn(process.execPath, [launcher].concat(a), { cwd: app });
    const direct = spawn(ref, a, { cwd: app });
    compared++;
    check('launcher ' + JSON.stringify(a) + ': output or exit code differs',
      viaLauncher.status === direct.status && viaLauncher.stdout === direct.stdout && viaLauncher.stderr === direct.stderr,
      firstDifference(viaLauncher.stderr, direct.stderr));
  }

  // A global install, run as the command on PATH would be.
  const prefix = path.join(tmp, 'global');
  npm(['install', '--global', '--prefix', prefix, path.join(packages, mainTarball), path.join(packages, platformTarball)], tmp, cache);
  const globalBundle = path.join(corpus, cases[0], 'bundle.json');
  const g = process.platform === 'win32'
    ? spawn(path.join(prefix, 'tzun-verify.cmd'), ['--no-publishers', globalBundle], { shell: true })
    : spawn(path.join(prefix, 'bin', 'tzun-verify'), ['--no-publishers', globalBundle]);
  const d = spawn(ref, ['--no-publishers', globalBundle]);
  compared++;
  check('global install: output or exit code differs', g.status === d.status && g.stdout === d.stdout && g.stderr === d.stderr,
    firstDifference(g.stdout + g.stderr, d.stdout + d.stderr));

  // The launcher's own errors.
  const installedPkg = path.join(app, 'node_modules', pkg);
  fs.renameSync(installedPkg, installedPkg + '.away');
  let e = spawn(process.execPath, [launcher, '--version'], { cwd: app });
  check('without ' + pkg + ': exit 127 and a message naming it', e.status === 127 && e.stderr.includes(pkg + ', which carries the binary') && e.stdout === '', e.stderr);
  fs.renameSync(installedPkg + '.away', installedPkg);
  const manifestPath = path.join(installedPkg, 'package.json');
  const manifest = fs.readFileSync(manifestPath, 'utf8');
  fs.writeFileSync(manifestPath, manifest.replace('"version": "' + version + '"', '"version": "0.0.1-other"'));
  e = spawn(process.execPath, [launcher, '--version'], { cwd: app });
  check('with ' + pkg + ' of another version: exit 127', e.status === 127 && e.stderr.includes('is version 0.0.1-other'), e.stderr);
  fs.writeFileSync(manifestPath, manifest);
  let msg = '';
  try {
    binaryPath('plan9', 'mips');
  } catch (err) {
    msg = err.message;
  }
  check('an unknown platform is refused by name', msg.includes('no binary for plan9-mips'), msg);

  // From a registry, as npm installs it from npmjs.com.
  const registry = await startRegistry(packages);
  try {
    // A bare `npx tzun-verify` in an empty directory, with an empty cache.
    const [node, npx] = ctx.npx;
    const empty = path.join(tmp, 'empty');
    const npxCache = path.join(tmp, 'npx-cache');
    fs.mkdirSync(empty);
    fs.mkdirSync(npxCache);
    const bundle = path.join(corpus, cases[0], 'bundle.json');
    for (const a of [['--json', bundle], [bundle]]) {
      const viaNpx = spawn(node, [npx, '--yes', 'tzun-verify'].concat(a), { cwd: empty, env: npmEnv(npxCache, registry.url) });
      const direct = spawn(ref, a, { cwd: empty });
      const strip = (t) => t.replace(CHECKED_AT, '"checkedAt":""');
      compared++;
      check('npx tzun-verify ' + a.join(' ') + ' from the registry: output or exit code differs',
        viaNpx.status === direct.status && strip(viaNpx.stdout) === strip(direct.stdout) && viaNpx.stderr === direct.stderr,
        firstDifference(strip(viaNpx.stdout) + viaNpx.stderr, strip(direct.stdout) + direct.stderr));
    }
    // The registry's log is read once the event loop has run.
    await new Promise((resolve) => setTimeout(resolve, 200));
    const fetched = registry.log.join('').split('\n').filter((l) => l.startsWith('GET /-/tarballs/')).map((l) => l.slice(16)).sort();
    check('npx downloaded only tzun-verify and ' + pkg + ' (got ' + fetched.join(', ') + ')',
      fetched.join(', ') === [mainTarball, platformTarball].sort().join(', '));
    const npxDirs = fs.readdirSync(path.join(npxCache, '_npx'));
    check('npx installed tzun-verify once (' + npxDirs.length + ' installs)', npxDirs.length === 1);
    const npxModules = path.join(npxCache, '_npx', npxDirs[0], 'node_modules');
    check('npx installed exactly tzun-verify and ' + pkg + ' (got ' + tzunPackages(npxModules) + ')',
      tzunPackages(npxModules) === ['tzun-verify', pkg].sort().join(', '));

    // npm install, once as each platform: exactly that platform's package,
    // and the launcher picks its binary, the release file byte for byte.
    for (const k of Object.keys(PLATFORMS)) {
      const [platform, arch] = k.split('-');
      const project = path.join(tmp, 'as-' + k);
      fs.mkdirSync(project);
      fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'as-' + k, version: '1.0.0', private: true }) + '\n');
      npm(['install', '--os=' + platform, '--cpu=' + arch, 'tzun-verify'], project, path.join(tmp, 'cache-' + k), registry.url);
      const modules = path.join(project, 'node_modules');
      check('as ' + k + ', npm installed exactly tzun-verify and tzun-verify-' + k + ' (got ' + tzunPackages(modules) + ')',
        tzunPackages(modules) === ['tzun-verify', 'tzun-verify-' + k].sort().join(', '));
      const goos = Object.keys(OS).find((g) => OS[g] === platform);
      const goarch = Object.keys(ARCH).find((g) => ARCH[g] === arch);
      const release = 'tzun-verify_' + version + '_' + goos + '_' + goarch + (goos === 'windows' ? '.exe' : '');
      let picked = null;
      try {
        picked = require(path.join(modules, 'tzun-verify', 'bin', 'tzun-verify.js')).binaryPath(platform, arch);
      } catch (err) {
        check('as ' + k + ', the launcher found no binary', false, err.message);
      }
      if (picked) {
        check('as ' + k + ', the launcher picks the ' + k + ' binary (' + picked + ')',
          executableFormat(picked) === k && sha256(picked) === sums.get(release) && picked.startsWith(path.join(modules, 'tzun-verify-' + k)));
      }
    }
    process.stdout.write('registry: npx tzun-verify in an empty directory, and npm install as each of ' +
      Object.keys(PLATFORMS).join(', ') + '\n');
  } finally {
    registry.child.kill();
  }

  if (failures.length > 0) {
    process.stdout.write(failures.length + ' failure(s); the install is kept in ' + tmp + '\n');
    process.exit(1);
  }
  fs.rmSync(tmp, { recursive: true, force: true });
  process.stdout.write('OK   ' + compared + ' runs of npx tzun-verify and the launcher matched the release binary ' + releaseName + '\n');
}

main().catch((err) => {
  process.stderr.write((err && err.stack) || String(err));
  process.stderr.write('\n');
  process.exit(1);
});
