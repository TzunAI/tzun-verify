#!/usr/bin/env node
'use strict';
// Makes the npm packages from a release's files and packs them:
//
//   node npm/stage.js <dist-dir> <out-dir> [<version>]
//
// <dist-dir> holds the files scripts/release-artifacts.sh writes (RELEASING.md,
// "The files"): the binaries and SHA256SUMS; the archives are not read. Every
// binary is checked against SHA256SUMS, and its header against the platform
// its package is for. <out-dir>, which must be empty or not exist, receives
// one directory and one tarball per package:
//
//   tzun-verify-<platform>-<arch>   one per release target: package.json,
//                                   README.md and bin/tzun-verify[.exe], the
//                                   release binary byte for byte
//   tzun-verify                     the launcher (npm/tzun-verify), with each
//                                   platform package, at the same version,
//                                   as an optional dependency
//
// and publish-order.txt, the tarballs in the order they are published:
// the platform packages first, tzun-verify last. The version is the one in
// the binaries' names; with <version>, anything else is refused. So is a
// release whose targets are not exactly the platforms the launcher knows.
// No package has an install script.

const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { PLATFORMS } = require('./tzun-verify/bin/tzun-verify.js');

const REPO = 'https://github.com/TzunAI/tzun-verify';
const MAIN = 'tzun-verify';
const TEMPLATE = path.join(__dirname, MAIN);

// Go's GOOS and GOARCH, as release file names spell them, to Node's
// process.platform and process.arch, as package names do.
const OS = { linux: 'linux', darwin: 'darwin', windows: 'win32' };
const ARCH = { amd64: 'x64', arm64: 'arm64' };
const LABEL = { linux: 'Linux', darwin: 'macOS', win32: 'Windows' };

const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$/;
const BINARY = /^tzun-verify_([^_]+)_([a-z0-9]+)_([a-z0-9]+)(\.exe)?$/;

function fail(msg) {
  process.stderr.write('stage: ' + msg + '\n');
  process.exit(1);
}

// readSums reads a SHA256SUMS file: name -> lower-case hex.
function readSums(file) {
  const sums = new Map();
  const text = fs.readFileSync(file, 'utf8');
  for (const line of text.split('\n')) {
    if (line === '') continue;
    const m = /^([0-9a-f]{64}) {2}(\S.*)$/.exec(line);
    if (!m) fail(file + ': not a sha256sum line: ' + JSON.stringify(line));
    if (sums.has(m[2])) fail(file + ': ' + m[2] + ' is listed twice');
    sums.set(m[2], m[1]);
  }
  return sums;
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

// executableFormat names the operating system and architecture a binary's
// header says it is for, as "<process.platform>-<process.arch>", or null.
function executableFormat(file) {
  const fd = fs.openSync(file, 'r');
  const head = Buffer.alloc(4096);
  const n = fs.readSync(fd, head, 0, head.length, 0);
  fs.closeSync(fd);
  const b = head.subarray(0, n);
  if (b.length >= 20 && b.readUInt32BE(0) === 0x7f454c46 && b[4] === 2 && b[5] === 1) {
    // ELF, 64-bit, little-endian: e_machine.
    const machine = { 0x3e: 'x64', 0xb7: 'arm64' }[b.readUInt16LE(18)];
    return machine ? 'linux-' + machine : null;
  }
  if (b.length >= 8 && b.readUInt32LE(0) === 0xfeedfacf) {
    // Mach-O, 64-bit: cputype.
    const cpu = { 0x01000007: 'x64', 0x0100000c: 'arm64' }[b.readUInt32LE(4)];
    return cpu ? 'darwin-' + cpu : null;
  }
  if (b.length >= 64 && b.toString('latin1', 0, 2) === 'MZ') {
    // PE: the COFF header's machine.
    const pe = b.readUInt32LE(0x3c);
    if (pe + 6 <= b.length && b.toString('latin1', pe, pe + 4) === 'PE\0\0') {
      const machine = { 0x8664: 'x64', 0xaa64: 'arm64' }[b.readUInt16LE(pe + 4)];
      return machine ? 'win32-' + machine : null;
    }
  }
  return null;
}

// npmCli returns the command that runs npm's own script (npm-cli.js,
// npx-cli.js) with this Node, so no shell is needed on any platform.
function npmCli(script) {
  const dir = path.dirname(process.execPath);
  for (const p of [
    path.join(dir, 'node_modules', 'npm', 'bin', script),
    path.join(dir, '..', 'lib', 'node_modules', 'npm', 'bin', script),
  ]) {
    if (fs.existsSync(p)) return [process.execPath, p];
  }
  throw new Error('cannot find npm\'s ' + script + ' next to ' + process.execPath);
}

function run(cmd, args, opts) {
  const r = childProcess.spawnSync(cmd, args, Object.assign({ encoding: 'utf8' }, opts));
  if (r.error) throw r.error;
  if (r.status !== 0) {
    fail(cmd + ' ' + args.join(' ') + ' exited ' + r.status + ':\n' + r.stdout + r.stderr);
  }
  return r.stdout;
}

function writeJSON(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
}

function platformReadme(pkg, key, version, file, hash) {
  const [platform, arch] = key.split('-');
  const exe = PLATFORMS[key];
  return [
    '# ' + pkg,
    '',
    'The ' + LABEL[platform] + ' ' + arch + ' binary of',
    '[tzun-verify](https://www.npmjs.com/package/tzun-verify) ' + version + '.',
    'Install `tzun-verify`, not this package: npm installs this one with it',
    'on ' + LABEL[platform] + ' ' + arch + ', and the `tzun-verify` command runs it.',
    '',
    '`bin/' + exe + '` is byte for byte `' + file + '` of the GitHub release',
    '[v' + version + '](' + REPO + '/releases/tag/v' + version + '), whose `SHA256SUMS`',
    'lists it with the SHA-256',
    '',
    '```',
    hash,
    '```',
    '',
    'and whose build provenance attestation covers it:',
    '',
    '```',
    'gh attestation verify bin/' + exe + ' --repo TzunAI/tzun-verify \\',
    '  --signer-workflow TzunAI/tzun-verify/.github/workflows/release.yml \\',
    '  --source-ref refs/tags/v' + version + ' --deny-self-hosted-runners',
    '```',
    '',
  ].join('\n');
}

// pack runs npm pack in dir and checks the tarball holds exactly files,
// each with the mode given.
function pack(dir, out, files) {
  const [node, cli] = npmCli('npm-cli.js');
  const json = run(node, [cli, 'pack', '--json', '--pack-destination', out], { cwd: dir });
  const [info] = JSON.parse(json);
  const got = info.files.map((f) => f.path + ' ' + f.mode.toString(8)).sort();
  const want = Object.keys(files).map((f) => f + ' ' + files[f].toString(8)).sort();
  if (got.join('\n') !== want.join('\n')) {
    fail(info.filename + ' holds\n  ' + got.join('\n  ') + '\nnot\n  ' + want.join('\n  '));
  }
  return info;
}

function main() {
  const args = process.argv.slice(2);
  if (args.length < 2 || args.length > 3) {
    process.stderr.write('usage: node npm/stage.js <dist-dir> <out-dir> [<version>]\n');
    process.exit(2);
  }
  const [dist, outArg, wantVersion] = args;
  fs.mkdirSync(outArg, { recursive: true });
  const out = fs.realpathSync(outArg);
  if (fs.readdirSync(out).length > 0) fail(out + ' is not empty');

  const sums = readSums(path.join(dist, 'SHA256SUMS'));
  const targets = new Map();
  let version = null;
  for (const name of sums.keys()) {
    const m = BINARY.exec(name);
    if (!m) continue;
    const [, v, goos, goarch, exe] = m;
    if (version === null) version = v;
    if (v !== version) fail('SHA256SUMS names versions ' + version + ' and ' + v);
    const key = OS[goos] + '-' + ARCH[goarch];
    if (!OS[goos] || !ARCH[goarch] || !PLATFORMS[key]) {
      fail('the release has a binary for ' + goos + '/' + goarch + ', and npm/tzun-verify/bin/tzun-verify.js no package for it');
    }
    if ((PLATFORMS[key] === 'tzun-verify.exe') !== (exe === '.exe')) fail(name + ': wrong executable suffix for ' + key);
    targets.set(key, name);
  }
  if (version === null) fail('SHA256SUMS names no binary');
  if (!VERSION.test(version)) fail('version ' + version + ' is not <major>.<minor>.<patch>[-<pre>]');
  if (wantVersion !== undefined && wantVersion !== version) fail('the binaries are version ' + version + ', not ' + wantVersion);
  for (const key of Object.keys(PLATFORMS)) {
    if (!targets.has(key)) fail('SHA256SUMS names no binary for ' + key);
  }

  const template = JSON.parse(fs.readFileSync(path.join(TEMPLATE, 'package.json'), 'utf8'));
  if (template.name !== MAIN) fail('npm/tzun-verify/package.json names ' + template.name);
  if (template.scripts) fail('npm/tzun-verify/package.json has scripts; no package may run anything at install');

  const order = [];
  const rows = [];
  const optional = {};
  for (const key of Object.keys(PLATFORMS)) {
    const file = targets.get(key);
    const src = path.join(dist, file);
    const hash = sha256(src);
    if (hash !== sums.get(file)) fail(file + ' has SHA-256 ' + hash + ', SHA256SUMS says ' + sums.get(file));
    const format = executableFormat(src);
    if (format !== key) fail(file + ' is a ' + (format || 'unknown') + ' executable, not ' + key);

    const [platform, arch] = key.split('-');
    const pkg = MAIN + '-' + key;
    const exe = PLATFORMS[key];
    const dir = path.join(out, pkg);
    fs.mkdirSync(path.join(dir, 'bin'), { recursive: true });
    fs.copyFileSync(src, path.join(dir, 'bin', exe));
    fs.chmodSync(path.join(dir, 'bin', exe), 0o755);
    if (sha256(path.join(dir, 'bin', exe)) !== hash) fail('the copy of ' + file + ' differs');
    writeJSON(path.join(dir, 'package.json'), {
      name: pkg,
      version: version,
      description: 'The ' + LABEL[platform] + ' ' + arch + ' binary of tzun-verify ' + version + ', from its GitHub release. Install tzun-verify, which runs it.',
      homepage: template.homepage,
      bugs: template.bugs,
      repository: { type: 'git', url: template.repository.url, directory: 'npm' },
      os: [platform],
      cpu: [arch],
      files: ['bin/' + exe],
      preferUnplugged: true,
    });
    fs.writeFileSync(path.join(dir, 'README.md'), platformReadme(pkg, key, version, file, hash));
    const info = pack(dir, out, { 'package.json': 0o644, 'README.md': 0o644, ['bin/' + exe]: 0o755 });
    order.push(info.filename);
    rows.push([info.filename, file, hash]);
    optional[pkg] = version;
  }

  const main = Object.assign({}, template, { version: version, optionalDependencies: optional });
  delete main.private;
  const dir = path.join(out, MAIN);
  fs.mkdirSync(path.join(dir, 'bin'), { recursive: true });
  fs.copyFileSync(path.join(TEMPLATE, 'README.md'), path.join(dir, 'README.md'));
  fs.copyFileSync(path.join(TEMPLATE, 'bin', 'tzun-verify.js'), path.join(dir, 'bin', 'tzun-verify.js'));
  fs.chmodSync(path.join(dir, 'bin', 'tzun-verify.js'), 0o755);
  writeJSON(path.join(dir, 'package.json'), main);
  const info = pack(dir, out, { 'package.json': 0o644, 'README.md': 0o644, 'bin/tzun-verify.js': 0o755 });
  order.push(info.filename);
  rows.push([info.filename, '(launcher)', '']);

  fs.writeFileSync(path.join(out, 'publish-order.txt'), order.join('\n') + '\n');
  process.stdout.write('== npm packages of tzun-verify ' + version + ', in publishing order\n');
  for (const [tarball, file, hash] of rows) {
    process.stdout.write(tarball.padEnd(40) + ' ' + file + (hash ? '  sha256 ' + hash : '') + '\n');
  }
}

if (require.main === module) {
  main();
}

module.exports = { npmCli: npmCli, readSums: readSums, executableFormat: executableFormat, OS: OS, ARCH: ARCH };
