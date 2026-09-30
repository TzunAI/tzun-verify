#!/usr/bin/env node
'use strict';
// The tzun-verify command of the npm package: it runs the release binary for
// this machine and passes its arguments, standard streams and exit code
// through unchanged. The binary comes from the platform package npm installed
// with tzun-verify as an optional dependency (tzun-verify-linux-x64, ...), and
// is byte for byte the file of the same name in the GitHub release. Nothing is
// downloaded, at install or here.
//
// Exit codes are the verifier's (0, 1, 2, 3, 4, 64), except when the binary
// cannot be run at all: 127 when no platform package for this machine is
// installed, 126 when the binary is there but will not start.

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Each platform package, named tzun-verify-<process.platform>-<process.arch>,
// and its binary's name under bin/. npm/stage.js builds a package for each
// entry from the release target of the same platform, and refuses a release
// whose targets differ from these.
const PLATFORMS = {
  'linux-x64': 'tzun-verify',
  'linux-arm64': 'tzun-verify',
  'darwin-x64': 'tzun-verify',
  'darwin-arm64': 'tzun-verify',
  'win32-x64': 'tzun-verify.exe',
};

class LaunchError extends Error {}

// binaryPath returns the path of the binary for platform and arch, from the
// installed platform package of this package's own version, and throws a
// LaunchError that says what to do when there is none.
function binaryPath(platform, arch) {
  const key = platform + '-' + arch;
  if (!Object.prototype.hasOwnProperty.call(PLATFORMS, key)) {
    throw new LaunchError(
      'there is no binary for ' + key + ' in this npm package; it carries ' +
        Object.keys(PLATFORMS).join(', ') + '.\n' +
        'Build tzun-verify from source instead: https://github.com/TzunAI/tzun-verify#how-to-run-it'
    );
  }
  const name = 'tzun-verify-' + key;
  let manifest;
  try {
    manifest = require.resolve(name + '/package.json');
  } catch (err) {
    throw new LaunchError(
      'the package ' + name + ', which carries the binary for ' + key + ', is not installed.\n' +
        'npm installs it with tzun-verify as an optional dependency: reinstall tzun-verify\n' +
        'without --omit=optional (or --no-optional), and if a lockfile made on another\n' +
        'platform left it out, reinstall without that lockfile.'
    );
  }
  const own = require('../package.json').version;
  const theirs = JSON.parse(fs.readFileSync(manifest, 'utf8')).version;
  if (theirs !== own) {
    throw new LaunchError(
      name + ' is version ' + theirs + ', but tzun-verify is ' + own + ': reinstall tzun-verify.'
    );
  }
  return path.join(path.dirname(manifest), 'bin', PLATFORMS[key]);
}

function main() {
  let bin;
  try {
    bin = binaryPath(process.platform, process.arch);
  } catch (err) {
    if (!(err instanceof LaunchError)) throw err;
    process.stderr.write('tzun-verify: ' + err.message + '\n');
    process.exit(127);
  }
  const run = childProcess.spawnSync(bin, process.argv.slice(2), {
    stdio: 'inherit',
    windowsHide: true,
  });
  if (run.error) {
    process.stderr.write('tzun-verify: cannot run ' + bin + ': ' + run.error.message + '\n');
    process.exit(126);
  }
  if (run.signal) {
    // Die of the same signal, as a shell reports a command killed by one.
    process.kill(process.pid, run.signal);
    process.exit(128 + (os.constants.signals[run.signal] || 0));
  }
  process.exit(run.status);
}

if (require.main === module) {
  main();
}

module.exports = { PLATFORMS: PLATFORMS, binaryPath: binaryPath };
