// Serves web/dist on 127.0.0.1 with the response headers web/_headers
// states, the way a static host would: for local use and for the page's
// tests, never for hosting.
//
//   node web/serve.mjs [--port 8787] [--root web/dist]

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const argv = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = argv.indexOf(name);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : fallback;
};
const port = Number(opt('--port', process.env.PORT || '8787'));
const root = resolve(opt('--root', join(here, 'dist')));

const types = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.txt': 'text/plain; charset=utf-8',
};

// parseHeaders reads _headers: a path pattern on its own line ("/*" or an
// exact path), then its headers, indented, as "Name: value".
function parseHeaders(text) {
  const rules = [];
  let current = null;
  for (const line of text.split('\n')) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    if (!/^\s/.test(line)) {
      current = { pattern: line.trim(), headers: [] };
      rules.push(current);
      continue;
    }
    const i = line.indexOf(':');
    if (current && i > 0) current.headers.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
  }
  return rules;
}

function matches(pattern, path) {
  if (pattern.endsWith('*')) return path.startsWith(pattern.slice(0, -1));
  return pattern === path;
}

let rules = [];
try {
  rules = parseHeaders(await readFile(join(root, '_headers'), 'utf8'));
} catch {
  console.error(`serve: no _headers in ${root}; run web/build.sh first`);
  process.exit(1);
}

const server = createServer(async (req, res) => {
  let url;
  let path;
  try {
    url = new URL(req.url, 'http://localhost');
    path = decodeURIComponent(url.pathname);
  } catch {
    // A malformed address (GET /%E0%A4%A) is answered, never thrown.
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' }).end('bad request\n');
    return;
  }
  if (path.endsWith('/')) path += 'index.html';
  const file = normalize(join(root, path));
  if (file !== root && !file.startsWith(root + sep)) {
    res.writeHead(403).end();
    return;
  }
  for (const rule of rules) {
    if (matches(rule.pattern, url.pathname)) for (const [k, v] of rule.headers) res.setHeader(k, v);
  }
  res.setHeader('Cache-Control', 'no-store');
  try {
    if (!(await stat(file)).isFile() || path.endsWith('/_headers')) throw new Error('not a page file');
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream', 'Content-Length': body.length });
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('not found\n');
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`serving ${root} at http://127.0.0.1:${port}/`);
});
