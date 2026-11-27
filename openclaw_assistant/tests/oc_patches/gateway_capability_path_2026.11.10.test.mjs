// Upstream check for OpenClaw 2026.11.10 (no add-on patch). 2026.11.10 carries openclaw/openclaw#190863 itself
// (d4c687ac8c97, src/gateway/plugin-node-capability.ts:343-344), so oc-patches/2026.11.10 has no
// gateway-capability-path-guard. These tests check that the bundled stock function still marks a capability-scoped
// path /__openclaw__/cap/<cap>/<rest> as malformed when <rest> starts with a second slash or an encoded slash or
// backslash. The callers then answer 400 (server-http-request.ts:283-286, server-http-upgrades.ts:301-304).
// The cases are those of the former backport's tests (gateway_capability_path_2026.11.8.test.mjs, removed with the
// 2026.11.8 set). The code is sliced from the one-line minified module after the marker line
// '//!src/gateway/plugin-node-capability.ts'; the anchors are minified code, each once in the chunk.
// They run the real normalizePluginNodeCapabilityScopedUrl in a vm with synthetic URLs (no gateway, no network, no
// runtime dependencies; normalizeOptionalString is the string-coerce one-liner). Node 22 or 24.
// In a container of the image built with OPENCLAW_VERSION=2026.11.10:
//   node --test tests/oc_patches/gateway_capability_path_2026.11.10.test.mjs
// or against an unpacked package (stock or patched by oc_dist_patch.py, the chunk is not patched):
//   OC_DIST=<package>/dist node --test tests/oc_patches/gateway_capability_path_2026.11.10.test.mjs
// A failure here means a later build lost the upstream guard: re-add the patch to oc-patches/<version>/.
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const OPENCLAW_VERSION = '2026.11.10';
// Stock chunk (not patched; the marker line below pins the module it holds).
const CHUNK = 'plugin-node-capability-C3FKPhfC.mjs';

const distDir = process.env.OC_DIST || path.join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'openclaw', 'dist');
const version = JSON.parse(fs.readFileSync(path.join(distDir, '..', 'package.json'), 'utf8')).version;
assert.equal(version, OPENCLAW_VERSION, `these tests are for OpenClaw ${OPENCLAW_VERSION}; OC_DIST belongs to ${version}`);
const chunk = fs.readFileSync(path.join(distDir, CHUNK), 'utf8');
assert.ok(chunk.split('\n').includes('//!src/gateway/plugin-node-capability.ts'), `${CHUNK} does not hold src/gateway/plugin-node-capability.ts`);
const once = (from, to) => {
  const start = chunk.indexOf(from);
  assert.ok(start >= 0 && chunk.indexOf(from, start + 1) < 0, `${from.trim()} is not in ${CHUNK} exactly once`);
  const end = chunk.indexOf(to, start + from.length);
  assert.ok(end > start, `${to.trim()} does not follow ${from.trim()}`);
  return chunk.slice(start, end);
};
const constants = once('const PLUGIN_NODE_CAPABILITY_PATH_PREFIX=', 'const DEFAULT_PLUGIN_NODE_CAPABILITY_TTL_MS=');
const fn = once('function normalizePluginNodeCapabilityScopedUrl(', 'function setClientPluginNodeCapability(');
const context = vm.createContext({
  URL,
  // string-coerce.ts normalizeOptionalString: a trimmed non-empty string, else undefined
  normalizeOptionalString: (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
});
vm.runInContext(`${constants}\n${fn}\nglobalThis.normalize = normalizePluginNodeCapabilityScopedUrl;`, context);
const normalize = (url) => JSON.parse(JSON.stringify(context.normalize(url)));

test(`${version}: a scoped path is rewritten to its canonical path plus the capability query`, () => {
  assert.deepEqual(normalize('/__openclaw__/cap/abc123/plugins/x/index.html?a=1'), {
    pathname: '/plugins/x/index.html', capability: 'abc123',
    rewrittenUrl: '/plugins/x/index.html?a=1&oc_cap=abc123', scopedPath: true, malformedScopedPath: false,
  });
  assert.deepEqual(normalize('/__openclaw__/cap/abc123/'),
    { pathname: '/', capability: 'abc123', rewrittenUrl: '/?oc_cap=abc123', scopedPath: true, malformedScopedPath: false });
});

for (const [label, url] of [['a second slash', '/__openclaw__/cap/abc123//evil.example/x'],
  ['an encoded slash', '/__openclaw__/cap/abc123/%2fevil.example/x'],
  ['an encoded backslash (upper case)', '/__openclaw__/cap/abc123/%5Cevil.example/x']]) {
  test(`${version}: a scoped path whose remainder starts with ${label} is malformed (openclaw/openclaw#190863, upstream)`, () => {
    const r = normalize(url);
    assert.equal(r.scopedPath, true);
    assert.equal(r.malformedScopedPath, true);
    assert.equal(r.rewrittenUrl, undefined);
  });
}

test(`${version}: the other malformed and unscoped forms are unchanged`, () => {
  assert.equal(normalize('/__openclaw__/cap/abc123').malformedScopedPath, true); // no "/" after the capability
  assert.equal(normalize('/__openclaw__/cap//x').malformedScopedPath, true); // empty capability
  assert.equal(normalize('/__openclaw__/cap/%E0%A4%A/x').malformedScopedPath, true); // undecodable capability
  assert.deepEqual(normalize('/plugins/x?oc_cap=q1'),
    { pathname: '/plugins/x', capability: 'q1', scopedPath: false, malformedScopedPath: false });
  assert.equal(normalize('/plugins/a//b').malformedScopedPath, false); // only scoped paths are checked
});
