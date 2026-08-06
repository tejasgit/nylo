// SPDX-License-Identifier: MIT
/**
 * Integration tests for the exported TypeScript server (setupNyloRoutes),
 * proving replay protection is enforced both with the built-in default
 * store and with an integrator-supplied store.
 *
 * Node 18 cannot run TypeScript directly, so the server is compiled once
 * with tsc into a throwaway build directory.
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { execSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const BUILD_DIR = path.join(ROOT, '.test-build');
const SECRET = 'server-routes-test-secret';

const { signCrossDomainToken, createInMemoryReplayStore } = require('../server/utils/token-core');

let setupNyloRoutes;

before(() => {
  process.env.NYLO_TOKEN_SECRET = SECRET;
  fs.rmSync(BUILD_DIR, { recursive: true, force: true });
  execSync(
    'npx tsc --module commonjs --target ES2020 --moduleResolution node --esModuleInterop --skipLibCheck ' +
    '--outDir .test-build --rootDir . server/index.ts',
    { cwd: ROOT, stdio: 'pipe' }
  );
  // The shared CJS cores are plain .js and are not emitted by tsc — copy them.
  for (const f of fs.readdirSync(path.join(ROOT, 'server', 'utils'))) {
    if (f.endsWith('.js')) {
      fs.copyFileSync(path.join(ROOT, 'server', 'utils', f), path.join(BUILD_DIR, 'server', 'utils', f));
    }
  }
  // Same for the shared event-envelope contract module (plain CJS .js).
  fs.mkdirSync(path.join(BUILD_DIR, 'shared'), { recursive: true });
  for (const f of fs.readdirSync(path.join(ROOT, 'shared'))) {
    if (f.endsWith('.js')) {
      fs.copyFileSync(path.join(ROOT, 'shared', f), path.join(BUILD_DIR, 'shared', f));
    }
  }
  ({ setupNyloRoutes } = require(path.join(BUILD_DIR, 'server', 'index.js')));
});

after(() => {
  fs.rmSync(BUILD_DIR, { recursive: true, force: true });
});

function makeStorage(extra) {
  return Object.assign({
    getCustomer: async () => ({ id: 1 }),
    getCustomerByApiKey: async () => null,
    createInteraction: async () => ({}),
    parseDomain: (d) => ({ mainDomain: d, subdomain: null }),
    isDomainVerified: async () => true
  }, extra);
}

async function startServer(storage) {
  const express = require('express');
  const app = express();
  app.use(express.json());
  setupNyloRoutes(app, storage);
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  return { server, baseUrl: 'http://127.0.0.1:' + server.address().port };
}

function makeToken() {
  return signCrossDomainToken({
    tenantId: 1,
    sourceDomain: 'source.example.com',
    destinationDomain: 'dest.example.com',
    waiTag: 'wai_abc123def456_xyz',
    sessionId: 'session-1'
  }, SECRET);
}

async function verify(baseUrl, token) {
  const res = await fetch(baseUrl + '/api/tracking/verify-cross-domain-token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, domain: 'dest.example.com', customerId: 1 })
  });
  return { status: res.status, body: await res.json() };
}

test('setupNyloRoutes enforces replay protection with the built-in default store', async () => {
  const { server, baseUrl } = await startServer(makeStorage({}));
  try {
    const token = makeToken();
    const first = await verify(baseUrl, token);
    assert.strictEqual(first.status, 200, JSON.stringify(first.body));
    assert.strictEqual(first.body.success, true);

    const replay = await verify(baseUrl, token);
    assert.strictEqual(replay.status, 403);
    assert.strictEqual(replay.body.error, 'TOKEN_REPLAYED');
  } finally {
    server.close();
  }
});

test('setupNyloRoutes uses an integrator-supplied replay store when provided', async () => {
  const store = createInMemoryReplayStore();
  const { server, baseUrl } = await startServer(makeStorage({ tokenReplayStore: store }));
  try {
    const token = makeToken();
    const first = await verify(baseUrl, token);
    assert.strictEqual(first.status, 200, JSON.stringify(first.body));

    // The supplied store must have recorded the token…
    const { hashToken } = require('../server/utils/token-core');
    assert.strictEqual(await store.isTokenUsed(hashToken(token)), true);

    // …and reuse must be rejected.
    const replay = await verify(baseUrl, token);
    assert.strictEqual(replay.status, 403);
    assert.strictEqual(replay.body.error, 'TOKEN_REPLAYED');
  } finally {
    server.close();
  }
});

test('setupNyloRoutes: concurrent verifications of the same token allow exactly one success', async () => {
  const { server, baseUrl } = await startServer(makeStorage({}));
  try {
    const token = makeToken();
    const results = await Promise.all(
      Array.from({ length: 6 }, () => verify(baseUrl, token))
    );
    const successes = results.filter((r) => r.status === 200);
    const replays = results.filter((r) => r.status === 403 && r.body.error === 'TOKEN_REPLAYED');
    assert.strictEqual(successes.length, 1, 'exactly one 2xx');
    assert.strictEqual(replays.length, 5, 'all others rejected as replays');
  } finally {
    server.close();
  }
});

test('setupNyloRoutes: legacy check+mark store is serialized so concurrent replays cannot both win', async () => {
  // Legacy store WITHOUT consumeToken and with an artificial async delay to
  // widen the race window.
  const used = new Map();
  const legacyStore = {
    isTokenUsed: async (h) => { await new Promise((r) => setTimeout(r, 5)); return used.has(h); },
    markTokenUsed: async (h, ttl) => { await new Promise((r) => setTimeout(r, 5)); used.set(h, Date.now() + ttl); }
  };
  const { server, baseUrl } = await startServer(makeStorage({ tokenReplayStore: legacyStore }));
  try {
    const token = makeToken();
    const results = await Promise.all(
      Array.from({ length: 6 }, () => verify(baseUrl, token))
    );
    const successes = results.filter((r) => r.status === 200);
    assert.strictEqual(successes.length, 1, 'exactly one 2xx even with a non-atomic legacy store');
  } finally {
    server.close();
  }
});
