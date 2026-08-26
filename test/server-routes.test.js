// SPDX-License-Identifier: MIT
/**
 * Integration tests for the exported TypeScript server (setupNyloRoutes):
 *  - write-grant authorization on verification and ingestion;
 *  - unauthorized callers cannot consume (burn) tokens;
 *  - replay protection with built-in, integrator-supplied, and legacy stores;
 *  - fingerprint stripping + URL minimization at ingestion;
 *  - production fail-closed startup requirements.
 *
 * Node 18 cannot run TypeScript directly, so the server is compiled once
 * with tsc into a throwaway build directory.
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { execSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..');
const BUILD_DIR = path.join(ROOT, '.test-build');
const SECRET = 'server-routes-test-secret';

const { signCrossDomainToken, createInMemoryReplayStore, hashToken } = require('../server/utils/token-core');
const { signWriteGrant } = require('../server/utils/write-grant');
const { buildEnvelope } = require('../shared/event-envelope');

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
    getTenantIdForDomain: async (d) =>
      (d === 'dest.example.com' || d === 'source.example.com') ? 1 : null,
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

function makeGrant(domain, scopes, tenantId) {
  return signWriteGrant({
    tenantId: tenantId === undefined ? '1' : tenantId,
    domain: domain || 'dest.example.com',
    scopes: scopes || ['ingest', 'register']
  }, SECRET);
}

async function verify(baseUrl, token, opts) {
  opts = opts || {};
  const headers = { 'Content-Type': 'application/json' };
  const grant = 'grant' in opts ? opts.grant : makeGrant();
  if (grant) headers['X-Nylo-Grant'] = grant;
  const res = await fetch(baseUrl + '/api/tracking/verify-cross-domain-token', {
    method: 'POST',
    headers,
    body: JSON.stringify({ token, domain: 'dest.example.com' })
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

test('verification without a write grant is rejected AND does not consume the token', async () => {
  const { server, baseUrl } = await startServer(makeStorage({}));
  try {
    const token = makeToken();

    const unauthorized = await verify(baseUrl, token, { grant: null });
    assert.strictEqual(unauthorized.status, 401);
    assert.strictEqual(unauthorized.body.error, 'GRANT_REQUIRED');

    const tampered = await verify(baseUrl, token, { grant: makeGrant() + 'x' });
    assert.strictEqual(tampered.status, 403);

    // The legitimate destination can still verify: the failed attempts
    // above must not have burned the token.
    const legit = await verify(baseUrl, token);
    assert.strictEqual(legit.status, 200, JSON.stringify(legit.body));
  } finally {
    server.close();
  }
});

test('verification with a grant for the wrong domain is rejected without consuming the token', async () => {
  const { server, baseUrl } = await startServer(makeStorage({}));
  try {
    const token = makeToken();
    const wrongDomain = await verify(baseUrl, token, { grant: makeGrant('other.example.com') });
    assert.strictEqual(wrongDomain.status, 403);
    assert.strictEqual(wrongDomain.body.error, 'GRANT_DOMAIN_MISMATCH');

    const legit = await verify(baseUrl, token);
    assert.strictEqual(legit.status, 200, JSON.stringify(legit.body));
  } finally {
    server.close();
  }
});

test('the grant issuance route resolves tenants from server-side domain mapping', async () => {
  const { server, baseUrl } = await startServer(makeStorage({}));
  try {
    const res = await fetch(baseUrl + '/api/tracking/grant', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Origin': 'https://dest.example.com' },
      body: JSON.stringify({ domain: 'dest.example.com' })
    });
    const body = await res.json();
    assert.strictEqual(res.status, 200, JSON.stringify(body));
    assert.strictEqual(body.success, true);
    assert.ok(body.grant, 'grant issued');

    // The issued grant authorizes verification for its domain.
    const token = makeToken();
    const result = await verify(baseUrl, token, { grant: body.grant });
    assert.strictEqual(result.status, 200, JSON.stringify(result.body));

    // Unmapped domains get nothing.
    const denied = await fetch(baseUrl + '/api/tracking/grant', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Origin': 'https://unmapped.example.com' },
      body: JSON.stringify({ domain: 'unmapped.example.com' })
    });
    assert.strictEqual(denied.status, 403);

    // Origin/domain mismatch is refused: a page cannot request a grant
    // for a domain it is not served from.
    const mismatch = await fetch(baseUrl + '/api/tracking/grant', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Origin': 'https://evil.example.com' },
      body: JSON.stringify({ domain: 'dest.example.com' })
    });
    assert.strictEqual(mismatch.status, 403);
  } finally {
    server.close();
  }
});

test('/api/track requires a grant, derives the tenant from it, strips fingerprint fields and minimizes URLs', async () => {
  const captured = [];
  const { server, baseUrl } = await startServer(makeStorage({
    createInteraction: async (row) => { captured.push(row); return row; }
  }));
  try {
    const event = {
      eventId: crypto.randomBytes(16).toString('hex'),
      sessionId: 'sess_route_test_01',
      waiTag: 'wai_1234567890_abc',
      userId: 'wai_1234567890_abc',
      domain: 'dest.example.com',
      eventType: 'page_view',
      timestamp: new Date().toISOString(),
      url: 'https://dest.example.com/checkout?email=a@b.com&token=SECRETVALUE#step2',
      metadata: '{"loadTime":42}',
      // Fingerprint-capable fields a malicious/outdated client might send:
      language: 'en-US',
      screenWidth: 1920,
      userAgent: 'Mozilla/5.0'
    };
    const envelope = buildEnvelope([event], { batchId: crypto.randomBytes(16).toString('hex') });

    // Without a grant: rejected, nothing stored.
    const noGrant = await fetch(baseUrl + '/api/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope)
    });
    assert.strictEqual(noGrant.status, 401);
    assert.strictEqual(captured.length, 0);

    // With a grant: stored under the grant's tenant, sanitized.
    const res = await fetch(baseUrl + '/api/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Nylo-Grant': makeGrant() },
      body: JSON.stringify(envelope)
    });
    const body = await res.json();
    assert.strictEqual(res.status, 200, JSON.stringify(body));
    assert.strictEqual(body.eventsProcessed, 1, JSON.stringify(body));
    assert.strictEqual(captured.length, 1);

    const row = captured[0];
    assert.strictEqual(String(row.customerId), '1', 'tenant comes from the grant');
    assert.strictEqual(row.pageUrl, 'https://dest.example.com/checkout', 'query/fragment stripped');
    const serialized = JSON.stringify(row).toLowerCase();
    assert.ok(!serialized.includes('secretvalue'), 'query secrets never stored');
    assert.ok(!serialized.includes('useragent'), 'user agent stripped');
    assert.ok(!serialized.includes('screenwidth'), 'screen size stripped');
    assert.ok(!serialized.includes('"language"'), 'language stripped');

    // Conflicting customerId in an event is rejected, not reassigned.
    const conflicting = Object.assign({}, event, {
      eventId: crypto.randomBytes(16).toString('hex'),
      customerId: '999'
    });
    const res2 = await fetch(baseUrl + '/api/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Nylo-Grant': makeGrant() },
      body: JSON.stringify(buildEnvelope([conflicting]))
    });
    const body2 = await res2.json();
    assert.strictEqual(body2.results[0].status, 'rejected');
    assert.strictEqual(body2.results[0].reason, 'tenant_mismatch');
  } finally {
    server.close();
  }
});

test('production startup fails closed without durable replay storage and domain→tenant mapping', () => {
  const express = require('express');
  const prevEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    // No durable replay store → refuse to start.
    assert.throws(() => {
      const app = express();
      app.use(express.json());
      setupNyloRoutes(app, makeStorage({ tokenReplayStore: undefined, getTenantIdForDomain: undefined }));
    }, /replay/i);

    // Replay store present but no server-side tenant mapping → refuse to start.
    assert.throws(() => {
      const app = express();
      app.use(express.json());
      setupNyloRoutes(app, makeStorage({
        tokenReplayStore: createInMemoryReplayStore(),
        getTenantIdForDomain: undefined
      }));
    }, /getTenantIdForDomain/);
  } finally {
    process.env.NODE_ENV = prevEnv;
  }
});
