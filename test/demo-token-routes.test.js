// SPDX-License-Identifier: MIT
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const express = require('express');
const { registerTokenVerification } = require('../examples/demo-token-routes');
const { signCrossDomainToken } = require('../server/utils/token-core');
const { signWriteGrant } = require('../server/utils/write-grant');

const SECRET = 'endpoint-test-secret';
const CLAIMS = {
  tenantId: '1',
  sourceDomain: 'source.example.com',
  destinationDomain: 'dest.example.com',
  waiTag: 'wai_abc123def456_xyz',
  sessionId: 'session-1'
};

let server, baseUrl;

before(async () => {
  const app = express();
  app.use(express.json());
  registerTokenVerification(app, { secret: SECRET });
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = 'http://127.0.0.1:' + server.address().port;
});

after(() => server && server.close());

// Verification is authorized by a write grant bound to the destination
// domain; the tenant inside the grant is what the token must match.
function makeGrant(domain, tenantId) {
  return signWriteGrant({
    tenantId: tenantId || '1',
    domain: domain || 'dest.example.com',
    scopes: ['ingest']
  }, SECRET);
}

async function verify(body, opts) {
  opts = opts || {};
  const headers = { 'Content-Type': 'application/json' };
  const grant = 'grant' in opts ? opts.grant : makeGrant(body.domain);
  if (grant) headers['X-Nylo-Grant'] = grant;
  const res = await fetch(baseUrl + '/api/tracking/verify-cross-domain-token', {
    method: 'POST',
    headers,
    body: JSON.stringify(body)
  });
  return { status: res.status, body: await res.json() };
}

test('valid WTX-1 token verifies once, replay is rejected', async () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  const first = await verify({ token, domain: 'dest.example.com' });
  assert.strictEqual(first.status, 200);
  assert.strictEqual(first.body.verified, true);
  assert.strictEqual(first.body.identity.waiTag, CLAIMS.waiTag);

  const replay = await verify({ token, domain: 'dest.example.com' });
  assert.strictEqual(replay.status, 403);
  assert.strictEqual(replay.body.error, 'TOKEN_REPLAYED');
});

test('verification without a write grant is rejected and does NOT consume the token', async () => {
  const token = signCrossDomainToken({ ...CLAIMS, sessionId: 'noburn-1' }, SECRET);

  const unauthorized = await verify({ token, domain: 'dest.example.com' }, { grant: null });
  assert.strictEqual(unauthorized.status, 401);
  assert.strictEqual(unauthorized.body.error, 'GRANT_REQUIRED');

  const tampered = await verify({ token, domain: 'dest.example.com' }, { grant: makeGrant() + 'x' });
  assert.strictEqual(tampered.status, 403);
  assert.ok(String(tampered.body.error).startsWith('GRANT_'));

  // The legitimate destination still verifies — unauthorized attempts must
  // not burn the token.
  const legit = await verify({ token, domain: 'dest.example.com' });
  assert.strictEqual(legit.status, 200, JSON.stringify(legit.body));
});

test('legacy-shaped token (no version/jti/iat/bindings) is rejected', async () => {
  const legacy = Buffer.from(JSON.stringify({
    waiTag: CLAIMS.waiTag, sessionId: CLAIMS.sessionId, userId: null,
    domain: 'dest.example.com', exp: Date.now() + 60000, sig: 'ab'.repeat(32)
  })).toString('base64');
  const r = await verify({ token: legacy, domain: 'dest.example.com' });
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.body.error, 'MISSING_CLAIMS');
});

test('unsigned token is rejected', async () => {
  const unsigned = Buffer.from(JSON.stringify({
    ...CLAIMS, v: 1, jti: 'x'.repeat(16), iat: Date.now(), exp: Date.now() + 60000
  })).toString('base64');
  const r = await verify({ token: unsigned, domain: 'dest.example.com' });
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.body.error, 'MISSING_SIGNATURE');
});

test('destination-domain binding is enforced at the endpoint', async () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  // The caller holds a perfectly valid grant for other.example.com, but the
  // token was minted for dest.example.com — the token binding must fail.
  const r = await verify({ token, domain: 'other.example.com' }, { grant: makeGrant('other.example.com') });
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.body.error, 'DOMAIN_MISMATCH');
});

test('tenant binding is enforced at the endpoint', async () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  // Authenticated as tenant 999 (via the grant) — a tenant-1 token must not
  // verify for them.
  const r = await verify({ token, domain: 'dest.example.com' }, { grant: makeGrant('dest.example.com', '999') });
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.body.error, 'TENANT_MISMATCH');
});

test('malformed token gets 400', async () => {
  const r = await verify({ token: 'not-a-token', domain: 'dest.example.com' });
  assert.strictEqual(r.status, 400);
  assert.strictEqual(r.body.error, 'MALFORMED_TOKEN');
});

test('all shipped demo servers use the shared verifier (no legacy inline verification)', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  for (const file of ['demo-server.js', 'demo-server-sqlite.js', 'demo-server-postgres.js']) {
    const src = fs.readFileSync(path.join(__dirname, '..', 'examples', file), 'utf8');
    assert.ok(src.includes('registerTokenVerification'), file + ' must use the shared WTX-1 verifier');
    assert.ok(!src.includes("createHmac('sha256', NYLO_TOKEN_SECRET)"), file + ' must not contain a legacy inline verifier');
    assert.ok(src.includes('createCorsMiddleware'), file + ' must use the shared fail-closed CORS middleware');
  }
});

test('concurrent verifications of the same token: exactly one succeeds', async () => {
  const token = signCrossDomainToken({ ...CLAIMS, sessionId: 'concurrent-1' }, SECRET);
  const results = await Promise.all(
    Array.from({ length: 8 }, () => verify({ token, domain: 'dest.example.com' }))
  );
  const successes = results.filter((r) => r.status === 200);
  const replays = results.filter((r) => r.status === 403 && r.body.error === 'TOKEN_REPLAYED');
  assert.strictEqual(successes.length, 1, 'exactly one 2xx');
  assert.strictEqual(replays.length, 7, 'all others rejected as replays');
});

test('production registration requires a durable replay store (fails loud at startup)', () => {
  assert.throws(
    () => registerTokenVerification(express(), { secret: SECRET, production: true }),
    /replayStore/
  );
  const durable = { consumeToken: async () => true };
  assert.doesNotThrow(
    () => registerTokenVerification(express(), { secret: SECRET, production: true, replayStore: durable })
  );
});
