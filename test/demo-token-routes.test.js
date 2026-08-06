// SPDX-License-Identifier: MIT
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const express = require('express');
const { registerTokenVerification } = require('../examples/demo-token-routes');
const { signCrossDomainToken } = require('../server/utils/token-core');

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

async function verify(body) {
  const res = await fetch(baseUrl + '/api/tracking/verify-cross-domain-token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return { status: res.status, body: await res.json() };
}

test('valid WTX-1 token verifies once, replay is rejected', async () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  const first = await verify({ token, domain: 'dest.example.com', customerId: '1' });
  assert.strictEqual(first.status, 200);
  assert.strictEqual(first.body.verified, true);
  assert.strictEqual(first.body.identity.waiTag, CLAIMS.waiTag);

  const replay = await verify({ token, domain: 'dest.example.com', customerId: '1' });
  assert.strictEqual(replay.status, 403);
  assert.strictEqual(replay.body.error, 'TOKEN_REPLAYED');
});

test('legacy-shaped token (no version/jti/iat/bindings) is rejected', async () => {
  const legacy = Buffer.from(JSON.stringify({
    waiTag: CLAIMS.waiTag, sessionId: CLAIMS.sessionId, userId: null,
    domain: 'dest.example.com', exp: Date.now() + 60000, sig: 'ab'.repeat(32)
  })).toString('base64');
  const r = await verify({ token: legacy, domain: 'dest.example.com', customerId: '1' });
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.body.error, 'MISSING_CLAIMS');
});

test('unsigned token is rejected', async () => {
  const unsigned = Buffer.from(JSON.stringify({
    ...CLAIMS, v: 1, jti: 'x'.repeat(16), iat: Date.now(), exp: Date.now() + 60000
  })).toString('base64');
  const r = await verify({ token: unsigned, domain: 'dest.example.com', customerId: '1' });
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.body.error, 'MISSING_SIGNATURE');
});

test('destination-domain binding is enforced at the endpoint', async () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  const r = await verify({ token, domain: 'other.example.com', customerId: '1' });
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.body.error, 'DOMAIN_MISMATCH');
});

test('tenant binding is enforced at the endpoint', async () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  const r = await verify({ token, domain: 'dest.example.com', customerId: '999' });
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.body.error, 'TENANT_MISMATCH');
});

test('malformed token gets 400', async () => {
  const r = await verify({ token: 'not-a-token', domain: 'dest.example.com', customerId: '1' });
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
    Array.from({ length: 8 }, () => verify({ token, domain: 'dest.example.com', customerId: '1' }))
  );
  const successes = results.filter((r) => r.status === 200);
  const replays = results.filter((r) => r.status === 403 && r.body.error === 'TOKEN_REPLAYED');
  assert.strictEqual(successes.length, 1, 'exactly one 2xx');
  assert.strictEqual(replays.length, 7, 'all others rejected as replays');
});
