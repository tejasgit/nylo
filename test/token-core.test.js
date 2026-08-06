// SPDX-License-Identifier: MIT
const { test } = require('node:test');
const assert = require('node:assert');
const {
  TOKEN_VERSION,
  signCrossDomainToken,
  verifyCrossDomainToken,
  hashToken,
  createInMemoryReplayStore
} = require('../server/utils/token-core');

const SECRET = 'test-secret';
const CLAIMS = {
  tenantId: 42,
  sourceDomain: 'source.example.com',
  destinationDomain: 'dest.example.com',
  waiTag: 'wai_abc123def456_xyz',
  sessionId: 'session-1'
};

test('sign + verify roundtrip includes version, jti, iat, exp and bindings', () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  const result = verifyCrossDomainToken(token, SECRET);
  assert.ok(result.valid);
  const p = result.payload;
  assert.strictEqual(p.v, TOKEN_VERSION);
  assert.ok(typeof p.jti === 'string' && p.jti.length >= 16);
  assert.ok(typeof p.iat === 'number');
  assert.ok(p.exp > p.iat);
  assert.strictEqual(p.tenantId, '42');
  assert.strictEqual(p.sourceDomain, 'source.example.com');
  assert.strictEqual(p.destinationDomain, 'dest.example.com');
});

test('signing requires tenant, source and destination', () => {
  for (const missing of ['tenantId', 'sourceDomain', 'destinationDomain', 'waiTag', 'sessionId']) {
    const claims = { ...CLAIMS };
    delete claims[missing];
    assert.throws(() => signCrossDomainToken(claims, SECRET), new RegExp(missing));
  }
});

test('tampered payload is rejected', () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  const parsed = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
  parsed.waiTag = 'wai_forged000000_zzz';
  const forged = Buffer.from(JSON.stringify(parsed)).toString('base64');
  assert.strictEqual(verifyCrossDomainToken(forged, SECRET).error, 'INVALID_SIGNATURE');
});

test('unsigned token is rejected', () => {
  const unsigned = Buffer.from(JSON.stringify({ ...CLAIMS, v: 1, jti: 'x', iat: Date.now(), exp: Date.now() + 1000 })).toString('base64');
  assert.strictEqual(verifyCrossDomainToken(unsigned, SECRET).error, 'MISSING_SIGNATURE');
});

test('malformed token is rejected', () => {
  assert.strictEqual(verifyCrossDomainToken('not-base64-json', SECRET).error, 'MALFORMED_TOKEN');
});

test('legacy token without new claims is rejected', () => {
  // old format: no v/jti/iat/tenantId/sourceDomain
  const legacy = Buffer.from(JSON.stringify({
    waiTag: CLAIMS.waiTag, sessionId: CLAIMS.sessionId, userId: null,
    domain: 'dest.example.com', exp: Date.now() + 60000, sig: 'ab'.repeat(32)
  })).toString('base64');
  assert.strictEqual(verifyCrossDomainToken(legacy, SECRET).error, 'MISSING_CLAIMS');
});

test('expired token is rejected', () => {
  const token = signCrossDomainToken(CLAIMS, SECRET, { now: Date.now() - 10 * 60 * 1000 });
  assert.strictEqual(verifyCrossDomainToken(token, SECRET).error, 'TOKEN_EXPIRED');
});

test('future-dated token is rejected', () => {
  const token = signCrossDomainToken(CLAIMS, SECRET, { now: Date.now() + 10 * 60 * 1000 });
  assert.strictEqual(verifyCrossDomainToken(token, SECRET).error, 'INVALID_IAT');
});

test('destination domain binding is enforced', () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  assert.ok(verifyCrossDomainToken(token, SECRET, { expectedDestination: 'dest.example.com' }).valid);
  assert.strictEqual(
    verifyCrossDomainToken(token, SECRET, { expectedDestination: 'other.example.com' }).error,
    'DOMAIN_MISMATCH'
  );
});

test('tenant binding is enforced', () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  assert.ok(verifyCrossDomainToken(token, SECRET, { expectedTenant: 42 }).valid);
  assert.strictEqual(verifyCrossDomainToken(token, SECRET, { expectedTenant: 7 }).error, 'TENANT_MISMATCH');
});

test('wrong secret is rejected', () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  assert.strictEqual(verifyCrossDomainToken(token, 'other-secret').error, 'INVALID_SIGNATURE');
});

test('replay store detects reuse', async () => {
  const store = createInMemoryReplayStore();
  const token = signCrossDomainToken(CLAIMS, SECRET);
  const hash = hashToken(token);
  assert.strictEqual(await store.isTokenUsed(hash), false);
  await store.markTokenUsed(hash, 60000);
  assert.strictEqual(await store.isTokenUsed(hash), true);
});

test('replay store consumeToken is atomic: only one concurrent consumer wins', async () => {
  const store = createInMemoryReplayStore();
  const hash = hashToken(signCrossDomainToken(CLAIMS, SECRET));
  const results = await Promise.all(
    Array.from({ length: 10 }, () => store.consumeToken(hash, 60000))
  );
  assert.strictEqual(results.filter(Boolean).length, 1, 'exactly one consumer must win');
});
