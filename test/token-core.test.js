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

function decodeEnvelope(token) {
  return JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
}

function encodeEnvelope(envelope) {
  return Buffer.from(JSON.stringify(envelope)).toString('base64');
}

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
  assert.strictEqual(p.waiTag, CLAIMS.waiTag);
});

test('signing requires tenant, source and destination', () => {
  for (const missing of ['tenantId', 'sourceDomain', 'destinationDomain', 'waiTag', 'sessionId']) {
    const claims = { ...CLAIMS };
    delete claims[missing];
    assert.throws(() => signCrossDomainToken(claims, SECRET), new RegExp(missing));
  }
});

test('token is encrypted: no identity or context readable in transit', () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  const decoded = Buffer.from(token, 'base64').toString('utf-8');
  // The envelope may expose routing metadata (tenant, destination) needed
  // for key derivation — but never identity or source context.
  assert.ok(!decoded.includes(CLAIMS.waiTag), 'waiTag must not appear in cleartext');
  assert.ok(!decoded.includes(CLAIMS.sessionId), 'sessionId must not appear in cleartext');
  assert.ok(!decoded.includes(CLAIMS.sourceDomain), 'sourceDomain must not appear in cleartext');
  assert.ok(!decoded.includes('"waiTag"'), 'no identity field names in cleartext');
  const envelope = decodeEnvelope(token);
  assert.deepStrictEqual(Object.keys(envelope).sort(), ['ct', 'dst', 'iv', 'tag', 'tid'].concat(['v']).sort());
});

test('tampered ciphertext is rejected', () => {
  const token = signCrossDomainToken(CLAIMS, SECRET);
  const envelope = decodeEnvelope(token);
  const ct = Buffer.from(envelope.ct, 'base64');
  ct[0] = ct[0] ^ 0xff;
  envelope.ct = ct.toString('base64');
  assert.strictEqual(verifyCrossDomainToken(encodeEnvelope(envelope), SECRET).error, 'INVALID_SIGNATURE');
});

test('spoofed envelope routing cannot redirect a token', () => {
  // Attacker rewrites the cleartext destination to make a token look like
  // it was minted for another domain: key derivation + AAD binding fail.
  const token = signCrossDomainToken(CLAIMS, SECRET);
  const envelope = decodeEnvelope(token);
  envelope.dst = 'attacker.example.com';
  const forged = encodeEnvelope(envelope);
  assert.strictEqual(
    verifyCrossDomainToken(forged, SECRET, { expectedDestination: 'attacker.example.com' }).error,
    'INVALID_SIGNATURE'
  );
});

test('tokens for different destinations use different keys (ciphertext swap fails)', () => {
  const tokenA = signCrossDomainToken(CLAIMS, SECRET);
  const tokenB = signCrossDomainToken({ ...CLAIMS, destinationDomain: 'other.example.com' }, SECRET);
  const envA = decodeEnvelope(tokenA);
  const envB = decodeEnvelope(tokenB);
  // Graft A's encrypted payload into B's envelope: decryption keys differ.
  const graft = { ...envB, ct: envA.ct, iv: envA.iv, tag: envA.tag };
  assert.strictEqual(verifyCrossDomainToken(encodeEnvelope(graft), SECRET).error, 'INVALID_SIGNATURE');
});

test('envelope without auth tag is rejected', () => {
  const envelope = decodeEnvelope(signCrossDomainToken(CLAIMS, SECRET));
  delete envelope.tag;
  assert.strictEqual(verifyCrossDomainToken(encodeEnvelope(envelope), SECRET).error, 'MISSING_SIGNATURE');
});

test('malformed token is rejected', () => {
  assert.strictEqual(verifyCrossDomainToken('not-base64-json', SECRET).error, 'MALFORMED_TOKEN');
});

test('oversized and malformed encrypted envelopes are rejected before decryption', () => {
  assert.strictEqual(verifyCrossDomainToken('A'.repeat(16 * 1024 + 1), SECRET).error, 'MALFORMED_TOKEN');

  const envelope = decodeEnvelope(signCrossDomainToken(CLAIMS, SECRET));
  envelope.iv = Buffer.alloc(1024).toString('base64');
  assert.strictEqual(verifyCrossDomainToken(encodeEnvelope(envelope), SECRET).error, 'MALFORMED_TOKEN');

  const badTag = decodeEnvelope(signCrossDomainToken(CLAIMS, SECRET));
  badTag.tag = Buffer.alloc(15).toString('base64');
  assert.strictEqual(verifyCrossDomainToken(encodeEnvelope(badTag), SECRET).error, 'MALFORMED_TOKEN');
});

test('legacy v1 signed-cleartext token is rejected', () => {
  const legacyPayload = {
    v: 1, jti: 'x'.repeat(32), iat: Date.now(), exp: Date.now() + 60000,
    tenantId: '42', sourceDomain: CLAIMS.sourceDomain, destinationDomain: CLAIMS.destinationDomain,
    waiTag: CLAIMS.waiTag, sessionId: CLAIMS.sessionId, userId: null, sig: 'ab'.repeat(32)
  };
  const legacy = Buffer.from(JSON.stringify(legacyPayload)).toString('base64');
  assert.strictEqual(verifyCrossDomainToken(legacy, SECRET).error, 'UNSUPPORTED_VERSION');
});

test('unversioned legacy token is rejected', () => {
  const legacy = Buffer.from(JSON.stringify({
    waiTag: CLAIMS.waiTag, sessionId: CLAIMS.sessionId, userId: null,
    domain: 'dest.example.com', exp: Date.now() + 60000, sig: 'ab'.repeat(32)
  })).toString('base64');
  assert.strictEqual(verifyCrossDomainToken(legacy, SECRET).error, 'UNSUPPORTED_VERSION');
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
