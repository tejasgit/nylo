// SPDX-License-Identifier: MIT
/**
 * Unit tests for write grants: server-signed, short-lived, tenant/domain/
 * scope-bound browser write authorization.
 */
const { test } = require('node:test');
const assert = require('node:assert');

const {
  signWriteGrant,
  verifyWriteGrant,
  DEFAULT_GRANT_TTL_MS
} = require('../server/utils/write-grant');

const SECRET = 'write-grant-test-secret';
const CLAIMS = { tenantId: '42', domain: 'app.example.com', scopes: ['ingest', 'register'] };

test('sign → verify roundtrip preserves tenant, domain and scopes', () => {
  const grant = signWriteGrant(CLAIMS, SECRET);
  const result = verifyWriteGrant(grant, SECRET, { requiredScope: 'ingest' });
  assert.strictEqual(result.valid, true, result.error);
  assert.strictEqual(result.payload.tenantId, '42');
  assert.strictEqual(result.payload.domain, 'app.example.com');
  assert.deepStrictEqual(result.payload.scopes, ['ingest', 'register']);
  assert.ok(result.payload.exp - result.payload.iat === DEFAULT_GRANT_TTL_MS);
});

test('tampered payload or signature is rejected', () => {
  const grant = signWriteGrant(CLAIMS, SECRET);
  const [payload, sig] = grant.split('.');

  // Flip a character in the middle of the signature. (Never the last one:
  // the final base64url char carries only 2 significant bits, so a last-char
  // swap can decode to the identical signature bytes and "verify" fine.)
  const mid = 10;
  const flipped = sig[mid] === 'A' ? 'B' : 'A';
  const badSig = payload + '.' + (sig.slice(0, mid) + flipped + sig.slice(mid + 1));
  assert.strictEqual(verifyWriteGrant(badSig, SECRET, {}).valid, false);

  // Swap in a forged payload claiming another tenant
  const forged = Buffer.from(JSON.stringify({
    gv: 1, jti: 'x', iat: Date.now(), exp: Date.now() + 60000,
    tenantId: '999', domain: 'app.example.com', scopes: ['ingest']
  })).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const forgedGrant = forged + '.' + sig;
  const result = verifyWriteGrant(forgedGrant, SECRET, {});
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'BAD_SIGNATURE');
});

test('verification with the wrong secret fails', () => {
  const grant = signWriteGrant(CLAIMS, SECRET);
  assert.strictEqual(verifyWriteGrant(grant, 'other-secret', {}).valid, false);
});

test('expired grants are rejected', () => {
  const grant = signWriteGrant(CLAIMS, SECRET, { now: Date.now() - DEFAULT_GRANT_TTL_MS - 120000 });
  const result = verifyWriteGrant(grant, SECRET, {});
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'EXPIRED');
});

test('grants from the future (beyond clock skew) are rejected', () => {
  const grant = signWriteGrant(CLAIMS, SECRET, { now: Date.now() + 10 * 60 * 1000 });
  const result = verifyWriteGrant(grant, SECRET, {});
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'NOT_YET_VALID');
});

test('domain binding: a grant for one domain is invalid for another', () => {
  const grant = signWriteGrant(CLAIMS, SECRET);
  const result = verifyWriteGrant(grant, SECRET, { expectedDomain: 'other.example.com' });
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'DOMAIN_MISMATCH');
});

test('scope binding: a grant without the required scope is rejected', () => {
  const grant = signWriteGrant({ tenantId: '1', domain: 'a.example.com', scopes: ['register'] }, SECRET);
  const result = verifyWriteGrant(grant, SECRET, { requiredScope: 'ingest' });
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'SCOPE_MISSING');
});

test('malformed inputs never throw and are rejected', () => {
  for (const bad of ['', 'garbage', 'a.b.c', 'onlypayload', '.', null, undefined, 42]) {
    const result = verifyWriteGrant(bad, SECRET, {});
    assert.strictEqual(result.valid, false, 'must reject: ' + String(bad));
  }
});

test('missing secret fails closed', () => {
  const grant = signWriteGrant(CLAIMS, SECRET);
  const result = verifyWriteGrant(grant, '', {});
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, 'NO_SECRET');
  assert.throws(() => signWriteGrant(CLAIMS, ''), /secret/i);
});

test('signing validates claims: tenant, domain and known scopes are required', () => {
  assert.throws(() => signWriteGrant({ domain: 'a.com', scopes: ['ingest'] }, SECRET), /tenantId/);
  assert.throws(() => signWriteGrant({ tenantId: '1', scopes: ['ingest'] }, SECRET), /domain/);
  assert.throws(() => signWriteGrant({ tenantId: '1', domain: 'a.com', scopes: [] }, SECRET), /scopes/);
  assert.throws(() => signWriteGrant({ tenantId: '1', domain: 'a.com', scopes: ['admin'] }, SECRET), /scopes/);
});
