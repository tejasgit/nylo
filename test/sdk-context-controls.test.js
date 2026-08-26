// SPDX-License-Identifier: MIT
/**
 * Claim-oriented conformance tests: time-limited identifiers with automatic
 * expiry when unused, user-facing context controls (view / reset / revoke),
 * digest-derived WaiTag format, and the transparent context-preservation
 * notification. See docs/patent/ for the claim mapping.
 */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadSdk } = require('./helpers/sdk-harness');

const FEATURES = 'trackPageViews,trackClicks,trackCustomEvents';

function daysAgoIso(days) {
  return new Date(Date.now() - days * 86400000).toISOString();
}

async function harvestIdentityRecord() {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();
  await env.flush();
  const raw = env.sessionStorage.getItem('nylo_session_identity');
  assert.ok(raw, 'expected a persisted identity to harvest');
  return JSON.parse(raw);
}

function loadSeededSdk(record, extraAttrs) {
  const env = loadSdk({
    attrs: Object.assign({ 'data-features': FEATURES }, extraAttrs || {}),
    localStorageSeed: { nylo_consent: 'granted' },
    sessionStorageSeed: { nylo_session_identity: JSON.stringify(record) }
  });
  const events = [];
  env.window.dispatchEvent = function(ev) { events.push(ev); return true; };
  env.contextEvents = events;
  return env;
}

test('WaiTag is an opaque hex digest (no embedded timestamp or domain marker)', async () => {
  const a = loadSdk({ attrs: { 'data-features': FEATURES } });
  a.Nylo.setConsent({ analytics: true });
  await a.flush();
  const tagA = a.Nylo.getSession().waiTag;
  assert.match(tagA, /^wai_[0-9a-f]{19}_[0-9a-f]{8}$/, 'digest-derived format');

  const b = loadSdk({ attrs: { 'data-features': FEATURES } });
  b.Nylo.setConsent({ analytics: true });
  await b.flush();
  assert.notStrictEqual(tagA, b.Nylo.getSession().waiTag, 'tags must be unpredictable per identity');
});

test('recently used identity is restored and the continuity notification fires', async () => {
  const record = await harvestIdentityRecord();
  record.lastUsedAt = daysAgoIso(1);
  const seededLastUsed = record.lastUsedAt;

  const env = loadSeededSdk(record);
  await env.flush();
  await env.flush();

  assert.strictEqual(env.Nylo.getSession().waiTag, record.waiTag, 'identity restored');

  const preserved = env.contextEvents.filter((e) => e.type === 'nyloContextPreserved');
  assert.strictEqual(preserved.length, 1, 'exactly one continuity notification');
  assert.strictEqual(preserved[0].detail.source, 'first_party_storage');
  assert.strictEqual(preserved[0].detail.waiTag, record.waiTag);

  // Active use slides the retention window forward.
  const stored = JSON.parse(env.sessionStorage.getItem('nylo_session_identity'));
  assert.ok(stored.lastUsedAt > seededLastUsed, 'lastUsedAt touched on active use');
});

test('identity unused past the default 30-day window expires into a fresh identity', async () => {
  const record = await harvestIdentityRecord();
  record.createdAt = daysAgoIso(31);
  record.lastUsedAt = daysAgoIso(31);

  const env = loadSeededSdk(record);
  await env.flush();
  await env.flush();

  const session = env.Nylo.getSession();
  assert.ok(session.waiTag, 'a fresh identity is minted');
  assert.notStrictEqual(session.waiTag, record.waiTag, 'expired identifier must not be resurrected');
  assert.strictEqual(
    env.contextEvents.filter((e) => e.type === 'nyloContextPreserved').length,
    0,
    'no continuity notification for a fresh identity'
  );
});

test('identity expires absolutely after max age even when recently used', async () => {
  const record = await harvestIdentityRecord();
  record.createdAt = daysAgoIso(181);
  record.lastUsedAt = daysAgoIso(1);

  const env = loadSeededSdk(record);
  await env.flush();
  await env.flush();

  assert.notStrictEqual(env.Nylo.getSession().waiTag, record.waiTag, 'absolute max age enforced');
});

test('legacy record without timestamps fails closed into a fresh identity', async () => {
  const record = await harvestIdentityRecord();
  delete record.createdAt;
  delete record.lastUsedAt;
  delete record.syncedAt;

  const env = loadSeededSdk(record);
  await env.flush();
  await env.flush();

  assert.ok(env.Nylo.getSession().waiTag);
  assert.notStrictEqual(env.Nylo.getSession().waiTag, record.waiTag, 'timestampless record must not be trusted');
});

test('unused-expiry window is configurable via data attribute', async () => {
  const record = await harvestIdentityRecord();
  record.lastUsedAt = daysAgoIso(2);

  // 2 days unused: inside the default window, outside a 1-day window.
  const env = loadSeededSdk(record, { 'data-identity-unused-expiry-days': '1' });
  await env.flush();
  await env.flush();

  assert.notStrictEqual(env.Nylo.getSession().waiTag, record.waiTag, 'shortened window enforced');
  const view = await env.Nylo.getStoredContext();
  assert.strictEqual(view.retentionPolicy.unusedExpiryDays, 1);
});

test('invalid retention attributes keep the privacy-preserving defaults', async () => {
  const env = loadSdk({
    attrs: {
      'data-features': FEATURES,
      'data-identity-unused-expiry-days': '0',
      'data-identity-max-age-days': 'abc'
    }
  });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();
  await env.flush();

  const view = await env.Nylo.getStoredContext();
  assert.ok(view, 'context view available');
  assert.strictEqual(view.retentionPolicy.unusedExpiryDays, 30);
  assert.strictEqual(view.retentionPolicy.maxAgeDays, 180);
});

test('getStoredContext exposes stored data + expiry without extending retention', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();
  await env.flush();

  const before = env.sessionStorage.getItem('nylo_session_identity');
  const view = await env.Nylo.getStoredContext();

  assert.ok(view.waiTag && view.waiTag.startsWith('wai_'));
  assert.strictEqual(view.waiTag, env.Nylo.getSession().waiTag);
  assert.ok(view.createdAt, 'creation time disclosed');
  assert.ok(view.lastUsedAt, 'last use disclosed');
  assert.ok(view.expiresAt, 'expiry time disclosed');
  assert.ok(new Date(view.expiresAt).getTime() > Date.now(), 'expiry is in the future');
  assert.strictEqual(view.retentionPolicy.maxAgeDays, 180);
  assert.strictEqual(view.retentionPolicy.unusedExpiryDays, 30);

  // Viewing is passive: it must not rewrite the stored record.
  assert.strictEqual(env.sessionStorage.getItem('nylo_session_identity'), before);
});

test('getStoredContext returns null when nothing is stored', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  await env.flush();
  assert.strictEqual(await env.Nylo.getStoredContext(), null);
});

test('resetContext deletes the old identifier and mints an unlinked one', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();
  await env.flush();
  const oldTag = env.Nylo.getSession().waiTag;
  assert.ok(oldTag);

  const result = await env.Nylo.resetContext();
  await env.flush();

  assert.strictEqual(result, true);
  const newTag = env.Nylo.getSession().waiTag;
  assert.ok(newTag, 'fresh identity after reset');
  assert.notStrictEqual(newTag, oldTag, 'new identifier has no link to the old one');

  // The old identifier must be gone from every storage layer.
  const layers = [
    env.cookieJar['nylo_wai'] ? Buffer.from(env.cookieJar['nylo_wai'], 'base64').toString() : '',
    env.localStorage.getItem('nylo_cross_domain_identity') || '',
    env.sessionStorage.getItem('nylo_session_identity') || ''
  ];
  for (const layer of layers) {
    assert.ok(!layer.includes(oldTag), 'old identifier purged from storage');
  }
});

test('resetContext without active tracking deletes without minting', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  await env.flush();
  const result = await env.Nylo.resetContext();
  assert.strictEqual(result, true);
  assert.strictEqual(env.Nylo.getSession().waiTag, null);
  assert.strictEqual(env.sessionStorage.getItem('nylo_session_identity'), null);
});

test('revokeContext withdraws consent and purges identity, storage and queue', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();
  assert.ok(env.Nylo.getSession().waiTag);

  const callsBefore = env.fetchCalls.length;
  const result = env.Nylo.revokeContext();
  await env.flush();

  assert.strictEqual(result, true);
  assert.strictEqual(env.Nylo.getConsent().state, 'withdrawn');
  assert.strictEqual(env.Nylo.getSession().waiTag, null);
  assert.strictEqual(env.cookieJar['nylo_wai'], undefined);
  assert.strictEqual(env.localStorage.getItem('nylo_cross_domain_identity'), null);
  assert.strictEqual(env.sessionStorage.getItem('nylo_session_identity'), null);
  assert.strictEqual(env.Nylo.getSession().queueSize, 0);

  env.Nylo.track('after_revoke', {});
  await env.flush();
  assert.strictEqual(env.fetchCalls.length, callsBefore, 'no network traffic after revoke');
});
