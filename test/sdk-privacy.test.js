// SPDX-License-Identifier: MIT
/**
 * SDK privacy + authorization contract tests:
 *  - outbound requests carry NO fingerprint-capable fields and NO
 *    browser-asserted tenant identity (no customerId, no identity headers);
 *  - URLs leave the browser stripped of query strings and fragments;
 *  - writes are authorized by a server-issued write grant;
 *  - consent withdrawal aborts in-flight requests and cancels retries.
 */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadSdk } = require('./helpers/sdk-harness');

const FEATURES = 'trackPageViews,trackClicks,trackCustomEvents,trackConversions';

// Substrings that must never appear as keys in any outbound payload.
const FORBIDDEN_KEY_FRAGMENTS = [
  'useragent', 'user_agent', 'language', 'timezone', 'screenwidth',
  'screenheight', 'screensize', 'viewport', 'colordepth', 'pixelratio',
  'platform', 'hardwareconcurrency', 'devicememory', 'clickx', 'clicky',
  'pagex', 'pagey', 'screenx', 'screeny', 'maxtouchpoints', 'donottrack'
];

function collectKeysDeep(value, out) {
  if (!value || typeof value !== 'object') return out;
  if (Array.isArray(value)) {
    for (const item of value) collectKeysDeep(item, out);
    return out;
  }
  for (const [k, v] of Object.entries(value)) {
    out.push(k.toLowerCase());
    collectKeysDeep(v, out);
    // metadata may be a serialized JSON string — inspect inside it too.
    if (typeof v === 'string' && v.startsWith('{')) {
      try { collectKeysDeep(JSON.parse(v), out); } catch { /* not JSON */ }
    }
  }
  return out;
}

test('outbound batches carry no fingerprint fields, no tenant identity, sanitized URLs, and a write grant', async () => {
  const env = loadSdk({
    attrs: { 'data-features': FEATURES },
    search: '?email=user@example.com&token=supersecret',
    hash: '#section2'
  });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();

  env.Nylo.track('custom_event', { label: 'privacy-check' });
  env.Nylo.flush();
  await env.flush();
  await env.flush();

  const trackCalls = env.fetchCalls.filter((c) => String(c.url).endsWith('/api/track'));
  assert.ok(trackCalls.length >= 1, 'batch was sent');
  const call = trackCalls[trackCalls.length - 1];

  // --- Headers: grant present, identity/tenant headers gone ---
  const headers = call.options.headers || {};
  const headerNames = Object.keys(headers).map((h) => h.toLowerCase());
  assert.ok(headerNames.includes('x-nylo-grant'), 'write grant header attached');
  for (const banned of ['x-customer-id', 'x-session-id', 'x-waitag', 'x-api-key']) {
    assert.strictEqual(headerNames.includes(banned), false, banned + ' must not be sent');
  }

  // --- Body: no fingerprint keys, no customerId anywhere ---
  const body = JSON.parse(call.options.body);
  const keys = collectKeysDeep(body, []);
  for (const fragment of FORBIDDEN_KEY_FRAGMENTS) {
    assert.strictEqual(
      keys.some((k) => k.includes(fragment)), false,
      'outbound payload must not contain key fragment: ' + fragment
    );
  }
  assert.strictEqual(keys.includes('customerid'), false, 'no browser-asserted tenant identity');

  // --- URLs: query string and fragment stripped ---
  for (const event of body.events) {
    if (event.url) {
      assert.strictEqual(event.url, 'https://example.com/', 'url reduced to origin+path');
      assert.ok(!String(event.url).includes('supersecret'));
    }
  }

  // --- Registration: same rules ---
  const registerCalls = env.fetchCalls.filter((c) => String(c.url).includes('register-waitag'));
  assert.strictEqual(registerCalls.length, 1, 'identity registered once');
  const regBody = JSON.parse(registerCalls[0].options.body);
  assert.strictEqual('customerId' in regBody, false, 'registration carries no tenant assertion');
  assert.strictEqual('userAgent' in regBody, false, 'registration carries no user agent');
  const regHeaders = Object.keys(registerCalls[0].options.headers || {}).map((h) => h.toLowerCase());
  assert.ok(regHeaders.includes('x-nylo-grant'), 'registration is grant-authorized');
});

test('write grant is requested before batches and cached for subsequent sends', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();

  env.Nylo.track('custom_event', { n: 1 });
  env.Nylo.flush();
  await env.flush();
  env.Nylo.track('custom_event', { n: 2 });
  env.Nylo.flush();
  await env.flush();

  const grantCalls = env.fetchCalls.filter((c) => String(c.url).includes('/api/tracking/grant'));
  const trackCalls = env.fetchCalls.filter((c) => String(c.url).endsWith('/api/track'));
  assert.ok(trackCalls.length >= 2, 'two batches sent');
  assert.strictEqual(grantCalls.length, 1, 'grant fetched once and cached');
  const grantBody = JSON.parse(grantCalls[0].options.body);
  assert.deepStrictEqual(Object.keys(grantBody).sort(), ['domain'], 'grant request sends only the page domain');
});

test('withdrawing consent aborts in-flight batch requests', async () => {
  const env = loadSdk({
    attrs: { 'data-features': FEATURES },
    fetchHandler: (url) => {
      const u = String(url);
      if (u.includes('/api/tracking/grant')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            success: true,
            grant: 'g.sig',
            expiresAt: new Date(Date.now() + 600000).toISOString()
          })
        });
      }
      if (u.includes('register-waitag')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ success: true }) });
      }
      // /api/track hangs forever — simulates a slow network write.
      return new Promise(() => {});
    }
  });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();

  env.Nylo.track('custom_event', {});
  env.Nylo.flush();
  await env.flush();

  const trackCall = env.fetchCalls.find((c) => String(c.url).endsWith('/api/track'));
  assert.ok(trackCall, 'batch request was issued');
  assert.ok(trackCall.options.signal, 'batch request carries an abort signal');
  assert.strictEqual(trackCall.options.signal.aborted, false);

  env.Nylo.setConsent({ analytics: false });
  await env.flush();

  assert.strictEqual(trackCall.options.signal.aborted, true, 'in-flight request aborted on withdrawal');
  assert.strictEqual(env.Nylo.getSession().queueSize, 0);
});

test('withdrawing consent cancels scheduled retries — no resurrection after failure', async () => {
  const env = loadSdk({
    attrs: { 'data-features': FEATURES },
    fetchHandler: (url) => {
      const u = String(url);
      if (u.includes('/api/tracking/grant')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            success: true,
            grant: 'g.sig',
            expiresAt: new Date(Date.now() + 600000).toISOString()
          })
        });
      }
      if (u.includes('register-waitag')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ success: true }) });
      }
      return Promise.reject(new Error('network down'));
    }
  });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();

  env.Nylo.track('custom_event', {});
  env.Nylo.flush();
  await env.flush();

  const trackCallsBefore = env.fetchCalls.filter((c) => String(c.url).endsWith('/api/track')).length;
  assert.ok(trackCallsBefore >= 1, 'failed batch attempt happened');

  env.Nylo.setConsent({ analytics: false });
  await env.flush();

  // Wait past the first retry backoff (1s). A cancelled retry must not fire.
  await new Promise((r) => setTimeout(r, 1300));

  const trackCallsAfter = env.fetchCalls.filter((c) => String(c.url).endsWith('/api/track')).length;
  assert.strictEqual(trackCallsAfter, trackCallsBefore, 'no retry traffic after withdrawal');
  assert.strictEqual(env.Nylo.getSession().queueSize, 0, 'retry queue purged');
});

test('custom event metadata is stripped client-side: fingerprint keys and URL queries never leave the browser', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();

  env.Nylo.track('custom_event', {
    userAgent: 'Mozilla/5.0',
    'user-agent': 'Mozilla/5.0 alias',
    deviceCapabilities: { webglRenderer: 'GPU' },
    clientX: 10,
    productUrl: 'https://shop.example.com/item?id=9&email=a@b.com#frag',
    keep: 'me'
  });
  env.Nylo.flush();
  await env.flush();
  await env.flush();

  const trackCalls = env.fetchCalls.filter((c) => String(c.url).endsWith('/api/track'));
  assert.ok(trackCalls.length >= 1, 'batch was sent');
  const raw = String(trackCalls[trackCalls.length - 1].options.body).toLowerCase();
  for (const banned of ['useragent', 'user-agent', 'user_agent', 'capabilit', 'webgl', 'clientx', 'mozilla']) {
    assert.strictEqual(raw.includes(banned), false, 'outbound body must not contain: ' + banned);
  }
  assert.ok(raw.includes('keep'), 'legitimate metadata keys survive');
  assert.ok(raw.includes('/item'), 'URL path survives in metadata values');
  assert.strictEqual(raw.includes('email='), false, 'URL query stripped from metadata values');
  assert.strictEqual(raw.includes('frag'), false, 'URL fragment stripped from metadata values');
});

test('tracking fails closed when secure randomness is unavailable: no identity, no writes', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES }, noCrypto: true });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();
  await env.flush();

  env.Nylo.track('custom_event', { probe: 1 });
  env.Nylo.flush();
  await env.flush();
  await env.flush();

  const writeCalls = env.fetchCalls.filter((c) =>
    String(c.url).endsWith('/api/track') || String(c.url).includes('register-waitag'));
  assert.strictEqual(writeCalls.length, 0, 'no event or identity writes without secure randomness');
  const session = env.Nylo.getSession ? env.Nylo.getSession() : {};
  assert.ok(!session.sessionId, 'no predictable fallback session id');
  assert.ok(!session.waiTag, 'no waiTag without secure randomness');
});
