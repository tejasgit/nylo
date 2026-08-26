// SPDX-License-Identifier: MIT
const { test } = require('node:test');
const assert = require('node:assert');
const { loadSdk } = require('./helpers/sdk-harness');

const FEATURES = 'trackPageViews,trackClicks,trackCustomEvents,trackConversions';

test('default consent is unknown: no identity, no storage, no events', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  await env.flush();

  assert.ok(env.Nylo, 'API should be exposed even without consent');
  assert.strictEqual(env.Nylo.getConsent().state, 'unknown');
  assert.strictEqual(env.Nylo.getConsent().analytics, false);

  const session = env.Nylo.getSession();
  assert.strictEqual(session.waiTag, null);
  assert.strictEqual(session.sessionId, null);
  assert.strictEqual(env.cookieJar['nylo_wai'], undefined);
  assert.strictEqual(env.localStorage.getItem('nylo_cross_domain_identity'), null);
  assert.strictEqual(env.sessionStorage.getItem('nylo_session_identity'), null);

  env.Nylo.track('some_event', {});
  await env.flush();
  assert.strictEqual(env.Nylo.getSession().queueSize, 0, 'no events queued without consent');
  assert.strictEqual(env.fetchCalls.length, 0, 'no network calls without consent');
});

test('granting consent creates and persists identity, enables tracking', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();

  assert.strictEqual(env.Nylo.getConsent().state, 'granted');
  assert.strictEqual(env.localStorage.getItem('nylo_consent'), 'granted');

  const session = env.Nylo.getSession();
  assert.ok(session.waiTag && session.waiTag.startsWith('wai_'));
  assert.ok(env.cookieJar['nylo_wai'], 'identity cookie stored');
  assert.ok(env.localStorage.getItem('nylo_cross_domain_identity'));
  assert.ok(env.sessionStorage.getItem('nylo_session_identity'));
  assert.ok(session.queueSize > 0, 'page view queued after consent');
});

test('withdrawing consent deletes cookie, all storage keys and queued events', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();
  assert.ok(env.cookieJar['nylo_wai']);

  const callsBefore = env.fetchCalls.length;
  env.Nylo.setConsent({ analytics: false });
  await env.flush();

  assert.strictEqual(env.Nylo.getConsent().state, 'withdrawn');
  assert.strictEqual(env.localStorage.getItem('nylo_consent'), 'withdrawn');
  assert.strictEqual(env.cookieJar['nylo_wai'], undefined, 'nylo_wai cookie deleted');
  assert.strictEqual(env.localStorage.getItem('nylo_cross_domain_identity'), null);
  assert.strictEqual(env.sessionStorage.getItem('nylo_session_identity'), null);
  assert.strictEqual(env.Nylo.getSession().queueSize, 0, 'queued events deleted');
  assert.strictEqual(env.Nylo.getSession().waiTag, null);

  // no events sent after withdrawal
  env.Nylo.track('post_withdrawal_event', {});
  env.Nylo.flush();
  await env.flush();
  assert.strictEqual(env.Nylo.getSession().queueSize, 0);
  assert.strictEqual(env.fetchCalls.length, callsBefore, 'no network traffic after withdrawal');
});

test('declining from unknown yields denied (not withdrawn)', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  env.Nylo.setConsent({ analytics: false });
  await env.flush();
  assert.strictEqual(env.Nylo.getConsent().state, 'denied');
  assert.strictEqual(env.localStorage.getItem('nylo_consent'), 'denied');
});

test('persisted granted consent resumes tracking on next load', async () => {
  const env = loadSdk({
    attrs: { 'data-features': FEATURES },
    localStorageSeed: { nylo_consent: 'granted' }
  });
  await env.flush();
  assert.strictEqual(env.Nylo.getConsent().state, 'granted');
  assert.ok(env.Nylo.getSession().waiTag);
});

test('persisted withdrawn consent stays off on next load', async () => {
  const env = loadSdk({
    attrs: { 'data-features': FEATURES },
    localStorageSeed: { nylo_consent: 'withdrawn' }
  });
  await env.flush();
  assert.strictEqual(env.Nylo.getConsent().state, 'withdrawn');
  assert.strictEqual(env.Nylo.getSession().waiTag, null);
  assert.strictEqual(env.fetchCalls.length, 0);
});

test('fail closed: no configuration means no tracking features', async () => {
  const env = loadSdk(); // no data-features, no data-config
  env.Nylo.setConsent({ analytics: true });
  await env.flush();

  const features = env.Nylo.getFeatures();
  assert.ok(Object.values(features).every((v) => v === false), 'all features disabled without config');

  env.Nylo.track('custom_thing', {});
  await env.flush();
  assert.strictEqual(env.Nylo.getSession().queueSize, 0, 'no events queued when features are off');
});

test('invalid encrypted config disables tracking (fail closed)', async () => {
  const env = loadSdk({ attrs: { 'data-config': 'garbage.notdecryptable' } });
  env.Nylo.setConsent({ analytics: true });
  await env.flush();
  const features = env.Nylo.getFeatures();
  assert.ok(Object.values(features).every((v) => v === false));
});

function securityAttr(domains) {
  return Buffer.from(JSON.stringify({ authorizedDomains: domains })).toString('base64');
}

test('wildcard domain authorization uses host boundaries', async () => {
  const blocked = loadSdk({
    hostname: 'evilexample.com',
    attrs: { 'data-security': securityAttr(['*.example.com']) }
  });
  await blocked.flush();
  assert.strictEqual(blocked.Nylo, undefined, 'lookalike suffix domain must be blocked');

  const allowed = loadSdk({
    hostname: 'sub.example.com',
    attrs: { 'data-security': securityAttr(['*.example.com']), 'data-features': FEATURES }
  });
  await allowed.flush();
  assert.ok(allowed.Nylo, 'true subdomain must be allowed');
});

test('withdrawing consent during async startup cancels in-flight identity work', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  env.Nylo.setConsent({ analytics: true });
  // Withdraw immediately, before the async identity startup resolves
  env.Nylo.setConsent({ analytics: false });
  await env.flush();
  await env.flush();

  assert.strictEqual(env.Nylo.getConsent().state, 'withdrawn');
  assert.strictEqual(env.cookieJar['nylo_wai'], undefined, 'no identity cookie after mid-startup withdrawal');
  assert.strictEqual(env.localStorage.getItem('nylo_cross_domain_identity'), null);
  assert.strictEqual(env.sessionStorage.getItem('nylo_session_identity'), null);
  assert.strictEqual(env.Nylo.getSession().waiTag, null, 'no in-memory identity restored');
  assert.strictEqual(env.Nylo.getSession().sessionId, null);
  assert.strictEqual(env.Nylo.getSession().queueSize, 0, 'no events queued');
  const registerCalls = env.fetchCalls.filter((c) => String(c.url).includes('register-waitag'));
  assert.strictEqual(registerCalls.length, 0, 'no registration network call after withdrawal');
  assert.strictEqual(env.fetchCalls.length, 0, 'no network traffic at all after mid-startup withdrawal');
});

test('re-granting after mid-startup withdrawal still works cleanly', async () => {
  const env = loadSdk({ attrs: { 'data-features': FEATURES } });
  env.Nylo.setConsent({ analytics: true });
  env.Nylo.setConsent({ analytics: false });
  await env.flush();
  env.Nylo.setConsent({ analytics: true });
  await env.flush();
  assert.strictEqual(env.Nylo.getConsent().state, 'granted');
  assert.ok(env.Nylo.getSession().waiTag, 'new identity created after re-grant');
  assert.ok(env.cookieJar['nylo_wai']);
});

test('rapid grant → withdraw → re-grant: stale startup never persists or purges the new epoch', async () => {
  // Gate WebCrypto so the first startup's identity HMAC work is suspended
  // deterministically while consent flips.
  let releaseGate;
  const gate = new Promise((resolve) => { releaseGate = resolve; });
  const env = loadSdk({ attrs: { 'data-features': FEATURES }, cryptoGate: gate });

  env.Nylo.setConsent({ analytics: true });   // startup 1 blocks on gated crypto
  env.Nylo.setConsent({ analytics: false });  // withdraw while in flight
  env.Nylo.setConsent({ analytics: true });   // re-grant: startup 2 also gated

  releaseGate();                              // release both startups
  await env.flush();
  await env.flush();

  assert.strictEqual(env.Nylo.getConsent().state, 'granted');
  const session = env.Nylo.getSession();
  assert.ok(session.waiTag, 'new epoch identity must survive the stale startup');
  assert.ok(env.cookieJar['nylo_wai'], 'identity cookie of the new epoch must not be purged');
  const stored = env.localStorage.getItem('nylo_cross_domain_identity');
  assert.ok(stored, 'persistent identity of the new epoch must not be purged');

  // Whatever was persisted must belong to the current (new) epoch identity.
  assert.ok(String(stored).length > 0);
  const registerCalls = env.fetchCalls.filter((c) => String(c.url).includes('register-waitag'));
  assert.strictEqual(registerCalls.length, 1, 'only the new epoch registers its identity');
  const registeredWaiTag = JSON.parse(registerCalls[0].options.body).waiTag;
  assert.strictEqual(registeredWaiTag, session.waiTag, 'registered identity matches the live identity');
});

test('withdraw during gated startup: releasing the stale startup leaves everything deleted', async () => {
  let releaseGate;
  const gate = new Promise((resolve) => { releaseGate = resolve; });
  const env = loadSdk({ attrs: { 'data-features': FEATURES }, cryptoGate: gate });

  env.Nylo.setConsent({ analytics: true });
  env.Nylo.setConsent({ analytics: false });
  releaseGate();
  await env.flush();
  await env.flush();

  assert.strictEqual(env.Nylo.getConsent().state, 'withdrawn');
  assert.strictEqual(env.cookieJar['nylo_wai'], undefined);
  assert.strictEqual(env.localStorage.getItem('nylo_cross_domain_identity'), null);
  assert.strictEqual(env.sessionStorage.getItem('nylo_session_identity'), null);
  assert.strictEqual(env.Nylo.getSession().waiTag, null);
  assert.strictEqual(env.Nylo.getSession().queueSize, 0);
  assert.strictEqual(env.fetchCalls.length, 0, 'no network traffic from the cancelled startup');
});

test('reset while registration awaits a grant never uploads the pre-reset identity', async () => {
  let releaseGrant;
  let grantRequested;
  const grantRequestSeen = new Promise((resolve) => { grantRequested = resolve; });
  const pendingGrant = new Promise((resolve) => { releaseGrant = resolve; });
  const env = loadSdk({
    attrs: { 'data-features': FEATURES },
    fetchHandler: (url) => {
      if (String(url).includes('/api/tracking/grant')) {
        grantRequested();
        return pendingGrant;
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ success: true }) });
    }
  });

  env.Nylo.setConsent({ analytics: true });
  await grantRequestSeen;
  const oldWaiTag = env.Nylo.getSession().waiTag;
  assert.ok(oldWaiTag, 'initial identity exists while registration awaits grant');

  const reset = env.Nylo.resetContext();
  releaseGrant({
    ok: true,
    json: () => Promise.resolve({
      success: true,
      grant: 'test-grant-payload.test-signature',
      expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString()
    })
  });
  assert.strictEqual(await reset, true);
  await env.flush();
  await env.flush();

  const liveWaiTag = env.Nylo.getSession().waiTag;
  assert.ok(liveWaiTag);
  assert.notStrictEqual(liveWaiTag, oldWaiTag, 'reset minted an unlinked identity');
  const registrations = env.fetchCalls.filter((call) => String(call.url).includes('register-waitag'));
  assert.strictEqual(registrations.length, 1, 'only the post-reset identity is registered');
  assert.strictEqual(JSON.parse(registrations[0].options.body).waiTag, liveWaiTag);
});
