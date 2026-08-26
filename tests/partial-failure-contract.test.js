// SPDX-License-Identifier: MIT
/**
 * SDK-to-server partial-failure contract tests.
 *
 * Runs an express server backed by the shared demo ingestion handler with a
 * storage layer that fails transiently, and drives the wire protocol exactly
 * as the SDK does: versioned envelope out, per-event results in, retry of
 * failed events with the SAME eventIds (idempotent redelivery).
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const express = require('express');

const { createTrackHandler } = require('../examples/track-ingestion');
const { buildEnvelope } = require('../shared/event-envelope');
const { signWriteGrant } = require('../server/utils/write-grant');

const SECRET = 'partial-fail-test-secret';
// Ingestion is grant-authorized: the tenant comes from the signed grant.
const GRANT = signWriteGrant(
  { tenantId: 'cust-1', domain: 'demo.example.com', scopes: ['ingest'] },
  SECRET
);

function makeEventId() {
  return crypto.randomBytes(16).toString('hex');
}

function makeClientEvent(overrides) {
  return Object.assign({
    eventId: makeEventId(),
    sessionId: 'sess_partialfail',
    domain: 'demo.example.com',
    customerId: 'cust-1',
    eventType: 'page_view',
    timestamp: '2026-08-06T10:00:00.000Z',
    url: 'https://demo.example.com/'
  }, overrides || {});
}

let server;
let base;
const stored = [];
// eventIds that should fail storage exactly once (transient failure)
const failOnce = new Set();

test.before(async () => {
  const app = express();
  app.use(express.json());
  app.post('/api/track', createTrackHandler(async (event) => {
    if (failOnce.has(event.eventId)) {
      failOnce.delete(event.eventId);
      throw new Error('simulated transient storage failure');
    }
    stored.push(event);
  }, { grantSecret: SECRET }));
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => server && server.close());

async function postEnvelope(envelope) {
  const res = await fetch(`${base}/api/track`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Nylo-Grant': GRANT },
    body: JSON.stringify(envelope)
  });
  return { status: res.status, json: await res.json() };
}

test('partial storage failure returns per-event details, and SDK-style retry of failed events succeeds', async () => {
  const good = makeClientEvent();
  const flaky = makeClientEvent({ eventType: 'click' });
  failOnce.add(flaky.eventId);

  // First delivery: one stored, one storage_failed — HTTP 200, per-event detail
  const first = await postEnvelope(buildEnvelope([good, flaky]));
  assert.strictEqual(first.status, 200);
  assert.strictEqual(first.json.eventsProcessed, 1);
  assert.deepStrictEqual(
    first.json.results.map(r => r.status),
    ['stored', 'error']
  );
  assert.strictEqual(first.json.results[1].reason, 'storage_failed');

  // SDK behavior: requeue only the failed events (same eventId) and resend.
  const failedEvents = first.json.results
    .filter(r => r.status === 'error')
    .map(r => [good, flaky][r.index]);
  assert.deepStrictEqual(failedEvents, [flaky]);

  // Retry must be STORED, not reported as duplicate — dedup is committed
  // only after successful persistence.
  const retry = await postEnvelope(buildEnvelope(failedEvents));
  assert.strictEqual(retry.status, 200);
  assert.strictEqual(retry.json.results[0].status, 'stored');

  // A second redelivery of the now-stored event IS deduplicated.
  const redelivery = await postEnvelope(buildEnvelope([flaky]));
  assert.strictEqual(redelivery.json.results[0].status, 'duplicate');

  // Exactly one copy of each event stored.
  const ids = stored.map(e => e.eventId);
  assert.strictEqual(ids.filter(id => id === good.eventId).length, 1);
  assert.strictEqual(ids.filter(id => id === flaky.eventId).length, 1);
});

test('SDK sendBatch consumes per-event results: retries storage errors, drops rejected events', async () => {
  // Drive the actual src/nylo.js sendBatch logic in a stubbed browser
  // environment against contract-shaped responses.
  const responses = [];
  const sentBodies = [];
  const sandbox = buildSdkSandbox({
    fetch: (url, options) => {
      // Grant issuance is transparent to this contract: answer it directly
      // without consuming the scripted batch responses.
      if (String(url).includes('/api/tracking/grant')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({
            success: true,
            grant: 'test-grant.sig',
            expiresAt: new Date(Date.now() + 600000).toISOString()
          })
        });
      }
      sentBodies.push(JSON.parse(options.body));
      const next = responses.shift();
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(next)
      });
    }
  });

  const nylo = loadSdk(sandbox);
  // The SDK is fail-closed: sendBatch is a no-op until consent is granted.
  nylo.grantConsent();
  nylo.queueTestEvents([
    { eventId: 'a'.repeat(32), eventType: 'page_view', sessionId: 's', domain: 'd' },
    { eventId: 'b'.repeat(32), eventType: 'click', sessionId: 's', domain: 'd' },
    { eventId: 'c'.repeat(32), eventType: 'bogus', sessionId: 's', domain: 'd' }
  ]);

  // Server stores event 0, fails event 1 transiently, rejects event 2.
  responses.push({
    success: true,
    eventsProcessed: 1,
    results: [
      { index: 0, status: 'stored' },
      { index: 1, status: 'error', reason: 'storage_failed' },
      { index: 2, status: 'rejected', reason: 'validation_failed' }
    ]
  });
  // Retry succeeds.
  responses.push({
    success: true,
    eventsProcessed: 1,
    results: [{ index: 0, status: 'stored' }]
  });

  nylo.sendBatch();
  await waitFor(() => sentBodies.length === 2, sandbox);

  // First request: versioned envelope with all 3 events.
  assert.strictEqual(sentBodies[0].schemaVersion, 1);
  assert.strictEqual(sentBodies[0].events.length, 3);

  // Second request: only the storage-failed event redelivered, same eventId.
  assert.strictEqual(sentBodies[1].events.length, 1);
  const retried = Object.assign({}, sentBodies[1].common, sentBodies[1].events[0]);
  assert.strictEqual(retried.eventId, 'b'.repeat(32));

  // Rejected event was dropped, not retried, and queues are empty.
  assert.strictEqual(nylo.queueSizes().eventQueue, 0);
  assert.strictEqual(nylo.queueSizes().retryQueue, 0);
});

// ---------------------------------------------------------------------------
// Minimal browser sandbox for exercising src/nylo.js sendBatch in Node.

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function buildSdkSandbox(overrides) {
  const noop = () => {};
  const timers = [];
  const sandbox = {
    console,
    JSON,
    Object,
    Array,
    Math,
    Date,
    Promise,
    Error,
    Intl,
    crypto: {
      getRandomValues: (arr) => crypto.webcrypto.getRandomValues(arr)
    },
    Uint8Array,
    setTimeout: (fn, ms) => { timers.push(fn); return timers.length; },
    clearTimeout: noop,
    setInterval: () => 0,
    clearInterval: noop,
    performance: { now: () => Date.now(), mark: noop, measure: noop, getEntriesByName: () => [], timing: null },
    navigator: { language: 'en-US', userAgent: 'node-test', sendBeacon: noop },
    screen: { width: 1920, height: 1080 },
    localStorage: { getItem: () => null, setItem: noop, removeItem: noop },
    sessionStorage: { getItem: () => null, setItem: noop, removeItem: noop },
    document: {
      title: 'test', referrer: '', hidden: false,
      addEventListener: noop, removeEventListener: noop,
      currentScript: null,
      querySelector: () => null,
      createElement: () => ({ textContent: '', set innerHTML(v) {}, get innerHTML() { return ''; } })
    },
    fetch: overrides.fetch,
    AbortController,
    AbortSignal,
    __timers: timers
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.window.location = {
    hostname: 'demo.example.com', href: 'https://demo.example.com/',
    pathname: '/', search: '', origin: 'https://demo.example.com', protocol: 'https:'
  };
  sandbox.window.innerWidth = 1280;
  sandbox.window.innerHeight = 720;
  sandbox.window.crypto = sandbox.crypto;
  sandbox.window.addEventListener = noop;
  return sandbox;
}

function loadSdk(sandbox) {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'nylo.js'), 'utf8');
  // Expose internals for the contract test without changing production
  // behavior: inject a test hook just before the IIFE closes.
  const hook = `
  window.__nyloTest = {
    sendBatch: sendBatch,
    queueTestEvents: function(events) {
      events.forEach(function(e) { state.eventQueue.push(e); });
    },
    queueSizes: function() {
      return { eventQueue: state.eventQueue.length, retryQueue: state.retryQueue.length };
    },
    grantConsent: function() { state.consent = 'granted'; }
  };
  `;
  const lastClose = source.lastIndexOf('})();');
  assert.notStrictEqual(lastClose, -1, 'could not find IIFE close in nylo.js');
  const instrumented = source.slice(0, lastClose) + hook + source.slice(lastClose);
  vm.createContext(sandbox);
  vm.runInContext(instrumented, sandbox, { filename: 'nylo.js' });
  return sandbox.__nyloTest;
}

async function waitFor(predicate, sandbox) {
  for (let i = 0; i < 100; i++) {
    // Flush any retry timers the SDK scheduled (retry backoff).
    while (sandbox.__timers.length) sandbox.__timers.shift()();
    if (predicate()) return;
    await new Promise(r => setImmediate(r));
  }
  throw new Error('condition not met');
}
