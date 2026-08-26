// SPDX-License-Identifier: MIT
/**
 * End-to-end contract test: an SDK-built batch round-trips through the
 * demo server's /api/track ingestion, authorized by a write grant.
 *
 * The tenant comes from the server's domain→tenant mapping (via the
 * grant), never from caller-supplied customer IDs.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const path = require('node:path');

const { buildEnvelope, SCHEMA_VERSION } = require('../shared/event-envelope');

const PORT = 3199;
const BASE = `http://127.0.0.1:${PORT}`;
let server;
let GRANT;

function makeEventId() {
  return crypto.randomBytes(16).toString('hex');
}

function makeClientEvent(overrides) {
  return Object.assign({
    eventId: makeEventId(),
    sessionId: 'sess_contracttest',
    userId: 'wai_1234567890_abc',
    waiTag: 'wai_1234567890_abc',
    domain: 'demo.example.com',
    eventType: 'page_view',
    timestamp: '2026-08-06T10:00:00.000Z',
    url: 'https://demo.example.com/',
    metadata: '{"loadTime":42}'
  }, overrides || {});
}

async function postTrack(body, opts) {
  opts = opts || {};
  const headers = { 'Content-Type': 'application/json' };
  const grant = 'grant' in opts ? opts.grant : GRANT;
  if (grant) headers['X-Nylo-Grant'] = grant;
  const res = await fetch(`${BASE}/api/track`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body)
  });
  return { status: res.status, json: await res.json().catch(() => null) };
}

test.before(async () => {
  server = spawn('node', [path.join(__dirname, '..', 'examples', 'demo-server.js')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      NYLO_TOKEN_SECRET: 'contract-test-secret',
      NYLO_DEMO_DOMAINS: 'demo.example.com'
    },
    stdio: 'ignore'
  });
  // Wait for the server to accept connections
  let up = false;
  for (let i = 0; i < 50 && !up; i++) {
    try {
      await fetch(`${BASE}/api/stats`);
      up = true;
    } catch {
      await new Promise(r => setTimeout(r, 200));
    }
  }
  if (!up) throw new Error('demo server did not start');

  // Obtain a write grant for the demo domain (server-side tenant mapping).
  const res = await fetch(`${BASE}/api/tracking/grant`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain: 'demo.example.com' })
  });
  const body = await res.json();
  assert.strictEqual(body.success, true, 'grant issuance must succeed: ' + JSON.stringify(body));
  GRANT = body.grant;
});

test.after(() => {
  if (server) server.kill();
});

test('SDK-built batch is decompressed and stored server-side', async () => {
  const events = [
    makeClientEvent(),
    makeClientEvent({ eventType: 'click', url: 'https://demo.example.com/pricing' })
  ];
  const envelope = buildEnvelope(events, { batchId: makeEventId() });
  assert.strictEqual(envelope.schemaVersion, SCHEMA_VERSION);

  const { status, json } = await postTrack(envelope);
  assert.strictEqual(status, 200);
  assert.strictEqual(json.success, true);
  assert.strictEqual(json.eventsProcessed, 2);
  assert.strictEqual(json.results.length, 2);
  assert.ok(json.results.every(r => r.status === 'stored'));

  // Verify common fields were expanded into stored events
  const stored = await (await fetch(`${BASE}/api/events`)).json();
  const list = Array.isArray(stored) ? stored : stored.events || stored.interactions || [];
  const ours = list.filter(e => e.sessionId === 'sess_contracttest');
  assert.strictEqual(ours.length, 2);
  for (const e of ours) {
    assert.strictEqual(e.domain, 'demo.example.com');
    // Tenant identity comes from the grant (server-side mapping), which
    // maps demo domains to tenant '1'.
    assert.strictEqual(e.customerId, '1');
    assert.strictEqual(e.clientTimestamp, '2026-08-06T10:00:00.000Z');
    assert.ok(e.timestamp, 'server receipt time preserved');
    assert.match(e.eventId, /^[0-9a-f]{32}$/);
  }
});

test('duplicate eventId is deduplicated idempotently', async () => {
  const event = makeClientEvent({ eventType: 'conversion' });
  const envelope = buildEnvelope([event]);

  const first = await postTrack(envelope);
  assert.strictEqual(first.json.eventsProcessed, 1);

  const retry = await postTrack(buildEnvelope([event]));
  assert.strictEqual(retry.status, 200);
  assert.strictEqual(retry.json.eventsProcessed, 0);
  assert.strictEqual(retry.json.results[0].status, 'duplicate');
});

test('malformed batch is rejected with 400', async () => {
  const { status, json } = await postTrack({ schemaVersion: 1, events: 'garbage' });
  assert.strictEqual(status, 400);
  assert.strictEqual(json.success, false);
  assert.strictEqual(json.error, 'INVALID_EVENTS');
});

test('unknown schema version is rejected with 400', async () => {
  const { status, json } = await postTrack({
    schemaVersion: 2,
    common: {},
    events: [makeClientEvent()]
  });
  assert.strictEqual(status, 400);
  assert.strictEqual(json.error, 'UNSUPPORTED_SCHEMA_VERSION');
});

test('partial failure returns per-event details', async () => {
  const good = makeClientEvent({ eventType: 'click' });
  const bad = { eventId: makeEventId(), timestamp: '2026-08-06T10:00:00.000Z' }; // no eventType
  const { status, json } = await postTrack(buildEnvelope([good, bad]));
  assert.strictEqual(status, 200);
  assert.strictEqual(json.eventsProcessed, 1);
  assert.strictEqual(json.results[0].status, 'stored');
  assert.strictEqual(json.results[1].status, 'rejected');
  assert.strictEqual(json.results[1].reason, 'missing_event_type');
});

test('requests without a write grant are rejected with 401', async () => {
  const { status, json } = await postTrack(buildEnvelope([makeClientEvent()]), { grant: null });
  assert.strictEqual(status, 401);
  assert.strictEqual(json.error, 'GRANT_REQUIRED');
});

test('tampered write grants are rejected with 403', async () => {
  const { status, json } = await postTrack(
    buildEnvelope([makeClientEvent()]),
    { grant: GRANT + 'x' }
  );
  assert.strictEqual(status, 403);
  assert.ok(String(json.error).startsWith('GRANT_'), JSON.stringify(json));
});

test('an envelope customerId conflicting with the grant tenant is rejected', async () => {
  const envelope = buildEnvelope([makeClientEvent()], { customerId: 'cust-999' });
  const { status, json } = await postTrack(envelope);
  assert.strictEqual(status, 403);
  assert.strictEqual(json.error, 'TENANT_MISMATCH');
});

test('events for a domain outside the grant are rejected per-event', async () => {
  const foreign = makeClientEvent({ domain: 'other.example.com' });
  const { status, json } = await postTrack(buildEnvelope([foreign]));
  assert.strictEqual(status, 200);
  assert.strictEqual(json.eventsProcessed, 0);
  assert.strictEqual(json.results[0].status, 'rejected');
  assert.strictEqual(json.results[0].reason, 'domain_not_authorized');
});

test('stored URLs are stripped of query strings and fragments', async () => {
  const event = makeClientEvent({
    eventType: 'click',
    sessionId: 'sess_urlstrip',
    url: 'https://demo.example.com/checkout?email=a@b.com&token=SECRET#step2'
  });
  const { status, json } = await postTrack(buildEnvelope([event]));
  assert.strictEqual(status, 200);
  assert.strictEqual(json.eventsProcessed, 1);

  const stored = await (await fetch(`${BASE}/api/events`)).json();
  const list = Array.isArray(stored) ? stored : stored.events || stored.interactions || [];
  const ours = list.filter(e => e.sessionId === 'sess_urlstrip');
  assert.strictEqual(ours.length, 1);
  assert.strictEqual(ours[0].url, 'https://demo.example.com/checkout');
  assert.ok(!JSON.stringify(ours[0]).includes('SECRET'));
});

test('grant issuance refuses domains without a tenant mapping', async () => {
  const res = await fetch(`${BASE}/api/tracking/grant`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain: 'unmapped.example.com' })
  });
  assert.strictEqual(res.status, 403);
  const body = await res.json();
  assert.strictEqual(body.error, 'UNKNOWN_DOMAIN');
});

test('grant issuance refuses mismatched browser origins', async () => {
  const res = await fetch(`${BASE}/api/tracking/grant`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'https://evil.example.com'
    },
    body: JSON.stringify({ domain: 'demo.example.com' })
  });
  assert.strictEqual(res.status, 403);
  const body = await res.json();
  assert.strictEqual(body.error, 'ORIGIN_MISMATCH');
});
