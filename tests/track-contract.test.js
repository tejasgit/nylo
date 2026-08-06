/**
 * End-to-end contract test: an SDK-built batch round-trips through the
 * demo server's /api/track ingestion.
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
    customerId: 'cust-1',
    eventType: 'page_view',
    timestamp: '2026-08-06T10:00:00.000Z',
    url: 'https://demo.example.com/',
    metadata: '{"loadTime":42}'
  }, overrides || {});
}

async function postTrack(body) {
  const res = await fetch(`${BASE}/api/track`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Customer-ID': 'cust-1' },
    body: JSON.stringify(body)
  });
  return { status: res.status, json: await res.json().catch(() => null) };
}

test.before(async () => {
  server = spawn('node', [path.join(__dirname, '..', 'examples', 'demo-server.js')], {
    env: { ...process.env, PORT: String(PORT) },
    stdio: 'ignore'
  });
  // Wait for the server to accept connections
  for (let i = 0; i < 50; i++) {
    try {
      await fetch(`${BASE}/api/stats`);
      return;
    } catch {
      await new Promise(r => setTimeout(r, 200));
    }
  }
  throw new Error('demo server did not start');
});

test.after(() => {
  if (server) server.kill();
});

test('SDK-built batch is decompressed and stored server-side', async () => {
  const events = [
    makeClientEvent(),
    makeClientEvent({ eventType: 'click', url: 'https://demo.example.com/pricing' })
  ];
  const envelope = buildEnvelope(events, { batchId: makeEventId(), customerId: 'cust-1' });
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
    assert.strictEqual(e.customerId, 'cust-1');
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
