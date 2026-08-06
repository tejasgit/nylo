/**
 * Contract tests for the shared event envelope (client <-> server).
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const {
  SCHEMA_VERSION,
  LIMITS,
  buildEnvelope,
  parseEnvelope
} = require('../shared/event-envelope');

function makeEventId() {
  return crypto.randomBytes(16).toString('hex');
}

function makeClientEvent(overrides) {
  return Object.assign({
    eventId: makeEventId(),
    sessionId: 'sess_abcdefghij',
    userId: 'wai_1234567890_abc',
    waiTag: 'wai_1234567890_abc',
    domain: 'shop.example.com',
    customerId: 'cust-1',
    eventType: 'page_view',
    timestamp: '2026-08-06T10:00:00.000Z',
    url: 'https://shop.example.com/products',
    metadata: '{"loadTime":123}'
  }, overrides || {});
}

test('client-built batch round-trips through parseEnvelope', () => {
  const events = [
    makeClientEvent(),
    makeClientEvent({ eventType: 'click', url: 'https://shop.example.com/cart' })
  ];
  const envelope = buildEnvelope(events, { batchId: makeEventId(), customerId: 'cust-1' });

  // Common fields are hoisted, per-event copies stripped
  assert.strictEqual(envelope.schemaVersion, SCHEMA_VERSION);
  assert.strictEqual(envelope.common.sessionId, 'sess_abcdefghij');
  assert.strictEqual(envelope.events[0].sessionId, undefined);
  assert.ok(envelope.events[0].eventId);

  const parsed = parseEnvelope(JSON.parse(JSON.stringify(envelope)));
  assert.strictEqual(parsed.ok, true);
  assert.strictEqual(parsed.schemaVersion, 1);
  assert.strictEqual(parsed.events.length, 2);
  // Expanded events match the originals
  for (let i = 0; i < events.length; i++) {
    for (const key of Object.keys(events[i])) {
      assert.deepStrictEqual(parsed.events[i][key], events[i][key], `event ${i} field ${key}`);
    }
  }
});

test('events that differ from common keep their own values', () => {
  const events = [
    makeClientEvent(),
    makeClientEvent({ domain: 'blog.example.com' })
  ];
  const envelope = buildEnvelope(events);
  assert.strictEqual(envelope.events[1].domain, 'blog.example.com');
  const parsed = parseEnvelope(envelope);
  assert.strictEqual(parsed.events[0].domain, 'shop.example.com');
  assert.strictEqual(parsed.events[1].domain, 'blog.example.com');
});

test('unknown schema version is rejected', () => {
  const parsed = parseEnvelope({ schemaVersion: 99, common: {}, events: [makeClientEvent()] });
  assert.strictEqual(parsed.ok, false);
  assert.strictEqual(parsed.status, 400);
  assert.strictEqual(parsed.error, 'UNSUPPORTED_SCHEMA_VERSION');
});

test('malformed batches are rejected with 400', () => {
  const cases = [
    [null, 'INVALID_BODY'],
    ['string', 'INVALID_BODY'],
    [{ schemaVersion: 1, events: 'nope' }, 'INVALID_EVENTS'],
    [{ schemaVersion: 1, common: [], events: [] }, 'INVALID_COMMON'],
    [{ schemaVersion: 1, common: {}, events: [] }, 'EMPTY_BATCH'],
    [{ schemaVersion: 1, common: {}, events: [null] }, 'INVALID_EVENT'],
    [{ schemaVersion: 1, common: {}, events: [{ eventType: 'click' }] }, 'INVALID_EVENT_ID'],
    [{ schemaVersion: 1, common: {}, events: [{ eventId: 'short', eventType: 'click' }] }, 'INVALID_EVENT_ID'],
    [{ events: 42 }, 'INVALID_EVENTS']
  ];
  for (const [body, code] of cases) {
    const parsed = parseEnvelope(body);
    assert.strictEqual(parsed.ok, false, JSON.stringify(body));
    assert.strictEqual(parsed.status, 400);
    assert.strictEqual(parsed.error, code, JSON.stringify(body));
  }
});

test('duplicate eventId within a batch is rejected', () => {
  const dup = makeClientEvent();
  const parsed = parseEnvelope(buildEnvelope([dup, Object.assign({}, dup)]));
  assert.strictEqual(parsed.ok, false);
  assert.strictEqual(parsed.error, 'DUPLICATE_EVENT_ID');
});

test('batch and event size limits are enforced', () => {
  const tooMany = [];
  for (let i = 0; i < LIMITS.MAX_EVENTS_PER_BATCH + 1; i++) tooMany.push(makeClientEvent());
  const parsedCount = parseEnvelope(buildEnvelope(tooMany));
  assert.strictEqual(parsedCount.ok, false);
  assert.strictEqual(parsedCount.error, 'TOO_MANY_EVENTS');

  const bigEvent = makeClientEvent({ metadata: 'x'.repeat(LIMITS.MAX_EVENT_BYTES + 1) });
  const parsedBig = parseEnvelope(buildEnvelope([bigEvent]));
  assert.strictEqual(parsedBig.ok, false);
  assert.ok(['EVENT_TOO_LARGE', 'BATCH_TOO_LARGE'].includes(parsedBig.error));
});

test('legacy plain-array and single-event bodies still parse (schemaVersion 0)', () => {
  const arr = parseEnvelope([{ eventType: 'click', sessionId: 's1', domain: 'a.com' }]);
  assert.strictEqual(arr.ok, true);
  assert.strictEqual(arr.schemaVersion, 0);

  const single = parseEnvelope({ eventType: 'click', sessionId: 's1', domain: 'a.com' });
  assert.strictEqual(single.ok, true);
  assert.strictEqual(single.events.length, 1);

  // Old broken SDK shape: { events: { common, events } }
  const oldBroken = parseEnvelope({
    events: {
      common: { sessionId: 's1', domain: 'a.com' },
      events: [{ eventType: 'click' }]
    }
  });
  assert.strictEqual(oldBroken.ok, true);
  assert.strictEqual(oldBroken.events[0].sessionId, 's1');
  assert.strictEqual(oldBroken.events[0].eventType, 'click');
});
