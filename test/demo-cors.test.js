// SPDX-License-Identifier: MIT
const { test } = require('node:test');
const assert = require('node:assert');
const { createCorsMiddleware } = require('../examples/demo-cors');

function run(middleware, { origin, method = 'GET' } = {}) {
  const headers = {};
  let statusCode = null;
  let ended = false;
  const req = { headers: origin ? { origin } : {}, method };
  const res = {
    header: (k, v) => { headers[k] = v; return res; },
    status: (c) => { statusCode = c; return res; },
    send: () => { ended = true; return res; }
  };
  let nextCalled = false;
  middleware(req, res, () => { nextCalled = true; });
  return { headers, statusCode, ended, nextCalled };
}

test('allows configured origin with credentials and Vary: Origin', () => {
  const mw = createCorsMiddleware({ allowedOrigins: ['app.example.com'], production: true });
  const r = run(mw, { origin: 'https://app.example.com' });
  assert.strictEqual(r.headers['Access-Control-Allow-Origin'], 'https://app.example.com');
  assert.strictEqual(r.headers['Access-Control-Allow-Credentials'], 'true');
  assert.strictEqual(r.headers['Vary'], 'Origin');
  assert.ok(r.nextCalled);
});

test('does not reflect arbitrary origins', () => {
  const mw = createCorsMiddleware({ allowedOrigins: ['app.example.com'], production: false });
  const r = run(mw, { origin: 'https://evil.com' });
  assert.strictEqual(r.headers['Access-Control-Allow-Origin'], undefined);
  assert.strictEqual(r.headers['Access-Control-Allow-Credentials'], undefined);
  assert.ok(r.nextCalled, 'same-origin/non-CORS handling continues');
});

test('empty allowlist in production denies every origin (fail closed)', () => {
  const mw = createCorsMiddleware({ allowedOrigins: [], production: true });
  for (const origin of ['https://evil.com', 'http://localhost:5000', 'https://app.example.com']) {
    const r = run(mw, { origin });
    assert.strictEqual(r.headers['Access-Control-Allow-Origin'], undefined, origin + ' must be denied');
  }
});

test('empty allowlist in development only allows loopback origins', () => {
  const mw = createCorsMiddleware({ allowedOrigins: [], production: false });
  assert.strictEqual(run(mw, { origin: 'http://localhost:3000' }).headers['Access-Control-Allow-Origin'], 'http://localhost:3000');
  assert.strictEqual(run(mw, { origin: 'https://evil.com' }).headers['Access-Control-Allow-Origin'], undefined);
});

test('denied preflight gets no CORS headers but request is terminated', () => {
  const mw = createCorsMiddleware({ allowedOrigins: ['app.example.com'], production: true });
  const r = run(mw, { origin: 'https://evil.com', method: 'OPTIONS' });
  assert.strictEqual(r.headers['Access-Control-Allow-Origin'], undefined);
  assert.strictEqual(r.statusCode, 204);
  assert.ok(r.ended);
  assert.ok(!r.nextCalled);
});

test('wildcard allowlist entries respect host boundaries', () => {
  const mw = createCorsMiddleware({ allowedOrigins: ['*.example.com'], production: true });
  assert.strictEqual(run(mw, { origin: 'https://sub.example.com' }).headers['Access-Control-Allow-Origin'], 'https://sub.example.com');
  assert.strictEqual(run(mw, { origin: 'https://evilexample.com' }).headers['Access-Control-Allow-Origin'], undefined);
});
