// SPDX-License-Identifier: MIT
'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const express = require('express');
const { registerDemoWriteRoutes } = require('../examples/demo-write-routes');

const SECRET = 'demo-write-route-test-secret';

async function startServer() {
  const app = express();
  app.use(express.json());
  registerDemoWriteRoutes(app, { secret: SECRET });
  const server = await new Promise((resolve) => {
    const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
  });
  return { server, baseUrl: 'http://127.0.0.1:' + server.address().port };
}

test('demo registration is grant-gated, domain-bound, and tenant-bound', async () => {
  const { server, baseUrl } = await startServer();
  try {
    const identity = {
      waiTag: 'wai_abc123def4567890123_deadbeef',
      sessionId: 'session-1',
      domain: 'localhost'
    };

    const missing = await fetch(baseUrl + '/api/tracking/register-waitag', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(identity)
    });
    assert.strictEqual(missing.status, 401);

    const grantResponse = await fetch(baseUrl + '/api/tracking/grant', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'http://localhost' },
      body: JSON.stringify({ domain: 'localhost' })
    });
    assert.strictEqual(grantResponse.status, 200);
    const { grant } = await grantResponse.json();
    assert.ok(grant);

    const mismatch = await fetch(baseUrl + '/api/tracking/register-waitag', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Nylo-Grant': grant },
      body: JSON.stringify({ ...identity, customerId: '999' })
    });
    assert.strictEqual(mismatch.status, 403);
    assert.strictEqual((await mismatch.json()).error, 'TENANT_MISMATCH');

    const accepted = await fetch(baseUrl + '/api/tracking/register-waitag', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Nylo-Grant': grant },
      body: JSON.stringify(identity)
    });
    assert.strictEqual(accepted.status, 200);
    assert.strictEqual((await accepted.json()).success, true);
  } finally {
    server.close();
  }
});