// SPDX-License-Identifier: MIT
//
// Behavioral contract tests for the REFERENCE verification endpoint
// (server/api/waitag-tracking.ts), covering every response branch and
// HTTP status exactly as documented in draft-surampudi-wtx1-02
// Section 6.4: which failures carry a machine-readable `error` member,
// which are message-only, and which status each branch uses.
//
// scripts/check-draft-consistency.js statically inspects the same
// branches; these tests pin the observed runtime behavior.
'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const ts = require('typescript');

// node 18 cannot load TypeScript natively; register a minimal transpiling
// require hook so these tests exercise the actual reference handler
// rather than a JavaScript re-implementation of it.
require.extensions['.ts'] = function (m, filename) {
  const out = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2020,
      esModuleInterop: true
    },
    fileName: filename
  }).outputText;
  m._compile(out, filename);
};

const express = require('express');
const { signCrossDomainToken } = require('../server/utils/token-core');
const { signWriteGrant } = require('../server/utils/write-grant');
const { registerWaiTagTrackingRoutes } = require('../server/api/waitag-tracking.ts');

const SECRET = 'verify-contract-test-secret';
process.env.NYLO_TOKEN_SECRET = SECRET;

const DEST = 'dest.example.com';
const SOURCE = 'source.example.com';
const TENANT = '1';

function makeStorage(overrides) {
  const used = new Set();
  return Object.assign({
    getCustomer: async () => null,
    getCustomerByApiKey: async () => null,
    createInteraction: async () => ({}),
    parseDomain: (d) => ({ mainDomain: d, subdomain: null }),
    isDomainVerified: async () => true,
    tokenReplayStore: {
      isTokenUsed: async (h) => used.has(h),
      markTokenUsed: async (h) => { used.add(h); },
      consumeToken: async (h) => (used.has(h) ? false : (used.add(h), true))
    }
  }, overrides || {});
}

function makeGrant(opts) {
  opts = opts || {};
  return signWriteGrant({
    tenantId: opts.tenantId || TENANT,
    domain: opts.domain || DEST,
    scopes: opts.scopes || ['ingest', 'register']
  }, opts.secret || SECRET, { now: opts.now, ttlMs: opts.ttlMs });
}

function makeToken(opts) {
  opts = opts || {};
  return signCrossDomainToken({
    tenantId: opts.tenantId || TENANT,
    sourceDomain: opts.sourceDomain || SOURCE,
    destinationDomain: opts.destinationDomain || DEST,
    waiTag: opts.waiTag || 'wai_9f86d081884c7d65_contract',
    sessionId: opts.sessionId || 'sess_contract'
  }, opts.secret || SECRET, { ttlMs: opts.ttlMs });
}

// Three apps: normal storage, storage with no domain-authorization
// capability (fail-closed test), and storage whose check throws (500).
let servers = [];
let urls = {};

function listen(app) {
  return new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
}

before(async () => {
  const variants = {
    normal: makeStorage(),
    unverified: makeStorage({ isDomainVerified: async () => false }),
    nocheck: makeStorage({ isDomainVerified: undefined }),
    throwing: makeStorage({ isDomainVerified: async () => { throw new Error('boom'); } })
  };
  for (const [name, storage] of Object.entries(variants)) {
    const app = express();
    app.use(express.json());
    registerWaiTagTrackingRoutes(app, storage);
    const s = await listen(app);
    servers.push(s);
    urls[name] = 'http://127.0.0.1:' + s.address().port;
  }
});

after(() => servers.forEach((s) => s.close()));

async function verify(body, opts) {
  opts = opts || {};
  const headers = { 'Content-Type': 'application/json' };
  const grant = 'grant' in opts ? opts.grant : makeGrant({ domain: body.domain });
  if (grant) headers['X-Nylo-Grant'] = grant;
  const res = await fetch((urls[opts.app || 'normal']) + '/api/tracking/verify-cross-domain-token', {
    method: 'POST', headers, body: JSON.stringify(body)
  });
  return { status: res.status, body: await res.json() };
}

function assertCoded(res, status, code) {
  assert.strictEqual(res.status, status, `expected HTTP ${status}, got ${res.status}: ${JSON.stringify(res.body)}`);
  assert.strictEqual(res.body.success, false);
  assert.strictEqual(res.body.error, code);
  assert.strictEqual(typeof res.body.message, 'string');
}

// Draft Section 6.4: structural request errors and internal errors are
// message-only -- success:false with NO machine-readable error member.
function assertMessageOnly(res, status) {
  assert.strictEqual(res.status, status, `expected HTTP ${status}, got ${res.status}: ${JSON.stringify(res.body)}`);
  assert.strictEqual(res.body.success, false);
  assert.ok(!('error' in res.body), `expected no error member, got: ${JSON.stringify(res.body)}`);
  assert.strictEqual(typeof res.body.message, 'string');
}

// --------------------------- grant authorization (runs before everything)

test('503 GRANTS_UNAVAILABLE when grants are unconfigured in production', async () => {
  const envNode = process.env.NODE_ENV;
  const envSecret = process.env.NYLO_TOKEN_SECRET;
  process.env.NODE_ENV = 'production';
  delete process.env.NYLO_TOKEN_SECRET;
  try {
    const res = await verify({ token: 'x', domain: DEST }, { grant: null });
    assertCoded(res, 503, 'GRANTS_UNAVAILABLE');
  } finally {
    process.env.NODE_ENV = envNode;
    process.env.NYLO_TOKEN_SECRET = envSecret;
  }
});

test('401 GRANT_REQUIRED without an X-Nylo-Grant header', async () => {
  assertCoded(await verify({ token: 'x', domain: DEST }, { grant: null }), 401, 'GRANT_REQUIRED');
});

test('403 GRANT_MALFORMED for an unparseable grant', async () => {
  assertCoded(await verify({ token: 'x', domain: DEST }, { grant: 'garbage' }), 403, 'GRANT_MALFORMED');
});

test('403 GRANT_BAD_SIGNATURE for a grant signed under another secret', async () => {
  const grant = makeGrant({ secret: 'some-other-secret' });
  assertCoded(await verify({ token: 'x', domain: DEST }, { grant }), 403, 'GRANT_BAD_SIGNATURE');
});

test('403 GRANT_EXPIRED for an expired grant', async () => {
  const grant = makeGrant({ now: Date.now() - 7200000, ttlMs: 1000 });
  assertCoded(await verify({ token: 'x', domain: DEST }, { grant }), 403, 'GRANT_EXPIRED');
});

test('403 GRANT_SCOPE_MISSING: verification demands the ingest scope', async () => {
  const grant = makeGrant({ scopes: ['register'] });
  assertCoded(await verify({ token: 'x', domain: DEST }, { grant }), 403, 'GRANT_SCOPE_MISSING');
});

// ------------------- structural input validation (HTTP 400, message-only)

test('400 message-only when token is missing', async () => {
  assertMessageOnly(await verify({ domain: DEST }), 400);
});

test('400 message-only when domain is missing', async () => {
  assertMessageOnly(await verify({ token: 'x' }, { grant: makeGrant() }), 400);
});

test('400 message-only for a syntactically invalid domain', async () => {
  assertMessageOnly(await verify({ token: 'x', domain: '!!!' }, { grant: makeGrant() }), 400);
});

// ------------------------------------------- binding and identity checks

test('403 GRANT_DOMAIN_MISMATCH when the request domain differs from the grant', async () => {
  const grant = makeGrant({ domain: 'other.example.com' });
  assertCoded(await verify({ token: 'x', domain: DEST }, { grant }), 403, 'GRANT_DOMAIN_MISMATCH');
});

test('403 TENANT_MISMATCH when legacy customerId disagrees with the grant tenant', async () => {
  const res = await verify({ token: 'x', domain: DEST, customerId: '999' });
  assertCoded(res, 403, 'TENANT_MISMATCH');
});

// ------------------------------------------------ token verification core

test('400 MALFORMED_TOKEN for an unparseable token', async () => {
  assertCoded(await verify({ token: 'garbage', domain: DEST }), 400, 'MALFORMED_TOKEN');
});

test('403 DOMAIN_MISMATCH when the token is bound to a different destination', async () => {
  const token = makeToken({ destinationDomain: 'other.example.com' });
  assertCoded(await verify({ token, domain: DEST }), 403, 'DOMAIN_MISMATCH');
});

test('403 TOKEN_EXPIRED for an expired token', async () => {
  // Two hours past expiry defeats any clock-skew allowance.
  const token = makeToken({ ttlMs: -7200000 });
  assertCoded(await verify({ token, domain: DEST }), 403, 'TOKEN_EXPIRED');
});

// ------------------------------------------------- domain authorization

test('403 DOMAIN_NOT_VERIFIED when a bound domain is not authorized for the tenant', async () => {
  const res = await verify({ token: makeToken(), domain: DEST }, { app: 'unverified' });
  assertCoded(res, 403, 'DOMAIN_NOT_VERIFIED');
});

test('403 DOMAIN_NOT_VERIFIED fail-closed in production when authorization state is unavailable', async () => {
  const envNode = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    const res = await verify({ token: makeToken(), domain: DEST }, { app: 'nocheck' });
    assertCoded(res, 403, 'DOMAIN_NOT_VERIFIED');
  } finally {
    process.env.NODE_ENV = envNode;
  }
});

// -------------------------------------------- success, replay, and 500s

test('200 success carries identity, domain, and verifiedAt; replay of the same token is 403 TOKEN_REPLAYED', async () => {
  const token = makeToken();
  const first = await verify({ token, domain: DEST });
  assert.strictEqual(first.status, 200, JSON.stringify(first.body));
  assert.strictEqual(first.body.success, true);
  assert.deepStrictEqual(Object.keys(first.body).sort(), ['domain', 'identity', 'success', 'verifiedAt']);
  assert.deepStrictEqual(Object.keys(first.body.identity).sort(), ['sessionId', 'userId', 'waiTag']);
  assert.strictEqual(first.body.identity.waiTag, 'wai_9f86d081884c7d65_contract');
  assert.strictEqual(first.body.identity.userId, null);
  assert.strictEqual(first.body.domain, DEST);
  assert.ok(!Number.isNaN(Date.parse(first.body.verifiedAt)), 'verifiedAt must be a timestamp');

  const replay = await verify({ token, domain: DEST });
  assertCoded(replay, 403, 'TOKEN_REPLAYED');
});

test('500 message-only when an internal dependency fails', async () => {
  const res = await verify({ token: makeToken(), domain: DEST }, { app: 'throwing' });
  assertMessageOnly(res, 500);
});
