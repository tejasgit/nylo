/**
 * SPDX-License-Identifier: MIT
 *
 * Nylo Write Grants — short-lived, server-signed browser write authorization.
 *
 * A write grant binds { tenant, page domain, scopes } together and is signed
 * with the server's secret. Browsers obtain one from POST /api/tracking/grant
 * (the server resolves the tenant from its own domain→tenant configuration)
 * and present it on every ingestion/registration request via the
 * `X-Nylo-Grant` header.
 *
 * Security properties:
 * - The BROWSER NEVER ASSERTS TENANT IDENTITY. The tenant inside the grant is
 *   chosen by the server at issuance time; ingestion endpoints trust only the
 *   signed grant, never caller-supplied customer IDs.
 * - Grants are domain-bound: events for domain D are only accepted with a
 *   grant issued for D.
 * - Grants are scope-bound ('ingest', 'register') and expire quickly.
 * - Grants are bearer credentials by design (a page reuses one for many
 *   batches within its TTL); they authorize WRITES only and never authorize
 *   reading or linking identity data.
 *
 * Format (mirrors WTX-1): base64url(payloadJSON) + '.' + base64url(hmacSha256).
 * The signature is computed over the exact payload JSON string.
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

'use strict';

const crypto = require('crypto');

const GRANT_VERSION = 1;
const DEFAULT_GRANT_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_GRANT_TTL_MS = 24 * 60 * 60 * 1000; // sanity ceiling
const MAX_CLOCK_SKEW_MS = 60 * 1000;
const GRANT_SCOPES = ['ingest', 'register'];

function base64UrlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(padded, 'base64');
}

function hmacSha256(data, secret) {
  return crypto.createHmac('sha256', secret).update(data, 'utf8').digest();
}

/**
 * Signs a write grant. `claims` = { tenantId, domain, scopes }.
 * Options: { now?, ttlMs?, jti? }.
 */
function signWriteGrant(claims, secret, opts) {
  opts = opts || {};
  if (!secret || typeof secret !== 'string') {
    throw new Error('A signing secret is required');
  }
  if (!claims || typeof claims !== 'object') {
    throw new Error('Grant claims are required');
  }
  const tenantId = claims.tenantId === 0 ? '0' : String(claims.tenantId || '');
  const domain = String(claims.domain || '').trim().toLowerCase();
  const scopes = Array.isArray(claims.scopes) ? claims.scopes.slice() : [];
  if (!tenantId) throw new Error('Grant tenantId is required');
  if (!domain) throw new Error('Grant domain is required');
  if (scopes.length === 0 || !scopes.every((s) => GRANT_SCOPES.indexOf(s) !== -1)) {
    throw new Error('Grant scopes must be a non-empty subset of: ' + GRANT_SCOPES.join(', '));
  }

  const now = typeof opts.now === 'number' ? opts.now : Date.now();
  const ttlMs = typeof opts.ttlMs === 'number' ? Math.min(opts.ttlMs, MAX_GRANT_TTL_MS) : DEFAULT_GRANT_TTL_MS;
  const payload = {
    gv: GRANT_VERSION,
    jti: opts.jti || crypto.randomBytes(16).toString('hex'),
    iat: now,
    exp: now + ttlMs,
    tenantId: tenantId,
    domain: domain,
    scopes: scopes
  };
  const payloadJson = JSON.stringify(payload);
  const signature = hmacSha256(payloadJson, secret);
  return base64UrlEncode(Buffer.from(payloadJson, 'utf8')) + '.' + base64UrlEncode(signature);
}

/**
 * Verifies a write grant. Options: { now?, expectedDomain?, requiredScope? }.
 * Returns { valid, payload, error } — never throws on bad input.
 */
function verifyWriteGrant(grant, secret, opts) {
  opts = opts || {};
  if (!secret || typeof secret !== 'string') {
    return { valid: false, payload: null, error: 'NO_SECRET' };
  }
  if (!grant || typeof grant !== 'string' || grant.length > 4096) {
    return { valid: false, payload: null, error: 'MALFORMED' };
  }
  const parts = grant.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { valid: false, payload: null, error: 'MALFORMED' };
  }

  let payloadJson;
  let providedSig;
  try {
    payloadJson = base64UrlDecode(parts[0]).toString('utf8');
    providedSig = base64UrlDecode(parts[1]);
  } catch (e) {
    return { valid: false, payload: null, error: 'MALFORMED' };
  }

  const expectedSig = hmacSha256(payloadJson, secret);
  if (providedSig.length !== expectedSig.length || !crypto.timingSafeEqual(providedSig, expectedSig)) {
    return { valid: false, payload: null, error: 'BAD_SIGNATURE' };
  }

  let parsed;
  try {
    parsed = JSON.parse(payloadJson);
  } catch (e) {
    return { valid: false, payload: null, error: 'MALFORMED' };
  }

  if (!parsed || typeof parsed !== 'object' ||
      parsed.gv !== GRANT_VERSION ||
      typeof parsed.jti !== 'string' ||
      typeof parsed.iat !== 'number' ||
      typeof parsed.exp !== 'number' ||
      typeof parsed.tenantId !== 'string' || parsed.tenantId.length === 0 ||
      typeof parsed.domain !== 'string' || parsed.domain.length === 0 ||
      !Array.isArray(parsed.scopes) ||
      parsed.scopes.length === 0 ||
      !parsed.scopes.every((s) => typeof s === 'string' && GRANT_SCOPES.indexOf(s) !== -1)) {
    return { valid: false, payload: null, error: 'INVALID_CLAIMS' };
  }

  const now = typeof opts.now === 'number' ? opts.now : Date.now();
  if (parsed.iat > now + MAX_CLOCK_SKEW_MS) {
    return { valid: false, payload: null, error: 'NOT_YET_VALID' };
  }
  if (parsed.exp <= now) {
    return { valid: false, payload: null, error: 'EXPIRED' };
  }
  if (parsed.exp - parsed.iat > MAX_GRANT_TTL_MS + MAX_CLOCK_SKEW_MS) {
    return { valid: false, payload: null, error: 'INVALID_CLAIMS' };
  }

  if (opts.expectedDomain) {
    const expected = String(opts.expectedDomain).trim().toLowerCase();
    if (parsed.domain !== expected) {
      return { valid: false, payload: null, error: 'DOMAIN_MISMATCH' };
    }
  }
  if (opts.requiredScope && parsed.scopes.indexOf(opts.requiredScope) === -1) {
    return { valid: false, payload: null, error: 'SCOPE_MISSING' };
  }

  return { valid: true, payload: parsed, error: null };
}

module.exports = {
  GRANT_VERSION,
  DEFAULT_GRANT_TTL_MS,
  MAX_CLOCK_SKEW_MS,
  GRANT_SCOPES,
  signWriteGrant,
  verifyWriteGrant
};
