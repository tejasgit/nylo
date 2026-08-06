/**
 * Nylo Cross-Domain Token Core (WTX-1)
 *
 * Signed, versioned, replay-resistant cross-domain tokens.
 * Every token carries: protocol version, jti (nonce), iat, exp,
 * tenantId, sourceDomain and destinationDomain.
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 *
 * COMMERCIAL NOTICE: part of the WTX-1 protocol covered by COMMERCIAL-LICENSE.
 */

'use strict';

const crypto = require('crypto');

const TOKEN_VERSION = 1;
const DEFAULT_TTL_MS = 5 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 60 * 1000;

const REQUIRED_CLAIMS = ['v', 'jti', 'iat', 'exp', 'tenantId', 'sourceDomain', 'destinationDomain', 'waiTag', 'sessionId'];

function canonicalPayload(p) {
  return {
    v: p.v,
    jti: p.jti,
    iat: p.iat,
    exp: p.exp,
    tenantId: p.tenantId,
    sourceDomain: p.sourceDomain,
    destinationDomain: p.destinationDomain,
    waiTag: p.waiTag,
    sessionId: p.sessionId,
    userId: p.userId === undefined ? null : p.userId
  };
}

function hmac(data, secret) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Creates a signed cross-domain token bound to tenant + source + destination.
 * Throws when a required claim is missing.
 */
function signCrossDomainToken(claims, secret, opts) {
  opts = opts || {};
  if (!secret) throw new Error('Token secret is required');
  ['tenantId', 'sourceDomain', 'destinationDomain', 'waiTag', 'sessionId'].forEach(function (k) {
    if (claims[k] === undefined || claims[k] === null || claims[k] === '') {
      throw new Error('Missing required token claim: ' + k);
    }
  });

  const now = typeof opts.now === 'number' ? opts.now : Date.now();
  const payload = canonicalPayload({
    v: TOKEN_VERSION,
    jti: opts.jti || crypto.randomBytes(16).toString('hex'),
    iat: now,
    exp: now + (typeof opts.ttlMs === 'number' ? opts.ttlMs : DEFAULT_TTL_MS),
    tenantId: String(claims.tenantId),
    sourceDomain: String(claims.sourceDomain).toLowerCase(),
    destinationDomain: String(claims.destinationDomain).toLowerCase(),
    waiTag: claims.waiTag,
    sessionId: claims.sessionId,
    userId: claims.userId === undefined ? null : claims.userId
  });

  const sig = hmac(JSON.stringify(payload), secret);
  return Buffer.from(JSON.stringify(Object.assign({}, payload, { sig: sig }))).toString('base64');
}

/**
 * Verifies signature, version, nonce, iat/exp and (optionally) the
 * expected destination domain and tenant.
 * Returns { valid, payload, error }.
 */
function verifyCrossDomainToken(token, secret, opts) {
  opts = opts || {};
  if (!secret) return { valid: false, payload: null, error: 'NO_SECRET' };

  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(String(token), 'base64').toString('utf-8'));
    if (!parsed || typeof parsed !== 'object') throw new Error('bad');
  } catch {
    return { valid: false, payload: null, error: 'MALFORMED_TOKEN' };
  }

  if (!parsed.sig || typeof parsed.sig !== 'string') {
    return { valid: false, payload: null, error: 'MISSING_SIGNATURE' };
  }

  for (const claim of REQUIRED_CLAIMS) {
    if (parsed[claim] === undefined || parsed[claim] === null || parsed[claim] === '') {
      return { valid: false, payload: null, error: 'MISSING_CLAIMS' };
    }
  }

  if (parsed.v !== TOKEN_VERSION) {
    return { valid: false, payload: null, error: 'UNSUPPORTED_VERSION' };
  }

  const payload = canonicalPayload(parsed);
  const expectedSig = hmac(JSON.stringify(payload), secret);
  const sigBuf = Buffer.from(parsed.sig, 'hex');
  const expBuf = Buffer.from(expectedSig, 'hex');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return { valid: false, payload: null, error: 'INVALID_SIGNATURE' };
  }

  const now = typeof opts.now === 'number' ? opts.now : Date.now();
  if (typeof payload.iat !== 'number' || payload.iat > now + MAX_CLOCK_SKEW_MS) {
    return { valid: false, payload: null, error: 'INVALID_IAT' };
  }
  if (typeof payload.exp !== 'number' || now > payload.exp) {
    return { valid: false, payload: null, error: 'TOKEN_EXPIRED' };
  }

  if (opts.expectedDestination &&
      String(opts.expectedDestination).toLowerCase() !== payload.destinationDomain) {
    return { valid: false, payload: null, error: 'DOMAIN_MISMATCH' };
  }
  if (opts.expectedTenant !== undefined && opts.expectedTenant !== null &&
      String(opts.expectedTenant) !== String(payload.tenantId)) {
    return { valid: false, payload: null, error: 'TENANT_MISMATCH' };
  }

  return { valid: true, payload: payload, error: null };
}

/**
 * Simple in-memory replay store (single-process). Distributed replay
 * protection is a deployment concern (see SECURITY.md).
 */
function createInMemoryReplayStore() {
  const used = new Map();

  function sweep(now) {
    for (const [key, expiry] of used) {
      if (now > expiry) used.delete(key);
    }
  }

  return {
    isTokenUsed: function (tokenHash) {
      sweep(Date.now());
      return Promise.resolve(used.has(tokenHash));
    },
    markTokenUsed: function (tokenHash, expiresInMs) {
      used.set(tokenHash, Date.now() + (expiresInMs || DEFAULT_TTL_MS));
      return Promise.resolve();
    },
    /**
     * Atomically consume a token: returns true if this caller won (token was
     * unused and is now marked used), false if it was already consumed.
     * The check-and-set happens synchronously, so concurrent verifications
     * of the same token cannot both succeed.
     */
    consumeToken: function (tokenHash, expiresInMs) {
      const now = Date.now();
      sweep(now);
      if (used.has(tokenHash)) return Promise.resolve(false);
      used.set(tokenHash, now + (expiresInMs || DEFAULT_TTL_MS));
      return Promise.resolve(true);
    }
  };
}

module.exports = {
  TOKEN_VERSION,
  DEFAULT_TTL_MS,
  signCrossDomainToken,
  verifyCrossDomainToken,
  hashToken,
  createInMemoryReplayStore
};
