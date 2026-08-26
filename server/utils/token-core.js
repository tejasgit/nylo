/**
 * SPDX-License-Identifier: LicenseRef-Nylo-Commercial
 *
 * Nylo Cross-Domain Token Core (WTX-1, version 2)
 *
 * Encrypted AND signed, versioned, replay-resistant cross-domain tokens.
 *
 * v2 format (sign-then-encrypt):
 *   inner payload  = { v, jti, iat, exp, tenantId, sourceDomain,
 *                      destinationDomain, waiTag, sessionId, userId }
 *   sig            = HMAC-SHA256(JSON(payload), macKey)            [hex]
 *   plaintext      = JSON({ ...payload, sig })
 *   ciphertext     = AES-256-GCM(plaintext, encKey, iv, aad)
 *   token          = base64(JSON({ v, tid, dst, iv, ct, tag }))
 *
 * Key derivation (domain-specific encryption keys): encKey and macKey are
 * derived per (tenant, destination domain, purpose) with HKDF-SHA256 from
 * the master token secret. A token minted for one destination cannot be
 * decrypted or verified under another destination's keys, so contextual
 * information is cryptographically separated across domains — not just
 * checked by a claim comparison after the fact.
 *
 * The only cleartext fields (tid, dst) are routing metadata required to
 * derive the decryption keys; they carry no user context and are also
 * bound into the AEAD associated data and duplicated inside the encrypted
 * payload, so tampering with them is detected twice.
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under the Nylo Commercial License (see COMMERCIAL-LICENSE).
 * Free for personal, academic, and evaluation use; commercial production
 * use requires a commercial license. See LICENSING.md.
 *
 * COMMERCIAL NOTICE: part of the WTX-1 protocol covered by COMMERCIAL-LICENSE.
 */

'use strict';

const crypto = require('crypto');

const TOKEN_VERSION = 2;
const DEFAULT_TTL_MS = 5 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 60 * 1000;
const MAX_TOKEN_CHARS = 16 * 1024;
const MAX_CIPHERTEXT_BYTES = 8 * 1024;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;

const HKDF_SALT = 'nylo-wtx1-v2';
const AAD_PREFIX = 'WTX1|v2|';

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

/**
 * Derives a purpose-specific 256-bit key bound to tenant + destination
 * domain. Distinct purposes ('enc', 'mac') yield independent keys, so the
 * encryption key is never reused as a MAC key.
 */
function deriveTokenKey(secret, purpose, tenantId, destinationDomain) {
  const info = purpose + '|' + String(tenantId) + '|' + String(destinationDomain).toLowerCase();
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(String(secret), 'utf-8'), Buffer.from(HKDF_SALT, 'utf-8'), Buffer.from(info, 'utf-8'), 32));
}

function tokenAad(tenantId, destinationDomain) {
  return Buffer.from(AAD_PREFIX + String(tenantId) + '|' + String(destinationDomain).toLowerCase(), 'utf-8');
}

function hmac(data, key) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Creates an encrypted, signed cross-domain token bound to tenant +
 * source + destination. Throws when a required claim is missing.
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
  const tenantId = String(claims.tenantId);
  const destinationDomain = String(claims.destinationDomain).toLowerCase();
  const payload = canonicalPayload({
    v: TOKEN_VERSION,
    jti: opts.jti || crypto.randomBytes(16).toString('hex'),
    iat: now,
    exp: now + (typeof opts.ttlMs === 'number' ? opts.ttlMs : DEFAULT_TTL_MS),
    tenantId: tenantId,
    sourceDomain: String(claims.sourceDomain).toLowerCase(),
    destinationDomain: destinationDomain,
    waiTag: claims.waiTag,
    sessionId: claims.sessionId,
    userId: claims.userId === undefined ? null : claims.userId
  });

  const macKey = deriveTokenKey(secret, 'mac', tenantId, destinationDomain);
  const sig = hmac(JSON.stringify(payload), macKey);
  const plaintext = Buffer.from(JSON.stringify(Object.assign({}, payload, { sig: sig })), 'utf-8');

  const encKey = deriveTokenKey(secret, 'enc', tenantId, destinationDomain);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
  cipher.setAAD(tokenAad(tenantId, destinationDomain));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const envelope = {
    v: TOKEN_VERSION,
    tid: tenantId,
    dst: destinationDomain,
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: tag.toString('base64')
  };
  return Buffer.from(JSON.stringify(envelope)).toString('base64');
}

/**
 * Decrypts and verifies a token: envelope shape, version, AEAD decryption
 * under the destination-specific key, inner HMAC signature, claim
 * completeness, envelope/payload binding, iat/exp and (optionally) the
 * expected destination domain and tenant.
 * Returns { valid, payload, error }.
 */
function verifyCrossDomainToken(token, secret, opts) {
  opts = opts || {};
  if (!secret) return { valid: false, payload: null, error: 'NO_SECRET' };
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_CHARS) {
    return { valid: false, payload: null, error: 'MALFORMED_TOKEN' };
  }

  let envelope;
  try {
    envelope = JSON.parse(Buffer.from(String(token), 'base64').toString('utf-8'));
    if (!envelope || typeof envelope !== 'object') throw new Error('bad');
  } catch {
    return { valid: false, payload: null, error: 'MALFORMED_TOKEN' };
  }

  // Legacy v1 (signed-but-cleartext) tokens and unknown versions are
  // rejected outright — confidentiality is not optional in v2.
  if (envelope.v !== TOKEN_VERSION) {
    return { valid: false, payload: null, error: 'UNSUPPORTED_VERSION' };
  }

  if (!envelope.tag || typeof envelope.tag !== 'string') {
    return { valid: false, payload: null, error: 'MISSING_SIGNATURE' };
  }
  if (typeof envelope.tid !== 'string' || envelope.tid === '' ||
      typeof envelope.dst !== 'string' || envelope.dst === '' ||
      typeof envelope.iv !== 'string' || envelope.iv === '' ||
      typeof envelope.ct !== 'string' || envelope.ct === '') {
    return { valid: false, payload: null, error: 'MALFORMED_TOKEN' };
  }
  if (envelope.tid.length > 128 || envelope.dst.length > 253 ||
      envelope.iv.length > 32 || envelope.tag.length > 32 ||
      envelope.ct.length > Math.ceil(MAX_CIPHERTEXT_BYTES * 4 / 3) + 4) {
    return { valid: false, payload: null, error: 'MALFORMED_TOKEN' };
  }

  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ciphertext = Buffer.from(envelope.ct, 'base64');
  if (iv.length !== GCM_IV_BYTES || tag.length !== GCM_TAG_BYTES ||
      ciphertext.length === 0 || ciphertext.length > MAX_CIPHERTEXT_BYTES) {
    return { valid: false, payload: null, error: 'MALFORMED_TOKEN' };
  }

  // Cheap pre-decryption routing checks give precise error codes; the
  // cryptographic binding below re-enforces both regardless.
  if (opts.expectedDestination &&
      String(opts.expectedDestination).toLowerCase() !== envelope.dst) {
    return { valid: false, payload: null, error: 'DOMAIN_MISMATCH' };
  }
  if (opts.expectedTenant !== undefined && opts.expectedTenant !== null &&
      String(opts.expectedTenant) !== envelope.tid) {
    return { valid: false, payload: null, error: 'TENANT_MISMATCH' };
  }

  let plaintext;
  try {
    const encKey = deriveTokenKey(secret, 'enc', envelope.tid, envelope.dst);
    const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, iv);
    decipher.setAAD(tokenAad(envelope.tid, envelope.dst));
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf-8');
  } catch {
    // Wrong key (wrong secret, tenant or destination) or tampered
    // ciphertext/AAD — all surface as an AEAD authentication failure.
    return { valid: false, payload: null, error: 'INVALID_SIGNATURE' };
  }

  let parsed;
  try {
    parsed = JSON.parse(plaintext);
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
  const macKey = deriveTokenKey(secret, 'mac', envelope.tid, envelope.dst);
  const expectedSig = hmac(JSON.stringify(payload), macKey);
  const sigBuf = Buffer.from(parsed.sig, 'hex');
  const expBuf = Buffer.from(expectedSig, 'hex');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return { valid: false, payload: null, error: 'INVALID_SIGNATURE' };
  }

  // The routing metadata the keys were derived from must match the signed
  // payload — a spoofed envelope cannot smuggle a foreign payload.
  if (payload.tenantId !== envelope.tid || payload.destinationDomain !== envelope.dst) {
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
