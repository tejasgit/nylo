// SPDX-License-Identifier: MIT
/**
 * Shared cross-domain token verification route for the Nylo demo servers.
 *
 * Uses the WTX-1 token core: rejects legacy/unsigned tokens, enforces
 * version, jti, iat/exp, tenant + destination-domain binding, and replay
 * protection.
 *
 * Verification is authorized by a write grant BEFORE the token is consumed:
 * without this, any unauthenticated caller who saw a token could "verify"
 * it once and thereby burn it (denial of service against the real
 * destination page) or harvest the identity payload.
 */

'use strict';

const {
  verifyCrossDomainToken,
  hashToken,
  createInMemoryReplayStore
} = require('../server/utils/token-core');
const { verifyWriteGrant } = require('../server/utils/write-grant');

const DEFAULT_TTL_MS = 5 * 60 * 1000;

function registerTokenVerification(app, options) {
  options = options || {};
  const secret = options.secret;
  if (!secret) throw new Error('registerTokenVerification requires a signing secret');
  const grantSecret = options.grantSecret || secret;
  const production = options.production !== undefined
    ? !!options.production
    : process.env.NODE_ENV === 'production';
  if (production && !options.replayStore) {
    // Fail loud at startup, not silently at replay time: an in-memory store
    // forgets consumed tokens on restart and is not shared across
    // instances, so "single-use" would be a lie in production.
    throw new Error(
      '[Nylo] Production requires a durable shared replayStore with atomic ' +
      'consumeToken() (database/distributed cache). The in-memory fallback ' +
      'is development-only.'
    );
  }
  const replayStore = options.replayStore || createInMemoryReplayStore();
  const ttlMs = options.ttlMs || DEFAULT_TTL_MS;

  app.post('/api/tracking/verify-cross-domain-token', async (req, res) => {
    const { token, domain } = req.body || {};

    if (!token) {
      return res.status(400).json({ success: false, message: 'Token is required' });
    }

    // Authorize the caller for this destination domain first. The grant
    // proves the request comes from a page the server issued a grant to for
    // exactly this domain — only then may the token be consumed.
    const rawGrant = req.headers['x-nylo-grant'];
    const grantValue = Array.isArray(rawGrant) ? rawGrant[0] : rawGrant;
    if (!grantValue) {
      return res.status(401).json({
        success: false,
        error: 'GRANT_REQUIRED',
        message: 'A write grant is required to verify cross-domain tokens'
      });
    }
    const grantResult = verifyWriteGrant(String(grantValue), grantSecret, {
      requiredScope: 'ingest',
      expectedDomain: domain
    });
    if (!grantResult.valid) {
      return res.status(403).json({
        success: false,
        error: 'GRANT_' + (grantResult.error || 'INVALID'),
        message: 'Write grant rejected: ' + (grantResult.error || 'INVALID')
      });
    }

    // Tenant comes from the authenticated grant, never from the body.
    const result = verifyCrossDomainToken(token, secret, {
      expectedDestination: domain,
      expectedTenant: String(grantResult.payload.tenantId)
    });

    if (!result.valid) {
      const status = result.error === 'MALFORMED_TOKEN' ? 400 : 403;
      return res.status(status).json({
        success: false,
        error: result.error,
        message: 'Cross-domain token rejected: ' + result.error
      });
    }

    // Atomic consume: exactly one concurrent verification of the same
    // token can win; all others are rejected as replays. Consumption only
    // happens AFTER authorization + validity checks succeed.
    const tokenHash = hashToken(token);
    const won = await replayStore.consumeToken(tokenHash, ttlMs);
    if (!won) {
      return res.status(403).json({
        success: false,
        error: 'TOKEN_REPLAYED',
        message: 'Token has already been used (replay detected)'
      });
    }

    return res.json({
      success: true,
      verified: true,
      identity: {
        sessionId: result.payload.sessionId,
        waiTag: result.payload.waiTag,
        userId: result.payload.userId || null
      },
      domain: result.payload.destinationDomain,
      verifiedAt: new Date().toISOString(),
      message: 'Token verified'
    });
  });

  return { replayStore };
}

module.exports = { registerTokenVerification, DEFAULT_TTL_MS };
