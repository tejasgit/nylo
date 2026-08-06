// SPDX-License-Identifier: MIT
/**
 * Shared cross-domain token verification route for the Nylo demo servers.
 *
 * Uses the WTX-1 token core: rejects legacy/unsigned tokens, enforces
 * version, jti, iat/exp, tenant + destination-domain binding, and replay
 * protection.
 */

'use strict';

const {
  verifyCrossDomainToken,
  hashToken,
  createInMemoryReplayStore
} = require('../server/utils/token-core');

const DEFAULT_TTL_MS = 5 * 60 * 1000;

function registerTokenVerification(app, options) {
  options = options || {};
  const secret = options.secret;
  if (!secret) throw new Error('registerTokenVerification requires a signing secret');
  const replayStore = options.replayStore || createInMemoryReplayStore();
  const ttlMs = options.ttlMs || DEFAULT_TTL_MS;

  app.post('/api/tracking/verify-cross-domain-token', async (req, res) => {
    const { token, domain, customerId } = req.body || {};

    if (!token) {
      return res.status(400).json({ success: false, message: 'Token is required' });
    }

    const result = verifyCrossDomainToken(token, secret, {
      expectedDestination: domain,
      expectedTenant: customerId
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
    // token can win; all others are rejected as replays.
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
