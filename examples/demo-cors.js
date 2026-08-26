// SPDX-License-Identifier: MIT
/**
 * Shared fail-closed CORS middleware for the Nylo demo servers.
 *
 * Exact-origin allowlist (NYLO_ALLOWED_ORIGINS), no arbitrary-origin
 * reflection. When no allowlist is configured, production denies all
 * cross-origin requests and development only allows loopback origins.
 */

'use strict';

const { originAllowed } = require('../server/utils/security-core');

function createCorsMiddleware(options) {
  options = options || {};
  const allowedOrigins = options.allowedOrigins ||
    (process.env.NYLO_ALLOWED_ORIGINS || '').split(',').filter(Boolean);
  const production = options.production !== undefined
    ? options.production
    : process.env.NODE_ENV === 'production';

  return function corsMiddleware(req, res, next) {
    const origin = req.headers.origin;
    res.header('Vary', 'Origin');
    if (origin && originAllowed(origin, allowedOrigins, { production, allowDevLoopback: true })) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      // Browser-facing surface only: identity/tenant headers are gone —
      // tenant identity travels inside the signed write grant, and API keys
      // are server-to-server only (never accepted from browsers).
      res.header('Access-Control-Allow-Headers',
        'Origin, X-Requested-With, Content-Type, Accept, X-Nylo-Grant, X-Batch-Size, X-SDK-Version');
      res.header('Access-Control-Max-Age', '86400');
    }
    if (req.method === 'OPTIONS') return res.status(204).send();
    next();
  };
}

module.exports = { createCorsMiddleware };
