/**
 * SPDX-License-Identifier: MIT
 *
 * Nylo Server — Express.js Integration Entry Point
 *
 * This file shows how to integrate Nylo tracking into an Express.js server.
 * Adapt the storage implementation to your database.
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

import express from 'express';
import { registerTrackingRoutes } from './api/tracking';
import { registerWaiTagTrackingRoutes } from './api/waitag-tracking';
import { registerDnsVerificationRoutes } from './api/dns-verify';
import { registerGrantRoutes } from './api/grant';
import { originAllowed, isValidDomainName } from './utils/security-core';

export interface NyloServerOptions {
  allowedOrigins?: string[];
  enforceHttps?: boolean;
  /**
   * Canonical public host (`analytics.example.com` or `host:port`) used as
   * the HTTPS redirect target. Required when enforceHttps is on: redirects
   * must never be built from the client-controlled Host header.
   * Falls back to the NYLO_CANONICAL_HOST environment variable.
   */
  canonicalHost?: string;
}

function isValidCanonicalHost(value: string): boolean {
  const colon = value.indexOf(':');
  const host = colon === -1 ? value : value.slice(0, colon);
  const port = colon === -1 ? '' : value.slice(colon + 1);
  if (port !== '' && !/^\d{1,5}$/.test(port)) return false;
  return isValidDomainName(host);
}

export function setupNyloRoutes(app: express.Express, storage: any, options?: NyloServerOptions) {
  const allowedOrigins = options?.allowedOrigins || [];
  const isProduction = process.env.NODE_ENV === 'production';
  const enforceHttps = options?.enforceHttps ?? isProduction;

  // Fail closed at startup: a production deployment without these is not a
  // hardened deployment, it only looks like one.
  if (isProduction) {
    if (!process.env.NYLO_TOKEN_SECRET) {
      throw new Error('[Nylo] NYLO_TOKEN_SECRET must be set in production — it signs write grants and cross-domain tokens.');
    }
    if (!storage?.tokenReplayStore || typeof storage.tokenReplayStore.consumeToken !== 'function') {
      throw new Error('[Nylo] Production requires storage.tokenReplayStore with atomic consumeToken() — durable and shared across processes. The in-memory fallback is development-only.');
    }
    if (typeof storage?.getTenantIdForDomain !== 'function') {
      throw new Error('[Nylo] Production requires storage.getTenantIdForDomain(domain) so tenants are resolved from server-side configuration.');
    }
  }

  if (enforceHttps) {
    const canonicalHost = String(options?.canonicalHost || process.env.NYLO_CANONICAL_HOST || '').trim().toLowerCase();
    const trustProxyConfigured = Boolean(app.get('trust proxy'));
    if (!canonicalHost || !isValidCanonicalHost(canonicalHost)) {
      const msg = '[Nylo] enforceHttps requires a valid canonicalHost option (or NYLO_CANONICAL_HOST) — redirect targets are never derived from the client-controlled Host header.';
      if (isProduction) throw new Error(msg);
      console.warn(msg + ' HTTPS redirect disabled (development).');
    } else if (!trustProxyConfigured) {
      // Without a trust-proxy setting, req.secure ignores X-Forwarded-Proto,
      // so behind any TLS-terminating proxy every request would look
      // insecure and loop forever. Skip rather than trust raw headers.
      console.warn('[Nylo] enforceHttps: Express "trust proxy" is not configured — HTTP→HTTPS redirect middleware disabled to avoid redirect loops. Call app.set("trust proxy", 1) (or redirect at the load balancer).');
    } else {
      app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
        // req.secure honors "trust proxy": X-Forwarded-Proto is only
        // believed when it comes from a configured trusted hop.
        if (req.secure) return next();
        return res.redirect(301, 'https://' + canonicalHost + req.url);
      });
    }
  }

  app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'SAMEORIGIN');
    res.header('X-XSS-Protection', '1; mode=block');
    res.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'");
    // req.secure honors "trust proxy" — raw X-Forwarded-Proto is never
    // trusted here (any client can send that header).
    if (req.secure) {
      res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  });

  // Centralized CORS. Exact-origin allowlist with host-boundary wildcard
  // matching; no arbitrary-origin reflection. Fail-closed: when no
  // allowlist is configured, production denies all cross-origin requests
  // and development only allows loopback origins.
  if (allowedOrigins.length === 0) {
    if (isProduction) {
      console.error('[Nylo] SECURITY: No allowedOrigins configured — all cross-origin requests will be rejected. Set allowedOrigins.');
    } else {
      console.warn('[Nylo] No allowedOrigins configured — only loopback origins (localhost/127.0.0.1) are allowed in development.');
    }
  }

  app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
    const origin = req.headers.origin;
    res.header('Vary', 'Origin');
    if (origin && originAllowed(origin, allowedOrigins, { production: isProduction, allowDevLoopback: true })) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      // Browser-facing surface only: identity/tenant headers (X-Customer-ID,
      // X-WaiTag, X-Session-ID) are gone — tenant identity travels inside
      // the signed write grant. API keys are server-to-server and are not
      // accepted from browsers.
      res.header('Access-Control-Allow-Headers',
        'Origin, X-Requested-With, Content-Type, Accept, X-Nylo-Grant, X-Batch-Size, X-SDK-Version');
      res.header('Access-Control-Max-Age', '86400');
    }
    if (req.method === 'OPTIONS') return res.status(204).send();
    next();
  });

  const rateLimitMap = new Map<string, number>();
  const RATE_LIMIT_WINDOW = 60 * 1000;
  const RATE_LIMIT_MAX = 100;

  // unref() so this housekeeping timer never keeps the process alive.
  const rateLimitTimer = setInterval(() => { rateLimitMap.clear(); }, RATE_LIMIT_WINDOW);
  if (typeof rateLimitTimer.unref === 'function') rateLimitTimer.unref();

  app.use('/api/', (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const key = req.ip || 'unknown';
    const current = rateLimitMap.get(key) || 0;
    if (current >= RATE_LIMIT_MAX) {
      return res.status(429).json({
        success: false,
        message: 'Rate limit exceeded. Try again later.',
        retryAfter: Math.ceil(RATE_LIMIT_WINDOW / 1000)
      });
    }
    rateLimitMap.set(key, current + 1);
    res.header('X-RateLimit-Limit', String(RATE_LIMIT_MAX));
    res.header('X-RateLimit-Remaining', String(RATE_LIMIT_MAX - current - 1));
    next();
  });

  registerGrantRoutes(app, storage);
  registerTrackingRoutes(app, storage);
  registerWaiTagTrackingRoutes(app, storage);
  registerDnsVerificationRoutes(app, storage);
}

export { registerTrackingRoutes } from './api/tracking';
export { registerWaiTagTrackingRoutes, TokenReplayStore } from './api/waitag-tracking';
export { registerGrantRoutes, requireWriteGrant } from './api/grant';
export { registerDnsVerificationRoutes } from './api/dns-verify';
export { generateWaiTagId, generateSessionId, generateApiKey } from './utils/secure-id';
export {
  generateVerificationToken,
  verifyDomainOwnership,
  checkSubdomainOwnership,
  extractParentDomain,
  getDnsRecordValue,
  getTxtRecordInstruction
} from './utils/dns-verification';
