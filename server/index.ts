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
import { originAllowed } from './utils/security-core';

export interface NyloServerOptions {
  allowedOrigins?: string[];
  enforceHttps?: boolean;
}

export function setupNyloRoutes(app: express.Express, storage: any, options?: NyloServerOptions) {
  const allowedOrigins = options?.allowedOrigins || [];
  const enforceHttps = options?.enforceHttps ?? (process.env.NODE_ENV === 'production');

  if (enforceHttps) {
    app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
      if (!req.secure && req.headers['x-forwarded-proto'] !== 'https') {
        return res.redirect(301, 'https://' + req.headers.host + req.url);
      }
      next();
    });
  }

  app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'SAMEORIGIN');
    res.header('X-XSS-Protection', '1; mode=block');
    res.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'");
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
      res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  });

  // Centralized CORS. Exact-origin allowlist with host-boundary wildcard
  // matching; no arbitrary-origin reflection. Fail-closed: when no
  // allowlist is configured, production denies all cross-origin requests
  // and development only allows loopback origins.
  const isProduction = process.env.NODE_ENV === 'production';
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
      res.header('Access-Control-Allow-Headers',
        'Origin, X-Requested-With, Content-Type, Accept, X-API-Key, X-Customer-ID, X-Session-ID, X-WaiTag, X-Batch-Size, X-SDK-Version');
      res.header('Access-Control-Expose-Headers',
        'X-WaiTag, X-Cross-Domain-WaiTag, X-Session-ID');
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

  registerTrackingRoutes(app, storage);
  registerWaiTagTrackingRoutes(app, storage);
  registerDnsVerificationRoutes(app, storage);
}

export { registerTrackingRoutes } from './api/tracking';
export { registerWaiTagTrackingRoutes, TokenReplayStore } from './api/waitag-tracking';
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
