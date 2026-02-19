/**
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
import { registerTrackingSyncRoutes } from './api/tracking-sync';
import { registerDnsVerificationRoutes } from './api/dns-verify';

export function setupNyloRoutes(app: express.Express, storage: any) {
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

  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Headers',
        'Origin, X-Requested-With, Content-Type, Accept, X-API-Key, X-Customer-ID, X-Session-ID, X-WaiTag, X-Batch-Size, X-SDK-Version');
      res.header('Access-Control-Expose-Headers',
        'X-WaiTag, X-Cross-Domain-WaiTag, X-Session-ID');
    }
    if (req.method === 'OPTIONS') return res.status(200).send();
    next();
  });

  const rateLimitMap = new Map<string, number>();
  const RATE_LIMIT_WINDOW = 60 * 1000;
  const RATE_LIMIT_MAX = 100;

  setInterval(() => { rateLimitMap.clear(); }, RATE_LIMIT_WINDOW);

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
  registerTrackingSyncRoutes(app, storage);
  registerDnsVerificationRoutes(app, storage);
}

export { registerTrackingRoutes } from './api/tracking';
export { registerWaiTagTrackingRoutes } from './api/waitag-tracking';
export { registerTrackingSyncRoutes } from './api/tracking-sync';
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
