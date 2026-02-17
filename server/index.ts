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
