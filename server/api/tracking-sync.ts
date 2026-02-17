/**
 * Nylo Cross-Domain Identity Synchronization
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 *
 * COMMERCIAL NOTICE: Cross-domain identity synchronization is part of
 * the WTX-1 protocol covered by LICENSE-COMMERCIAL.
 */

import type { Request, Response } from "express";

export interface SyncStorage {
  getCustomer(id: number): Promise<any>;
  getCustomerByApiKey(apiKey: string): Promise<any>;
  createInteraction(data: any): Promise<any>;
}

export function registerTrackingSyncRoutes(app: any, storage: SyncStorage) {
  app.options('/api/tracking/sync-identity', (req: Request, res: Response) => {
    const origin = req.headers.origin || '*';
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-API-Key, Cookie');
    res.header('Access-Control-Max-Age', '86400');
    res.status(200).send();
  });

  app.post('/api/tracking/sync-identity', async (req: Request, res: Response) => {
    try {
      const origin = req.headers.origin || '*';
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-API-Key');
      res.header('Access-Control-Allow-Credentials', 'true');

      let { customerId, waiTag, currentSite, domain } = req.body;
      const apiKey = req.headers['x-api-key'] as string;

      if (!waiTag) {
        waiTag = req.body.waitag || req.body.userId ||
          'wai-temp-' + Date.now() + '-' + Math.random().toString(36).substring(2, 8);
      }

      if (!currentSite) {
        currentSite = 'unknown';
      }

      const crossDomainMap = req.app.locals.crossDomainMap = req.app.locals.crossDomainMap || {};
      const userAgent = req.body.browserFingerprint || req.headers['user-agent'] || '';
      const fingerprint = userAgent + '-' + req.ip;

      if (currentSite !== 'unknown') {
        crossDomainMap[fingerprint] = crossDomainMap[fingerprint] || {};
        crossDomainMap[fingerprint][currentSite + 'WaiTag'] = waiTag;
      }

      const entry = crossDomainMap[fingerprint] || {};
      const siteKeys = Object.keys(entry).filter(k => k.endsWith('WaiTag'));
      const hasMultipleSites = siteKeys.length >= 2;

      if (hasMultipleSites) {
        const canonicalWaiTag = entry[siteKeys[0]];

        try {
          const customer = (apiKey ? await storage.getCustomerByApiKey(apiKey) : null) ||
            (customerId ? await storage.getCustomer(parseInt(customerId)) : null);

          if (customer) {
            await storage.createInteraction({
              customerId: customer.id,
              sessionId: req.body.sessionId || '',
              userId: canonicalWaiTag,
              pageUrl: req.body.pageUrl || '',
              domain: domain || 'unknown',
              mainDomain: (domain || '').split('.')[0],
              subdomain: null,
              interactionType: 'cross_domain_identity_match',
              context: {
                sites: Object.fromEntries(siteKeys.map(k => [k, entry[k]])),
                matchedBy: 'fingerprint'
              }
            });
          }
        } catch {}

        return res.json({
          success: true,
          shared: true,
          waiTag: canonicalWaiTag,
          message: 'Cross-domain identity matched'
        });
      }

      return res.json({
        success: true,
        shared: false,
        waiTag: waiTag,
        message: 'Identity synced'
      });
    } catch (error) {
      return res.json({
        success: true,
        shared: false,
        waiTag: req.body.waiTag || 'unknown',
        message: 'Identity sync processed with warnings'
      });
    }
  });
}
