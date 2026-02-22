/**
 * Nylo Tracking API — Batch Event Ingestion
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

import type { Request, Response } from "express";
import crypto from "crypto";

const dedupCache = new Map<string, number>();
const DEDUP_WINDOW_MS = parseInt(process.env.TRACKING_DEDUP_WINDOW_SECONDS || '60', 10) * 1000;

function cleanupDedupCache() {
  const now = Date.now();
  for (const [key, expireAt] of dedupCache.entries()) {
    if (now > expireAt) {
      dedupCache.delete(key);
    }
  }
}

setInterval(cleanupDedupCache, 60000).unref();

export interface TrackingStorage {
  createInteraction(data: any): Promise<any>;
}

export function registerTrackingRoutes(app: any, storage: TrackingStorage) {
  app.options("/api/track", (req: Request, res: Response) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, X-Customer-ID, X-Session-ID, X-WaiTag, X-Batch-Size, X-SDK-Version');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.status(200).send();
  });

  app.post("/api/track", async (req: Request, res: Response) => {
    try {
      const events = req.body.events || [req.body];

      if (!events || events.length === 0) {
        return res.status(400).json({ message: 'No events provided' });
      }

      let processedCount = 0;

      for (const eventItem of events) {
        let {
          eventType,
          domain,
          sessionId,
          timestamp,
          url,
          pageUrl,
          userId,
          metadata,
          ...eventData
        } = eventItem;

        if (!url && pageUrl) url = pageUrl;

        if (!sessionId || !eventType || !domain) continue;

        const eventTimestampStr = timestamp ? String(timestamp) : '';
        const dedupString = `${sessionId}:${eventType}:${eventTimestampStr}`;
        const dedupKey = crypto.createHash('sha256').update(dedupString).digest('hex');

        const now = Date.now();
        if (dedupCache.has(dedupKey)) {
          const expireAt = dedupCache.get(dedupKey)!;
          if (now < expireAt) {
            continue;
          }
        }

        dedupCache.set(dedupKey, now + DEDUP_WINDOW_MS);

        try {
          await storage.createInteraction({
            sessionId,
            userId: userId || null,
            timestamp: new Date(),
            pageUrl: url || pageUrl || '',
            domain,
            interactionType: eventType,
            content: metadata || '',
            mainDomain: domain.split('.').length > 2 ? domain.split('.').slice(1).join('.') : domain,
            subdomain: domain.split('.').length > 2 ? domain.split('.')[0] : null,
            customerId: req.headers['x-customer-id'],
            featureName: eventType,
            featureCategory: 'tracking',
            context: { metadata: metadata || '', ...eventData }
          });
          processedCount++;
        } catch (error) {
          console.error('Failed to store event:', eventType);
        }
      }

      res.json({
        success: true,
        eventsProcessed: processedCount,
        totalEvents: events.length
      });

    } catch (error) {
      console.error('Tracking endpoint error:', error);
      res.status(500).json({ success: false, message: 'Internal server error' });
    }
  });
}
