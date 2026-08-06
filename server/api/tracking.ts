/**
 * Nylo Tracking API — Batch Event Ingestion
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

import type { Request, Response } from "express";
import crypto from "crypto";
import {
  validateDomain,
  validateEventType,
  sanitizeFormData
} from '../utils/input-validation';

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

function validateAndSanitizeEvent(eventItem: any): any | null {
  const sanitized = sanitizeFormData(eventItem);

  let eventType = sanitized.eventType || sanitized.interactionType;
  if (!eventType || typeof eventType !== 'string') return null;

  try {
    eventType = validateEventType(eventType);
  } catch {
    eventType = 'custom';
  }

  let domain = sanitized.domain;
  if (!domain || typeof domain !== 'string') return null;

  try {
    domain = validateDomain(domain);
  } catch {
    return null;
  }

  const sessionId = sanitized.sessionId;
  if (!sessionId || typeof sessionId !== 'string') return null;

  return {
    eventType,
    domain,
    sessionId,
    url: sanitized.url || sanitized.pageUrl || '',
    userId: sanitized.userId || null,
    metadata: sanitized.metadata || '',
    timestamp: sanitized.timestamp,
    rest: Object.keys(sanitized).reduce((acc: any, key: string) => {
      if (!['eventType', 'interactionType', 'domain', 'sessionId', 'url', 'pageUrl', 'userId', 'metadata', 'timestamp'].includes(key)) {
        acc[key] = sanitized[key];
      }
      return acc;
    }, {})
  };
}

export function registerTrackingRoutes(app: any, storage: TrackingStorage) {
  // CORS (including OPTIONS preflight) is handled centrally in server/index.ts.
  app.post("/api/track", async (req: Request, res: Response) => {
    try {
      const events = req.body.events || [req.body];

      if (!events || events.length === 0) {
        return res.status(400).json({ message: 'No events provided' });
      }

      let processedCount = 0;
      let skippedCount = 0;

      for (const eventItem of events) {
        const validated = validateAndSanitizeEvent(eventItem);
        if (!validated) {
          skippedCount++;
          continue;
        }

        const eventTimestampStr = validated.timestamp ? String(validated.timestamp) : '';
        const dedupString = `${validated.sessionId}:${validated.eventType}:${eventTimestampStr}`;
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
            sessionId: validated.sessionId,
            userId: validated.userId,
            timestamp: new Date(),
            pageUrl: validated.url,
            domain: validated.domain,
            interactionType: validated.eventType,
            content: validated.metadata,
            mainDomain: validated.domain.split('.').length > 2 ? validated.domain.split('.').slice(1).join('.') : validated.domain,
            subdomain: validated.domain.split('.').length > 2 ? validated.domain.split('.')[0] : null,
            customerId: req.headers['x-customer-id'],
            featureName: validated.eventType,
            featureCategory: 'tracking',
            context: { metadata: validated.metadata, ...validated.rest }
          });
          processedCount++;
        } catch (error) {
          console.error('Failed to store event:', validated.eventType);
        }
      }

      res.json({
        success: true,
        eventsProcessed: processedCount,
        eventsSkipped: skippedCount,
        totalEvents: events.length
      });

    } catch (error) {
      console.error('Tracking endpoint error:', error);
      res.status(500).json({ success: false, message: 'Internal server error' });
    }
  });
}
