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
import { parseEnvelope } from '../../shared/event-envelope';

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
      const parsed = parseEnvelope(req.body);
      if (parsed.ok !== true) {
        // Explicit cast: keeps narrowing robust even when compiled without strict mode.
        const failure = parsed as { status: number; error: string; message: string };
        return res.status(failure.status).json({
          success: false,
          error: failure.error,
          message: failure.message
        });
      }

      const receivedAt = new Date();
      const results: Array<{ index: number; eventId: string | null; status: string; reason?: string }> = [];
      let processedCount = 0;

      for (let i = 0; i < parsed.events.length; i++) {
        const eventItem = parsed.events[i];
        const eventId: string | null = typeof eventItem.eventId === 'string' ? eventItem.eventId : null;

        const validated = validateAndSanitizeEvent(eventItem);
        if (!validated) {
          results.push({ index: i, eventId, status: 'rejected', reason: 'validation_failed' });
          continue;
        }

        // Idempotent dedup: prefer the client-generated cryptographic eventId,
        // fall back to a content hash for legacy (schemaVersion 0) events.
        const eventTimestampStr = validated.timestamp ? String(validated.timestamp) : '';
        const dedupKey = eventId
          ? `id:${eventId}`
          : crypto.createHash('sha256')
              .update(`${validated.sessionId}:${validated.eventType}:${eventTimestampStr}`)
              .digest('hex');

        const expireAt = dedupCache.get(dedupKey);
        if (expireAt !== undefined && Date.now() < expireAt) {
          results.push({ index: i, eventId, status: 'duplicate' });
          continue;
        }

        try {
          await storage.createInteraction({
            sessionId: validated.sessionId,
            userId: validated.userId,
            timestamp: receivedAt,
            pageUrl: validated.url,
            domain: validated.domain,
            interactionType: validated.eventType,
            content: validated.metadata,
            mainDomain: validated.domain.split('.').length > 2 ? validated.domain.split('.').slice(1).join('.') : validated.domain,
            subdomain: validated.domain.split('.').length > 2 ? validated.domain.split('.')[0] : null,
            customerId: req.headers['x-customer-id'],
            featureName: validated.eventType,
            featureCategory: 'tracking',
            context: {
              metadata: validated.metadata,
              ...validated.rest,
              eventId,
              clientTimestamp: validated.timestamp || null,
              serverReceivedAt: receivedAt.toISOString()
            }
          });
          // Commit dedup only after storage succeeded, so a client retry of
          // a storage_failed event is stored instead of reported as duplicate.
          dedupCache.set(dedupKey, Date.now() + DEDUP_WINDOW_MS);
          processedCount++;
          results.push({ index: i, eventId, status: 'stored' });
        } catch (error) {
          console.error('Failed to store event:', validated.eventType);
          results.push({ index: i, eventId, status: 'error', reason: 'storage_failed' });
        }
      }

      res.json({
        success: processedCount > 0 || parsed.events.length === 0,
        schemaVersion: parsed.schemaVersion,
        batchId: parsed.batchId,
        eventsProcessed: processedCount,
        eventsSkipped: parsed.events.length - processedCount,
        totalEvents: parsed.events.length,
        results
      });

    } catch (error) {
      console.error('Tracking endpoint error:', error);
      res.status(500).json({ success: false, message: 'Internal server error' });
    }
  });
}
