/**
 * SPDX-License-Identifier: MIT
 *
 * Nylo Tracking API — Batch Event Ingestion
 *
 * Write authorization: every batch must carry a server-signed write grant
 * (see server/api/grant.ts). The tenant an event is stored under comes from
 * the grant — caller-supplied customer IDs are never trusted, and any
 * conflicting ID in the payload is rejected loudly.
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

import type { Request, Response } from "express";
import crypto from "crypto";
import {
  validateDomain,
  validateEventType,
  validateSessionId,
  validateClientTimestamp,
  sanitizeFormData,
  sanitizeUrlForStorage,
  stripFingerprintFields
} from '../utils/input-validation';
import { splitRegistrableDomain } from '../utils/security-core';
import { parseEnvelope } from '../../shared/event-envelope';
import { requireWriteGrant } from './grant';

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

/**
 * Strict per-event validation: invalid events are rejected with a specific
 * reason, never silently "fixed" (the old code laundered unknown event types
 * into 'custom' and dropped invalid domains to null).
 */
function validateAndSanitizeEvent(eventItem: any): { ok: true; event: any } | { ok: false; reason: string } {
  const sanitized = stripFingerprintFields(sanitizeFormData(eventItem));

  const rawType = sanitized.eventType || sanitized.interactionType;
  if (!rawType || typeof rawType !== 'string') return { ok: false, reason: 'missing_event_type' };
  let eventType: string;
  try {
    eventType = validateEventType(rawType);
  } catch {
    return { ok: false, reason: 'invalid_event_type' };
  }

  const rawDomain = sanitized.domain;
  if (!rawDomain || typeof rawDomain !== 'string') return { ok: false, reason: 'missing_domain' };
  let domain: string;
  try {
    domain = validateDomain(rawDomain);
  } catch {
    return { ok: false, reason: 'invalid_domain' };
  }

  if (!sanitized.sessionId || typeof sanitized.sessionId !== 'string') {
    return { ok: false, reason: 'missing_session_id' };
  }
  let sessionId: string;
  try {
    sessionId = validateSessionId(sanitized.sessionId);
  } catch {
    return { ok: false, reason: 'invalid_session_id' };
  }

  let clientTimestamp: string | null = null;
  if (sanitized.timestamp !== undefined && sanitized.timestamp !== null && sanitized.timestamp !== '') {
    try {
      clientTimestamp = validateClientTimestamp(sanitized.timestamp);
    } catch {
      return { ok: false, reason: 'invalid_timestamp' };
    }
  }

  return {
    ok: true,
    event: {
      eventType,
      domain,
      sessionId,
      // Query strings and fragments are never stored (tokens, emails, search
      // terms). Origin + path only.
      url: sanitizeUrlForStorage(sanitized.url || sanitized.pageUrl),
      userId: typeof sanitized.userId === 'string' ? sanitized.userId.substring(0, 128) : null,
      metadata: sanitized.metadata || '',
      timestamp: clientTimestamp,
      customerId: sanitized.customerId,
      rest: Object.keys(sanitized).reduce((acc: any, key: string) => {
        if (!['eventType', 'interactionType', 'domain', 'sessionId', 'url', 'pageUrl', 'userId', 'metadata', 'timestamp', 'customerId'].includes(key)) {
          acc[key] = sanitized[key];
        }
        return acc;
      }, {})
    }
  };
}

export function registerTrackingRoutes(app: any, storage: TrackingStorage) {
  // CORS (including OPTIONS preflight) is handled centrally in server/index.ts.
  app.post("/api/track", async (req: Request, res: Response) => {
    try {
      const auth = requireWriteGrant(req, 'ingest');
      if (auth.ok !== true) {
        const failure = auth as { status: number; error: string; message: string };
        return res.status(failure.status).json({ success: false, error: failure.error, message: failure.message });
      }
      const grant = auth.grant;

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
        if (validated.ok !== true) {
          const failure = validated as { reason: string };
          results.push({ index: i, eventId, status: 'rejected', reason: failure.reason });
          continue;
        }
        const event = validated.event;

        // Domain binding: the grant only authorizes writes for the page
        // domain it was issued to.
        if (event.domain !== grant.domain) {
          results.push({ index: i, eventId, status: 'rejected', reason: 'domain_mismatch' });
          continue;
        }
        // Tenant binding: the tenant comes from the grant. A conflicting
        // caller-supplied customerId is an error, not a suggestion.
        if (event.customerId !== undefined && event.customerId !== null && String(event.customerId) !== String(grant.tenantId)) {
          results.push({ index: i, eventId, status: 'rejected', reason: 'tenant_mismatch' });
          continue;
        }

        // Idempotent dedup, scoped per tenant: prefer the client-generated
        // cryptographic eventId, fall back to a content hash for legacy
        // (schemaVersion 0) events.
        const eventTimestampStr = event.timestamp ? String(event.timestamp) : '';
        const dedupKey = eventId
          ? `id:${grant.tenantId}:${eventId}`
          : crypto.createHash('sha256')
              .update(`${grant.tenantId}:${event.sessionId}:${event.eventType}:${eventTimestampStr}`)
              .digest('hex');

        const expireAt = dedupCache.get(dedupKey);
        if (expireAt !== undefined && Date.now() < expireAt) {
          results.push({ index: i, eventId, status: 'duplicate' });
          continue;
        }

        const split = splitRegistrableDomain(event.domain);

        try {
          await storage.createInteraction({
            sessionId: event.sessionId,
            userId: event.userId,
            timestamp: receivedAt,
            pageUrl: event.url,
            domain: event.domain,
            interactionType: event.eventType,
            content: event.metadata,
            mainDomain: split.registrableDomain || event.domain,
            subdomain: split.subdomain,
            customerId: grant.tenantId,
            featureName: event.eventType,
            featureCategory: 'tracking',
            context: {
              metadata: event.metadata,
              ...event.rest,
              eventId,
              clientTimestamp: event.timestamp,
              serverReceivedAt: receivedAt.toISOString()
            }
          });
          // Commit dedup only after storage succeeded, so a client retry of
          // a storage_failed event is stored instead of reported as duplicate.
          dedupCache.set(dedupKey, Date.now() + DEDUP_WINDOW_MS);
          processedCount++;
          results.push({ index: i, eventId, status: 'stored' });
        } catch (error) {
          console.error('Failed to store event:', event.eventType);
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
