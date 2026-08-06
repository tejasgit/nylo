// SPDX-License-Identifier: MIT
/**
 * Shared /api/track ingestion logic for the Nylo demo servers.
 *
 * Uses the versioned event envelope contract from shared/event-envelope.js:
 * parses/validates the batch, expands common fields, dedupes on the
 * client-generated eventId, and reports per-event results.
 */

const { parseEnvelope } = require('../shared/event-envelope');

const DEDUP_WINDOW_MS = 60 * 1000;

function createTrackHandler(storeEvent) {
  const dedupCache = new Map();
  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const [key, expireAt] of dedupCache) {
      if (now > expireAt) dedupCache.delete(key);
    }
  }, 60 * 1000);
  if (cleanup.unref) cleanup.unref();

  return async function trackHandler(req, res) {
    const parsed = parseEnvelope(req.body);
    if (!parsed.ok) {
      return res.status(parsed.status).json({
        success: false,
        error: parsed.error,
        message: parsed.message
      });
    }

    const receivedAt = new Date().toISOString();
    const customerId = req.headers['x-customer-id'] || parsed.common.customerId || '1';
    const results = [];
    let processedCount = 0;

    for (let i = 0; i < parsed.events.length; i++) {
      const event = parsed.events[i];
      const eventId = typeof event.eventId === 'string' ? event.eventId : null;
      const eventType = event.eventType || event.interactionType;

      if (!eventType) {
        results.push({ index: i, eventId, status: 'rejected', reason: 'missing_event_type' });
        continue;
      }

      if (eventId) {
        const expireAt = dedupCache.get(eventId);
        if (expireAt !== undefined && Date.now() < expireAt) {
          results.push({ index: i, eventId, status: 'duplicate' });
          continue;
        }
      }

      const sessionId = event.sessionId || req.headers['x-session-id'] || 'unknown';
      const domain = event.domain || 'localhost';
      const waiTag = event.waiTag || req.headers['x-waitag'] || null;
      const userId = event.userId || waiTag;

      try {
        await storeEvent({
          eventId,
          eventType,
          sessionId,
          domain,
          waiTag,
          userId,
          customerId,
          url: event.url || event.pageUrl || '',
          metadata: event.metadata || {},
          clientTimestamp: event.timestamp || null,
          receivedAt
        });
        // Commit dedup only after storage succeeded, so a failed store
        // can be retried by the client without being reported as duplicate.
        if (eventId) dedupCache.set(eventId, Date.now() + DEDUP_WINDOW_MS);
        processedCount++;
        results.push({ index: i, eventId, status: 'stored' });
      } catch (err) {
        console.error('Failed to store event:', err.message);
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
  };
}

module.exports = { createTrackHandler };
