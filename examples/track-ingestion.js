// SPDX-License-Identifier: MIT
/**
 * Shared /api/track ingestion logic for the Nylo demo servers.
 *
 * Uses the versioned event envelope contract from shared/event-envelope.js:
 * parses/validates the batch, expands common fields, dedupes on the
 * client-generated eventId, and reports per-event results.
 *
 * Authorization model (mirrors server/api/tracking.ts):
 * - Every request must carry a server-signed write grant (X-Nylo-Grant)
 *   with the 'ingest' scope. The tenant comes from the grant — NEVER from
 *   caller-supplied customer IDs or headers.
 * - Events are only accepted for the domain the grant was issued for.
 * - Fingerprint-capable fields are stripped and URLs reduced to
 *   origin + path before storage (same shared implementations as the
 *   TypeScript server: server/utils/security-core.js).
 */

const { parseEnvelope } = require('../shared/event-envelope');
const { verifyWriteGrant } = require('../server/utils/write-grant');
const { stripFingerprintFields, sanitizeUrlForStorage } = require('../server/utils/security-core');

const DEDUP_WINDOW_MS = 60 * 1000;

function createTrackHandler(storeEvent, options) {
  options = options || {};
  const getGrantSecret = typeof options.grantSecret === 'function'
    ? options.grantSecret
    : function () { return options.grantSecret; };

  const dedupCache = new Map();
  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const [key, expireAt] of dedupCache) {
      if (now > expireAt) dedupCache.delete(key);
    }
  }, 60 * 1000);
  if (cleanup.unref) cleanup.unref();

  return async function trackHandler(req, res) {
    const secret = getGrantSecret();
    if (!secret) {
      return res.status(503).json({
        success: false,
        error: 'GRANTS_UNAVAILABLE',
        message: 'Write grants are not configured on this server'
      });
    }

    const rawGrant = req.headers['x-nylo-grant'];
    const grantValue = Array.isArray(rawGrant) ? rawGrant[0] : rawGrant;
    if (!grantValue) {
      return res.status(401).json({
        success: false,
        error: 'GRANT_REQUIRED',
        message: 'A write grant is required. Obtain one from POST /api/tracking/grant.'
      });
    }
    const grantResult = verifyWriteGrant(String(grantValue), secret, { requiredScope: 'ingest' });
    if (!grantResult.valid) {
      return res.status(403).json({
        success: false,
        error: 'GRANT_' + (grantResult.error || 'INVALID'),
        message: 'Write grant rejected: ' + (grantResult.error || 'INVALID')
      });
    }
    const grant = grantResult.payload;
    const tenantId = String(grant.tenantId);

    const parsed = parseEnvelope(req.body);
    if (!parsed.ok) {
      return res.status(parsed.status).json({
        success: false,
        error: parsed.error,
        message: parsed.message
      });
    }

    // The envelope may still carry a legacy customerId field. It must never
    // disagree with the authenticated tenant.
    const envelopeTenant = parsed.common && parsed.common.customerId;
    if (envelopeTenant !== undefined && envelopeTenant !== null &&
        String(envelopeTenant) !== tenantId) {
      return res.status(403).json({
        success: false,
        error: 'TENANT_MISMATCH',
        message: 'Envelope customerId conflicts with the authenticated tenant'
      });
    }

    const receivedAt = new Date().toISOString();
    const results = [];
    let processedCount = 0;

    for (let i = 0; i < parsed.events.length; i++) {
      const event = stripFingerprintFields(parsed.events[i]);
      const eventId = typeof event.eventId === 'string' ? event.eventId : null;
      const eventType = event.eventType || event.interactionType;

      if (!eventType) {
        results.push({ index: i, eventId, status: 'rejected', reason: 'missing_event_type' });
        continue;
      }

      // Domain binding: this grant only authorizes writes for its domain.
      const eventDomain = typeof event.domain === 'string' ? event.domain.trim().toLowerCase() : '';
      if (eventDomain && eventDomain !== grant.domain) {
        results.push({ index: i, eventId, status: 'rejected', reason: 'domain_not_authorized' });
        continue;
      }

      // Per-event tenant assertions must also agree with the grant.
      if (event.customerId !== undefined && event.customerId !== null &&
          String(event.customerId) !== tenantId) {
        results.push({ index: i, eventId, status: 'rejected', reason: 'tenant_mismatch' });
        continue;
      }

      if (eventId) {
        // Dedup is scoped per tenant so one tenant's eventId can never
        // shadow another tenant's event.
        const dedupKey = tenantId + ':' + eventId;
        const expireAt = dedupCache.get(dedupKey);
        if (expireAt !== undefined && Date.now() < expireAt) {
          results.push({ index: i, eventId, status: 'duplicate' });
          continue;
        }
      }

      const sessionId = event.sessionId || 'unknown';
      const domain = eventDomain || grant.domain;
      const waiTag = event.waiTag || null;
      const userId = event.userId || waiTag;

      try {
        await storeEvent({
          eventId,
          eventType,
          sessionId,
          domain,
          waiTag,
          userId,
          customerId: tenantId,
          url: sanitizeUrlForStorage(event.url || event.pageUrl || ''),
          metadata: event.metadata || {},
          clientTimestamp: event.timestamp || null,
          receivedAt
        });
        // Commit dedup only after storage succeeded, so a failed store
        // can be retried by the client without being reported as duplicate.
        if (eventId) dedupCache.set(tenantId + ':' + eventId, Date.now() + DEDUP_WINDOW_MS);
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
