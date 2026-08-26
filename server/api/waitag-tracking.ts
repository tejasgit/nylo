/**
 * SPDX-License-Identifier: LicenseRef-Nylo-Commercial
 *
 * Nylo WaiTag Tracking API — Identity Registration & Cross-Domain Verification
 *
 * Write authorization model:
 * - Browser routes (register-waitag, verify-cross-domain-token, event) require
 *   a server-signed write grant (X-Nylo-Grant). Tenant identity comes from the
 *   grant, never from caller-supplied customer IDs.
 * - Server-to-server token generation authenticates with a per-tenant API key
 *   resolved through storage.getCustomerByApiKey(); there is no shared global
 *   key and the caller cannot pick a different tenant than the key resolves to.
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under the Nylo Commercial License (see COMMERCIAL-LICENSE).
 * Free for personal, academic, and evaluation use; commercial production
 * use requires a commercial license. See LICENSING.md.
 *
 * COMMERCIAL NOTICE: Cross-domain token verification endpoints are part of
 * the WTX-1 protocol covered by COMMERCIAL-LICENSE.
 */

import type { Request, Response } from "express";
import {
  signCrossDomainToken,
  verifyCrossDomainToken,
  hashToken,
  createInMemoryReplayStore,
  DEFAULT_TTL_MS
} from '../utils/token-core';
import { generateWaiTagId, generateSessionId } from '../utils/secure-id';
import {
  validateWaiTagId,
  validateDomain,
  validateApiKey,
  validateSessionId,
  validateClientTimestamp,
  validateTrackingEvent,
  sanitizeFormData,
  sanitizeUrlForStorage,
  stripFingerprintFields
} from '../utils/input-validation';
import { requireWriteGrant } from './grant';

export interface TokenReplayStore {
  isTokenUsed(tokenHash: string): Promise<boolean>;
  markTokenUsed(tokenHash: string, expiresInMs?: number): Promise<void>;
  /**
   * Atomically consume a token: resolves true if this caller won (the token
   * was unused and is now marked used), false if it was already consumed.
   * Implement with a conditional insert (e.g. INSERT ... ON CONFLICT DO
   * NOTHING / SET NX) so concurrent verifications cannot both succeed.
   */
  consumeToken?(tokenHash: string, expiresInMs?: number): Promise<boolean>;
}

export interface WaiTagStorage {
  getCustomer(id: number): Promise<any>;
  getCustomerByApiKey(apiKey: string): Promise<any>;
  createInteraction(data: any): Promise<any>;
  parseDomain(domain: string): { mainDomain: string; subdomain: string | null };
  isDomainVerified?(domain: string, customerId: number): Promise<boolean>;
  getVerifiedDomains?(customerId: number): Promise<string[]>;
  getTenantIdForDomain?(domain: string): Promise<string | number | null>;
  tokenReplayStore?: TokenReplayStore;
}

export function registerWaiTagTrackingRoutes(app: any, storage: WaiTagStorage) {
  const isProduction = process.env.NODE_ENV === 'production';

  // Replay protection must always exist, and in production it must be
  // DURABLE and ATOMIC: an in-memory store silently loses every consumed
  // token on restart and cannot coordinate multiple processes, which turns
  // "replay protection" into a fiction. Fail closed at startup instead.
  let replayStore: TokenReplayStore;
  if (storage.tokenReplayStore) {
    if (isProduction && typeof storage.tokenReplayStore.consumeToken !== 'function') {
      throw new Error('[Nylo] Production requires tokenReplayStore.consumeToken() — an atomic conditional insert. Legacy check+mark stores are development-only.');
    }
    replayStore = storage.tokenReplayStore;
  } else {
    if (isProduction) {
      throw new Error('[Nylo] Production requires a durable storage.tokenReplayStore. In-memory replay protection loses state on restart and does not work across processes.');
    }
    console.warn('[SECURITY] No durable tokenReplayStore provided — using in-memory replay protection (development only, single process).');
    replayStore = createInMemoryReplayStore();
  }

  // Atomic consume. Stores that implement consumeToken() are used directly;
  // legacy check+mark stores are serialized through a per-process promise
  // chain so two concurrent verifications of the same token cannot both win.
  let legacyConsumeChain: Promise<unknown> = Promise.resolve();
  function consumeReplayToken(tokenHash: string, ttlMs: number): Promise<boolean> {
    if (typeof replayStore.consumeToken === 'function') {
      return replayStore.consumeToken(tokenHash, ttlMs);
    }
    const result = legacyConsumeChain.then(async () => {
      const alreadyUsed = await replayStore.isTokenUsed(tokenHash);
      if (alreadyUsed) return false;
      await replayStore.markTokenUsed(tokenHash, ttlMs);
      return true;
    });
    legacyConsumeChain = result.catch(() => undefined);
    return result;
  }

  // Resolves the customer record for a grant's tenant. The grant is signed
  // by us, so a missing customer means configuration drift — reject.
  async function customerFromGrant(tenantId: string): Promise<any | null> {
    const parsed = parseInt(tenantId, 10);
    if (!Number.isNaN(parsed)) {
      const byId = await Promise.resolve(storage.getCustomer(parsed)).catch(() => null);
      if (byId) return byId;
    }
    return null;
  }

  // CORS (including OPTIONS preflight) is handled centrally in server/index.ts.
  app.post("/api/tracking/register-waitag", async (req: Request, res: Response) => {
    try {
      const auth = requireWriteGrant(req, 'register');
      if (auth.ok !== true) {
        const failure = auth as { status: number; error: string; message: string };
        return res.status(failure.status).json({ success: false, error: failure.error, message: failure.message });
      }
      const grant = auth.grant;

      const body = sanitizeFormData(req.body || {});

      // Malformed identifiers are REJECTED, not silently replaced: silently
      // minting a fresh WaiTag hid client bugs and let garbage look like
      // success while the client kept using an identifier the server never
      // registered.
      let validWaiTag: string;
      if (body.waiTag === undefined || body.waiTag === null || body.waiTag === '') {
        validWaiTag = generateWaiTagId();
      } else {
        try {
          validWaiTag = validateWaiTagId(String(body.waiTag));
        } catch {
          return res.status(400).json({ success: false, error: 'INVALID_WAITAG', message: 'Malformed WaiTag identifier.' });
        }
      }

      let sessionId: string;
      if (body.sessionId === undefined || body.sessionId === null || body.sessionId === '') {
        sessionId = generateSessionId();
      } else {
        try {
          sessionId = validateSessionId(String(body.sessionId));
        } catch {
          return res.status(400).json({ success: false, error: 'INVALID_SESSION_ID', message: 'Malformed session id.' });
        }
      }

      let validDomain: string;
      try {
        validDomain = validateDomain(String(body.domain || ''));
      } catch {
        return res.status(400).json({ success: false, error: 'INVALID_DOMAIN', message: 'A valid domain is required.' });
      }
      if (validDomain !== grant.domain) {
        return res.status(403).json({ success: false, error: 'GRANT_DOMAIN_MISMATCH', message: 'Domain does not match the write grant.' });
      }

      let clientTimestamp: string | null = null;
      if (body.timestamp !== undefined && body.timestamp !== null && body.timestamp !== '') {
        try {
          clientTimestamp = validateClientTimestamp(body.timestamp);
        } catch {
          return res.status(400).json({ success: false, error: 'INVALID_TIMESTAMP', message: 'Timestamp is malformed or outside the accepted window.' });
        }
      }

      // Tenant identity comes exclusively from the server-signed grant.
      // A conflicting caller-supplied customerId is an error, not a choice.
      if (body.customerId !== undefined && body.customerId !== null && String(body.customerId) !== grant.tenantId) {
        return res.status(403).json({ success: false, error: 'TENANT_MISMATCH', message: 'customerId does not match the write grant tenant.' });
      }
      const customer = await customerFromGrant(grant.tenantId);
      if (!customer) {
        return res.status(403).json({ success: false, error: 'UNKNOWN_TENANT', message: 'Grant tenant could not be resolved.' });
      }

      const parsed = storage.parseDomain(validDomain);

      // Data minimization: registration stores the pseudonymous identifier
      // and its domain binding. No user agent, language, screen size,
      // referrer URL, or any other fingerprint-capable telemetry.
      try {
        await storage.createInteraction({
          customerId: customer.id,
          sessionId,
          userId: validWaiTag,
          pageUrl: '',
          domain: validDomain,
          mainDomain: parsed.mainDomain,
          subdomain: parsed.subdomain,
          interactionType: 'waitag_registration',
          context: {
            waiTag: validWaiTag,
            clientTimestamp
          }
        });
      } catch (error) {
        // Storage failures are surfaced, not converted into fake success:
        // the client must know its identity was never durably registered.
        console.error('Error storing WaiTag registration:', error);
        return res.status(500).json({ success: false, error: 'STORAGE_FAILED', message: 'Registration could not be stored.' });
      }

      return res.json({
        success: true,
        waiTag: validWaiTag,
        sessionId,
        domain: validDomain
      });
    } catch (error) {
      console.error('WaiTag registration error:', error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  });

  /**
   * COMMERCIAL FEATURE: Cross-Domain Token Verification (WTX-1)
   * See COMMERCIAL-LICENSE for production use requirements.
   * Routes are only registered if NYLO_TOKEN_SECRET is configured at startup.
   */
  if (!process.env.NYLO_TOKEN_SECRET) {
    console.error('[SECURITY] NYLO_TOKEN_SECRET not set at startup — cross-domain token endpoints will NOT be registered.');
    console.error('[SECURITY] Set NYLO_TOKEN_SECRET environment variable to enable cross-domain features.');
  } else {

  /**
   * Verifies that a domain is DNS-verified for the given tenant.
   * Fail-closed: when the storage layer cannot verify domains, requests
   * are rejected in production and allowed (with a warning) only in dev.
   */
  async function requireVerifiedDomain(domain: string, tenantId: number): Promise<{ ok: boolean; message?: string }> {
    if (!storage.isDomainVerified) {
      if (process.env.NODE_ENV === 'production') {
        return { ok: false, message: 'Domain verification is not available — cross-domain tokens are disabled in production.' };
      }
      console.warn('[SECURITY] storage.isDomainVerified not implemented — skipping domain verification (development only).');
      return { ok: true };
    }
    const verified = await storage.isDomainVerified(domain, tenantId);
    if (!verified) {
      return { ok: false, message: `Domain ${domain} is not verified for this tenant. Complete DNS verification first.` };
    }
    return { ok: true };
  }

  app.post("/api/tracking/verify-cross-domain-token", async (req: Request, res: Response) => {
    try {
      // Destination authorization FIRST: an unauthenticated caller must not
      // be able to consume (and thereby burn) someone else's token. Without
      // this ordering, an attacker who intercepts a token URL could void the
      // legitimate arrival by racing a bogus verification.
      const auth = requireWriteGrant(req, 'ingest');
      if (auth.ok !== true) {
        const failure = auth as { status: number; error: string; message: string };
        return res.status(failure.status).json({ success: false, error: failure.error, message: failure.message });
      }
      const grant = auth.grant;

      const { token, domain, customerId } = req.body || {};

      if (!token) {
        return res.status(400).json({ success: false, message: 'Token is required' });
      }
      if (!domain) {
        return res.status(400).json({ success: false, message: 'domain is required' });
      }

      let validDomain: string;
      try {
        validDomain = validateDomain(domain);
      } catch {
        return res.status(400).json({ success: false, message: 'Invalid domain format' });
      }
      if (validDomain !== grant.domain) {
        return res.status(403).json({ success: false, error: 'GRANT_DOMAIN_MISMATCH', message: 'Domain does not match the write grant.' });
      }
      // Legacy clients may still send customerId; it must agree with the
      // grant — it is never used as the source of tenant identity.
      if (customerId !== undefined && customerId !== null && String(customerId) !== grant.tenantId) {
        return res.status(403).json({ success: false, error: 'TENANT_MISMATCH', message: 'customerId does not match the write grant tenant.' });
      }

      const tokenSecret = process.env.NYLO_TOKEN_SECRET!;
      const result = verifyCrossDomainToken(token, tokenSecret, {
        expectedDestination: validDomain,
        expectedTenant: grant.tenantId
      });

      if (!result.valid) {
        const status = result.error === 'MALFORMED_TOKEN' ? 400 : 403;
        return res.status(status).json({
          success: false,
          error: result.error,
          message: 'Cross-domain token rejected: ' + result.error
        });
      }

      const payload = result.payload!;
      const tenantId = parseInt(payload.tenantId);

      // Both source and destination must be verified for the same tenant.
      for (const boundDomain of [payload.sourceDomain, payload.destinationDomain]) {
        const check = await requireVerifiedDomain(boundDomain, tenantId);
        if (!check.ok) {
          return res.status(403).json({ success: false, error: 'DOMAIN_NOT_VERIFIED', message: check.message });
        }
      }

      // Replay protection is mandatory and atomic: exactly one concurrent
      // verification of the same token can win. Consumption happens LAST,
      // after every authorization check has passed.
      const tokenHash = hashToken(token);
      const won = await consumeReplayToken(tokenHash, DEFAULT_TTL_MS);
      if (!won) {
        return res.status(403).json({
          success: false,
          error: 'TOKEN_REPLAYED',
          message: 'Token has already been used (replay detected)'
        });
      }

      return res.json({
        success: true,
        identity: {
          waiTag: payload.waiTag,
          sessionId: payload.sessionId,
          userId: payload.userId || null
        },
        domain: payload.destinationDomain,
        verifiedAt: new Date().toISOString()
      });
    } catch (error) {
      console.error('Error verifying cross-domain token:', error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  });

  app.post("/api/tracking/generate-cross-domain-token", async (req: Request, res: Response) => {
    try {
      // Per-tenant API-key authentication. The tenant is whatever tenant the
      // key resolves to — the caller cannot nominate a different one, and
      // there is no shared global key to steal.
      const rawApiKey = req.headers['x-api-key'] as string;
      if (!rawApiKey) {
        return res.status(401).json({
          success: false,
          error: 'UNAUTHORIZED',
          message: 'X-API-Key header is required to generate tokens'
        });
      }
      let apiKey: string;
      try {
        apiKey = validateApiKey(rawApiKey);
      } catch {
        return res.status(401).json({ success: false, error: 'UNAUTHORIZED', message: 'Invalid API key' });
      }
      const keyCustomer = await storage.getCustomerByApiKey(apiKey);
      if (!keyCustomer) {
        return res.status(401).json({ success: false, error: 'UNAUTHORIZED', message: 'Invalid API key' });
      }
      const tenantId = keyCustomer.id;

      const { waiTag, sessionId, userId, sourceDomain, destinationDomain, customerId } = req.body || {};

      if (!waiTag || !sessionId) {
        return res.status(400).json({ success: false, message: 'waiTag and sessionId are required' });
      }
      if (customerId !== undefined && customerId !== null && String(customerId) !== String(tenantId)) {
        return res.status(403).json({
          success: false,
          error: 'TENANT_MISMATCH',
          message: 'customerId does not match the tenant this API key belongs to'
        });
      }
      if (!sourceDomain || !destinationDomain) {
        return res.status(400).json({ success: false, message: 'sourceDomain and destinationDomain are required — tokens must be bound to both domains' });
      }

      let validSource: string;
      let validDestination: string;
      try {
        validSource = validateDomain(sourceDomain);
        validDestination = validateDomain(destinationDomain);
      } catch {
        return res.status(400).json({ success: false, message: 'Invalid sourceDomain or destinationDomain format' });
      }

      // Both source and destination must be verified for the key's tenant.
      for (const boundDomain of [validSource, validDestination]) {
        const check = await requireVerifiedDomain(boundDomain, tenantId);
        if (!check.ok) {
          return res.status(403).json({ success: false, error: 'DOMAIN_NOT_VERIFIED', message: check.message });
        }
      }

      const tokenSecret = process.env.NYLO_TOKEN_SECRET!;
      const token = signCrossDomainToken({
        tenantId,
        sourceDomain: validSource,
        destinationDomain: validDestination,
        waiTag,
        sessionId,
        userId: userId || null
      }, tokenSecret);

      return res.json({
        success: true,
        token,
        expiresAt: new Date(Date.now() + DEFAULT_TTL_MS).toISOString()
      });
    } catch (error) {
      console.error('Error generating cross-domain token:', error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  });

  } // end if (NYLO_TOKEN_SECRET) — cross-domain endpoints

  // NOTE: the legacy no-op /api/tracking/verify-waitag endpoint was removed —
  // it always returned isValid:true without verification. Use
  // /api/tracking/verify-cross-domain-token for real verification.

  app.post("/api/tracking/event", async (req: Request, res: Response) => {
    try {
      if (!req.body || Object.keys(req.body).length === 0) {
        return res.status(400).json({ success: false, message: 'Empty request body' });
      }

      const auth = requireWriteGrant(req, 'ingest');
      if (auth.ok !== true) {
        const failure = auth as { status: number; error: string; message: string };
        return res.status(failure.status).json({ success: false, error: failure.error, message: failure.message });
      }
      const grant = auth.grant;

      let validatedPayload;
      try {
        validatedPayload = validateTrackingEvent(req.body);
      } catch (error) {
        return res.status(400).json({
          success: false,
          message: error instanceof Error ? error.message : 'Invalid event payload'
        });
      }

      const {
        eventType, waiTag, domain, customerId: eventCustomerId,
        pageUrl, sessionId, metadata, ...rest
      } = validatedPayload;

      if (!domain) {
        return res.status(400).json({ success: false, error: 'INVALID_DOMAIN', message: 'domain is required' });
      }
      if (domain !== grant.domain) {
        return res.status(403).json({ success: false, error: 'GRANT_DOMAIN_MISMATCH', message: 'Domain does not match the write grant.' });
      }
      if (eventCustomerId !== undefined && eventCustomerId !== null && String(eventCustomerId) !== grant.tenantId) {
        return res.status(403).json({ success: false, error: 'TENANT_MISMATCH', message: 'customerId does not match the write grant tenant.' });
      }

      const customer = await customerFromGrant(grant.tenantId);
      if (!customer) {
        return res.status(403).json({ success: false, error: 'UNKNOWN_TENANT', message: 'Grant tenant could not be resolved.' });
      }

      const parsed = storage.parseDomain(domain);

      await storage.createInteraction({
        customerId: customer.id,
        sessionId: sessionId || generateSessionId(),
        userId: waiTag || null,
        pageUrl: sanitizeUrlForStorage(pageUrl),
        domain,
        mainDomain: parsed.mainDomain,
        subdomain: parsed.subdomain,
        interactionType: eventType,
        context: { metadata: stripFingerprintFields(metadata), ...stripFingerprintFields(rest) }
      });

      return res.json({ success: true, message: 'Event tracked' });
    } catch (error) {
      console.error('Tracking event error:', error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  });
}
