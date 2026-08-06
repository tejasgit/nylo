/**
 * SPDX-License-Identifier: LicenseRef-Nylo-Commercial
 *
 * Nylo WaiTag Tracking API — Identity Registration & Cross-Domain Verification
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
  validateEventType,
  sanitizeFormData,
  validateTrackingEvent
} from '../utils/input-validation';

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
  tokenReplayStore?: TokenReplayStore;
}

export function registerWaiTagTrackingRoutes(app: any, storage: WaiTagStorage) {
  // Replay protection must always exist. Prefer a durable store supplied by
  // the integrator; fall back to an in-memory store (single-process only).
  const replayStore: TokenReplayStore = storage.tokenReplayStore || createInMemoryReplayStore();
  if (!storage.tokenReplayStore) {
    console.warn('[SECURITY] No durable tokenReplayStore provided — using in-memory replay protection (single process only).');
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
  // CORS (including OPTIONS preflight) is handled centrally in server/index.ts.
  app.post("/api/tracking/register-waitag", async (req: Request, res: Response) => {
    try {
      const sanitizedBody = sanitizeFormData(req.body);

      const {
        waiTag: rawWaiTag,
        domain: rawDomain,
        customerId: requestCustomerId,
        apiKey: rawApiKey,
        timestamp,
        userAgent,
        referrer,
        language,
        screenSize
      } = sanitizedBody;

      let validWaiTag: string;
      let validDomain: string;

      try {
        if (!rawWaiTag) {
          validWaiTag = generateWaiTagId();
        } else {
          try {
            validWaiTag = validateWaiTagId(rawWaiTag);
          } catch {
            validWaiTag = generateWaiTagId();
          }
        }

        if (!rawDomain) {
          return res.status(400).json({ success: false, message: 'Domain is required' });
        }

        try {
          validDomain = validateDomain(rawDomain);
        } catch (error) {
          return res.status(400).json({
            success: false,
            message: `Invalid domain: ${error instanceof Error ? error.message : 'Unknown error'}`
          });
        }
      } catch (error) {
        return res.status(400).json({
          success: false,
          message: `Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`
        });
      }

      const headerApiKey = req.headers['x-api-key'] as string;
      let effectiveApiKey: string | undefined;

      if (headerApiKey) {
        try { effectiveApiKey = validateApiKey(headerApiKey); } catch {}
      }
      if (!effectiveApiKey && rawApiKey) {
        try { effectiveApiKey = validateApiKey(rawApiKey); } catch {}
      }

      let customer;
      try {
        if (effectiveApiKey) {
          customer = await storage.getCustomerByApiKey(effectiveApiKey);
        } else if (requestCustomerId) {
          customer = await storage.getCustomer(parseInt(requestCustomerId));
        }

        if (!customer) {
          return res.status(404).json({ success: false, message: 'Customer not found' });
        }
      } catch (error) {
        return res.status(500).json({ success: false, message: 'Server error processing customer lookup' });
      }

      try {
        const parsed = storage.parseDomain(validDomain);
        let sessionId = req.body.sessionId ? req.body.sessionId.toString() : generateSessionId();

        await storage.createInteraction({
          customerId: customer.id,
          sessionId: sessionId,
          userId: validWaiTag,
          pageUrl: req.body.pageUrl || '',
          domain: validDomain,
          mainDomain: parsed.mainDomain,
          subdomain: parsed.subdomain,
          interactionType: 'waitag_registration',
          context: {
            waiTag: validWaiTag,
            userAgent: userAgent || req.headers['user-agent'],
            referrer: referrer,
            language: language,
            screenSize: screenSize
          }
        });

        return res.json({
          success: true,
          waiTag: validWaiTag,
          sessionId: sessionId,
          domain: validDomain,
          customerId: customer.id
        });
      } catch (error) {
        console.error('Error storing WaiTag registration:', error);
        return res.json({
          success: true,
          waiTag: validWaiTag,
          sessionId: generateSessionId(),
          domain: validDomain
        });
      }
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
      const { token, domain, customerId } = req.body;

      if (!token) {
        return res.status(400).json({ success: false, message: 'Token is required' });
      }
      if (!domain || !customerId) {
        return res.status(400).json({ success: false, message: 'domain and customerId are required' });
      }

      let validDomain: string;
      try {
        validDomain = validateDomain(domain);
      } catch {
        return res.status(400).json({ success: false, message: 'Invalid domain format' });
      }

      const tokenSecret = process.env.NYLO_TOKEN_SECRET!;
      const result = verifyCrossDomainToken(token, tokenSecret, {
        expectedDestination: validDomain,
        expectedTenant: customerId
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
      // verification of the same token can win.
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
      const apiKey = req.headers['x-api-key'] as string;
      if (!apiKey || !process.env.NYLO_API_KEY || apiKey !== process.env.NYLO_API_KEY) {
        return res.status(401).json({
          success: false,
          error: 'UNAUTHORIZED',
          message: 'Valid X-API-Key header is required to generate tokens'
        });
      }

      const { waiTag, sessionId, userId, sourceDomain, destinationDomain, customerId } = req.body;

      if (!waiTag || !sessionId) {
        return res.status(400).json({ success: false, message: 'waiTag and sessionId are required' });
      }
      if (!customerId) {
        return res.status(400).json({ success: false, message: 'customerId is required — tokens must be bound to a tenant' });
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

      const tenantId = parseInt(customerId);
      if (!Number.isInteger(tenantId) || tenantId <= 0) {
        return res.status(400).json({ success: false, message: 'Invalid customerId' });
      }

      // Both source and destination must be verified for the same tenant.
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
      if (Object.keys(req.body).length === 0) {
        return res.status(400).json({ success: false, message: 'Empty request body' });
      }

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

      let customer;
      const apiKey = req.headers['x-api-key'] as string;

      if (apiKey) {
        customer = await storage.getCustomerByApiKey(apiKey);
      }
      if (!customer && eventCustomerId) {
        customer = await storage.getCustomer(parseInt(eventCustomerId));
      }
      if (!customer) {
        return res.status(404).json({ success: false, message: 'Customer not found' });
      }

      const parsed = storage.parseDomain(domain || '');

      await storage.createInteraction({
        customerId: customer.id,
        sessionId: sessionId || generateSessionId(),
        userId: waiTag || null,
        pageUrl: pageUrl || '',
        domain: domain || '',
        mainDomain: parsed.mainDomain,
        subdomain: parsed.subdomain,
        interactionType: eventType,
        context: { metadata, ...rest }
      });

      return res.json({ success: true, message: 'Event tracked' });
    } catch (error) {
      console.error('Tracking event error:', error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  });
}
