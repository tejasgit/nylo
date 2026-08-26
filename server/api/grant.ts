/**
 * SPDX-License-Identifier: MIT
 *
 * Nylo Write-Grant Issuance & Enforcement
 *
 * Browsers must not be able to write events into arbitrary tenants. Instead
 * of trusting caller-supplied customer IDs (the old model), every browser
 * write is authorized by a short-lived, server-signed grant:
 *
 *   1. The SDK POSTs { domain } to /api/tracking/grant.
 *   2. The server resolves the tenant for that domain from ITS OWN
 *      configuration (storage.getTenantIdForDomain) — never from the body —
 *      and checks the browser's Origin header against the claimed domain.
 *   3. The signed grant comes back and is presented on every ingestion /
 *      registration request via the `X-Nylo-Grant` header.
 *
 * Threat model honesty: a grant proves "the server agreed that THIS domain
 * maps to THIS tenant, recently". It is a bearer value scoped to writes for
 * one domain for a few minutes — it does not authenticate a person and does
 * not authorize reads. Server-to-server callers keep using API keys.
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

import type { Request, Response } from "express";
import crypto from "crypto";
import {
  signWriteGrant,
  verifyWriteGrant,
  DEFAULT_GRANT_TTL_MS,
  WriteGrantPayload
} from '../utils/write-grant';
import { validateDomain } from '../utils/input-validation';

export interface GrantStorage {
  getCustomer(id: number): Promise<any>;
  /**
   * Server-side domain→tenant mapping. REQUIRED in production: it is the
   * single source of truth for which tenant a page domain writes into.
   * Return null for unknown domains (grant is refused).
   */
  getTenantIdForDomain?(domain: string): Promise<string | number | null>;
}

let ephemeralDevSecret: string | null = null;

/**
 * The secret that signs grants (same secret as WTX-1 tokens; the payload
 * shapes are disjoint so the two can never be confused for one another).
 * Production requires NYLO_TOKEN_SECRET; development falls back to an
 * ephemeral per-process secret so local setups work out of the box.
 */
export function getGrantSecret(): string | null {
  if (process.env.NYLO_TOKEN_SECRET) return process.env.NYLO_TOKEN_SECRET;
  if (process.env.NODE_ENV === 'production') return null;
  if (!ephemeralDevSecret) {
    ephemeralDevSecret = crypto.randomBytes(32).toString('hex');
    console.warn('[Nylo] NYLO_TOKEN_SECRET not set — using an ephemeral development grant secret (grants are invalidated on restart).');
  }
  return ephemeralDevSecret;
}

export interface GrantCheckSuccess { ok: true; grant: WriteGrantPayload; }
export interface GrantCheckFailure { ok: false; status: number; error: string; message: string; }

/**
 * Route-level grant enforcement. Reads `X-Nylo-Grant`, verifies signature,
 * expiry, and scope. Domain/tenant binding is checked by the caller against
 * the request payload.
 */
export function requireWriteGrant(req: Request, requiredScope: string): GrantCheckSuccess | GrantCheckFailure {
  const secret = getGrantSecret();
  if (!secret) {
    return {
      ok: false, status: 503, error: 'GRANTS_UNAVAILABLE',
      message: 'Write grants are not configured (NYLO_TOKEN_SECRET is required).'
    };
  }
  const rawHeader = req.headers['x-nylo-grant'];
  const grantValue = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;
  if (!grantValue) {
    return {
      ok: false, status: 401, error: 'GRANT_REQUIRED',
      message: 'A write grant is required. Obtain one from POST /api/tracking/grant.'
    };
  }
  const result = verifyWriteGrant(String(grantValue), secret, { requiredScope });
  if (result.valid !== true) {
    return {
      ok: false, status: 403, error: 'GRANT_' + (result.error || 'INVALID'),
      message: 'Write grant rejected: ' + (result.error || 'INVALID')
    };
  }
  return { ok: true, grant: result.payload as WriteGrantPayload };
}

export function registerGrantRoutes(app: any, storage: GrantStorage) {
  const isProduction = process.env.NODE_ENV === 'production';
  const secret = getGrantSecret();
  if (!secret) {
    console.error('[Nylo] SECURITY: /api/tracking/grant not registered — NYLO_TOKEN_SECRET is required.');
    return;
  }
  if (typeof storage.getTenantIdForDomain !== 'function') {
    if (isProduction) {
      throw new Error('[Nylo] storage.getTenantIdForDomain(domain) is required in production — tenants must be resolved from server-side configuration, never from browser-supplied IDs.');
    }
    console.warn('[Nylo] storage.getTenantIdForDomain not implemented — development fallback maps every domain to customer 1. Implement it before production.');
  }

  app.post('/api/tracking/grant', async (req: Request, res: Response) => {
    try {
      let domain: string;
      try {
        domain = validateDomain(String((req.body && req.body.domain) || ''));
      } catch {
        return res.status(400).json({ success: false, error: 'INVALID_DOMAIN', message: 'A valid page domain is required.' });
      }

      // Origin binding: a browser cannot forge its Origin header, so a page
      // can only obtain grants for the domain it is actually running on.
      // Non-browser callers (no Origin) are allowed only outside production —
      // server-to-server integrations authenticate with API keys instead.
      const origin = req.headers.origin;
      if (origin) {
        let originHost: string | null = null;
        try { originHost = new URL(String(origin)).hostname.toLowerCase(); } catch { originHost = null; }
        if (originHost !== domain) {
          return res.status(403).json({ success: false, error: 'ORIGIN_MISMATCH', message: 'Origin header does not match the requested domain.' });
        }
      } else if (isProduction) {
        return res.status(403).json({ success: false, error: 'ORIGIN_REQUIRED', message: 'A browser Origin header is required for grant issuance.' });
      }

      let tenantId: string | number | null = null;
      if (typeof storage.getTenantIdForDomain === 'function') {
        tenantId = await storage.getTenantIdForDomain(domain);
      } else if (!isProduction) {
        const fallback = await storage.getCustomer(1).catch(() => null);
        tenantId = fallback ? fallback.id : null;
      }
      if (tenantId === null || tenantId === undefined || tenantId === '') {
        return res.status(403).json({ success: false, error: 'UNKNOWN_DOMAIN', message: 'No tenant is configured for this domain.' });
      }

      const scopes = ['ingest', 'register'];
      const grant = signWriteGrant({ tenantId, domain, scopes }, secret);
      return res.json({
        success: true,
        grant,
        expiresAt: new Date(Date.now() + DEFAULT_GRANT_TTL_MS).toISOString(),
        scopes
      });
    } catch (error) {
      console.error('Grant issuance error:', error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  });
}
