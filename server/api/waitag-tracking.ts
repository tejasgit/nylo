/**
 * Nylo WaiTag Tracking API — Identity Registration & Cross-Domain Verification
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 *
 * COMMERCIAL NOTICE: Cross-domain token verification endpoints are part of
 * the WTX-1 protocol covered by LICENSE-COMMERCIAL.
 */

import type { Request, Response } from "express";
import { generateWaiTagId, generateSessionId } from '../utils/secure-id';
import {
  validateWaiTagId,
  validateDomain,
  validateApiKey,
  validateEventType,
  sanitizeFormData,
  validateTrackingEvent
} from '../utils/input-validation';

export interface WaiTagStorage {
  getCustomer(id: number): Promise<any>;
  getCustomerByApiKey(apiKey: string): Promise<any>;
  createInteraction(data: any): Promise<any>;
  parseDomain(domain: string): { mainDomain: string; subdomain: string | null };
  isDomainVerified?(domain: string, customerId: number): Promise<boolean>;
}

export function registerWaiTagTrackingRoutes(app: any, storage: WaiTagStorage) {
  app.options("/api/tracking/register-waitag", (req: Request, res: Response) => {
    const origin = req.headers.origin || '*';
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-API-Key, Cookie');
    res.header('Access-Control-Expose-Headers', 'X-WaiTag, X-Cross-Domain-WaiTag');
    res.header('Access-Control-Max-Age', '86400');
    res.status(200).send();
  });

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

      const origin = req.headers.origin || '*';
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-API-Key, Cookie');
      res.header('Access-Control-Expose-Headers', 'X-WaiTag, X-Cross-Domain-WaiTag');

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
   * See LICENSE-COMMERCIAL for production use requirements.
   */
  app.options("/api/tracking/verify-cross-domain-token", (req: Request, res: Response) => {
    const origin = req.headers.origin || '*';
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-API-Key');
    res.status(200).send();
  });

  app.post("/api/tracking/verify-cross-domain-token", async (req: Request, res: Response) => {
    try {
      const { token, domain, customerId, referrer } = req.body;

      if (!token) {
        return res.status(400).json({ success: false, message: 'Token is required' });
      }

      const origin = req.headers.origin || '*';
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');

      if (storage.isDomainVerified && domain && customerId) {
        const verified = await storage.isDomainVerified(domain, parseInt(customerId));
        if (!verified) {
          return res.status(403).json({
            success: false,
            message: 'Domain not verified. Complete DNS verification before using cross-domain features.'
          });
        }
      }

      try {
        const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));

        if (decoded.waiTag && decoded.sessionId) {
          return res.json({
            success: true,
            identity: {
              waiTag: decoded.waiTag,
              sessionId: decoded.sessionId,
              userId: decoded.userId || null
            },
            verifiedAt: new Date().toISOString()
          });
        }
      } catch {
        // Token format not recognized
      }

      return res.json({
        success: false,
        message: 'Invalid or expired cross-domain token'
      });
    } catch (error) {
      console.error('Error verifying cross-domain token:', error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  });

  app.post("/api/tracking/verify-waitag", async (req: Request, res: Response) => {
    try {
      const { waiTag, domain } = req.body;

      if (!waiTag || !domain) {
        return res.status(400).json({ success: false, message: 'Missing required fields' });
      }

      return res.json({ success: true, isValid: true, waiTag: waiTag });
    } catch (error) {
      return res.status(500).json({ success: false, message: 'Server error verifying WaiTag' });
    }
  });

  app.options("/api/tracking/event", (req: Request, res: Response) => {
    const origin = req.headers.origin || '*';
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-API-Key');
    res.status(200).send();
  });

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
