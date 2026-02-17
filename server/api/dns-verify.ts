/**
 * DNS Domain Verification API
 *
 * Endpoints for domain ownership verification via DNS TXT records.
 * Customers prove they own a domain by adding a TXT record to their DNS.
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

import type { Request, Response } from "express";
import {
  generateVerificationToken,
  getDnsRecordValue,
  getTxtRecordInstruction,
  verifyDomainOwnership,
  checkSubdomainOwnership,
  extractParentDomain
} from '../utils/dns-verification';
import { validateDomain } from '../utils/input-validation';

export interface DnsVerificationStorage {
  getDomainVerification(domain: string, customerId: number): Promise<any | null>;
  createDomainVerification(data: {
    domain: string;
    customerId: number;
    token: string;
    status: 'pending' | 'verified' | 'failed';
  }): Promise<any>;
  updateDomainVerification(domain: string, customerId: number, data: {
    status: 'pending' | 'verified' | 'failed';
    verifiedAt?: Date;
    lastCheckedAt?: Date;
    failureReason?: string;
  }): Promise<any>;
  isDomainVerified(domain: string, customerId: number): Promise<boolean>;
  getCustomer(id: number): Promise<any>;
  getCustomerByApiKey(apiKey: string): Promise<any>;
}

export function registerDnsVerificationRoutes(app: any, storage: DnsVerificationStorage) {

  app.post("/api/domains/request-verification", async (req: Request, res: Response) => {
    try {
      const { domain: rawDomain, customerId: rawCustomerId } = req.body;
      const apiKey = req.headers['x-api-key'] as string;

      let validDomain: string;
      try {
        validDomain = validateDomain(rawDomain);
      } catch (error) {
        return res.status(400).json({
          success: false,
          message: error instanceof Error ? error.message : 'Invalid domain'
        });
      }

      let customer;
      if (apiKey) {
        customer = await storage.getCustomerByApiKey(apiKey);
      }
      if (!customer && rawCustomerId) {
        customer = await storage.getCustomer(parseInt(rawCustomerId));
      }
      if (!customer) {
        return res.status(404).json({ success: false, message: 'Customer not found' });
      }

      const existing = await storage.getDomainVerification(validDomain, customer.id);
      if (existing && existing.status === 'verified') {
        return res.json({
          success: true,
          domain: validDomain,
          status: 'verified',
          verifiedAt: existing.verifiedAt,
          message: 'Domain is already verified'
        });
      }

      const token = existing?.token || generateVerificationToken();

      if (!existing) {
        await storage.createDomainVerification({
          domain: validDomain,
          customerId: customer.id,
          token,
          status: 'pending'
        });
      }

      return res.json({
        success: true,
        domain: validDomain,
        status: 'pending',
        token,
        dnsRecord: {
          type: 'TXT',
          host: validDomain,
          value: getDnsRecordValue(token)
        },
        instruction: getTxtRecordInstruction(validDomain, token)
      });
    } catch (error) {
      console.error('Domain verification request error:', error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  });

  app.post("/api/domains/verify", async (req: Request, res: Response) => {
    try {
      const { domain: rawDomain, customerId: rawCustomerId } = req.body;
      const apiKey = req.headers['x-api-key'] as string;

      let validDomain: string;
      try {
        validDomain = validateDomain(rawDomain);
      } catch (error) {
        return res.status(400).json({
          success: false,
          message: error instanceof Error ? error.message : 'Invalid domain'
        });
      }

      let customer;
      if (apiKey) {
        customer = await storage.getCustomerByApiKey(apiKey);
      }
      if (!customer && rawCustomerId) {
        customer = await storage.getCustomer(parseInt(rawCustomerId));
      }
      if (!customer) {
        return res.status(404).json({ success: false, message: 'Customer not found' });
      }

      const verification = await storage.getDomainVerification(validDomain, customer.id);
      if (!verification) {
        return res.status(404).json({
          success: false,
          message: 'No verification request found for this domain. Call /api/domains/request-verification first.'
        });
      }

      if (verification.status === 'verified') {
        return res.json({
          success: true,
          domain: validDomain,
          status: 'verified',
          verifiedAt: verification.verifiedAt,
          message: 'Domain is already verified'
        });
      }

      const parentDomain = extractParentDomain(validDomain);
      let result;

      if (parentDomain) {
        const parentVerified = await storage.isDomainVerified(parentDomain, customer.id);
        result = await checkSubdomainOwnership(validDomain, verification.token, parentVerified);
      } else {
        const dnsResult = await verifyDomainOwnership(validDomain, verification.token);
        result = { ...dnsResult, method: 'direct_txt' };
      }

      if (result.verified) {
        await storage.updateDomainVerification(validDomain, customer.id, {
          status: 'verified',
          verifiedAt: new Date(),
          lastCheckedAt: new Date()
        });

        return res.json({
          success: true,
          domain: validDomain,
          status: 'verified',
          method: result.method,
          verifiedAt: new Date().toISOString(),
          message: 'Domain ownership verified successfully'
        });
      } else {
        await storage.updateDomainVerification(validDomain, customer.id, {
          status: 'failed',
          lastCheckedAt: new Date(),
          failureReason: result.error
        });

        return res.json({
          success: false,
          domain: validDomain,
          status: 'failed',
          error: result.error,
          expectedRecord: {
            type: 'TXT',
            host: validDomain,
            value: getDnsRecordValue(verification.token)
          }
        });
      }
    } catch (error) {
      console.error('Domain verification error:', error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  });

  app.get("/api/domains/status", async (req: Request, res: Response) => {
    try {
      const rawDomain = req.query.domain as string;
      const rawCustomerId = req.query.customerId as string;
      const apiKey = req.headers['x-api-key'] as string;

      if (!rawDomain) {
        return res.status(400).json({ success: false, message: 'Domain parameter is required' });
      }

      let validDomain: string;
      try {
        validDomain = validateDomain(rawDomain);
      } catch (error) {
        return res.status(400).json({
          success: false,
          message: error instanceof Error ? error.message : 'Invalid domain'
        });
      }

      let customer;
      if (apiKey) {
        customer = await storage.getCustomerByApiKey(apiKey);
      }
      if (!customer && rawCustomerId) {
        customer = await storage.getCustomer(parseInt(rawCustomerId));
      }
      if (!customer) {
        return res.status(404).json({ success: false, message: 'Customer not found' });
      }

      const verification = await storage.getDomainVerification(validDomain, customer.id);

      return res.json({
        success: true,
        domain: validDomain,
        status: verification?.status || 'unverified',
        verifiedAt: verification?.verifiedAt || null,
        lastCheckedAt: verification?.lastCheckedAt || null
      });
    } catch (error) {
      console.error('Domain status check error:', error);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
  });
}
