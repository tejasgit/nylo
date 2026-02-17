/**
 * DNS-Based Domain Ownership Verification
 *
 * Verifies domain ownership by checking for a specific TXT record in DNS.
 * Similar to Google Search Console and Stripe domain verification.
 *
 * Flow:
 * 1. Customer requests verification → server generates a unique token
 * 2. Customer adds TXT record: nylo-verify=<token> to their domain's DNS
 * 3. Customer triggers verification → server does dns.resolveTxt() lookup
 * 4. If the token matches, domain is marked as verified
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

import dns from 'dns';
import crypto from 'crypto';

const TXT_RECORD_PREFIX = 'nylo-verify=';

export interface DomainVerification {
  domain: string;
  token: string;
  status: 'pending' | 'verified' | 'failed';
  createdAt: Date;
  verifiedAt?: Date;
  lastCheckedAt?: Date;
  failureReason?: string;
}

export function generateVerificationToken(): string {
  return crypto.randomBytes(16).toString('hex');
}

export function getTxtRecordInstruction(domain: string, token: string): string {
  return `Add a TXT record to ${domain} with the value: ${TXT_RECORD_PREFIX}${token}`;
}

export function getDnsRecordValue(token: string): string {
  return `${TXT_RECORD_PREFIX}${token}`;
}

export async function verifyDomainOwnership(
  domain: string,
  expectedToken: string,
  options?: { timeout?: number }
): Promise<{ verified: boolean; error?: string }> {
  const timeout = options?.timeout || 10000;

  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve({ verified: false, error: 'DNS lookup timed out' });
    }, timeout);

    const resolver = new dns.Resolver();
    resolver.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1']);

    resolver.resolveTxt(domain, (err, records) => {
      clearTimeout(timer);

      if (err) {
        if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
          resolve({ verified: false, error: `No TXT records found for ${domain}` });
        } else {
          resolve({ verified: false, error: `DNS lookup failed: ${err.code}` });
        }
        return;
      }

      const expectedValue = `${TXT_RECORD_PREFIX}${expectedToken}`;

      const found = records.some((recordParts) => {
        const joined = recordParts.join('');
        return joined.trim() === expectedValue.trim();
      });

      if (found) {
        resolve({ verified: true });
      } else {
        resolve({
          verified: false,
          error: `TXT record "${expectedValue}" not found. Found ${records.length} TXT record(s) but none matched.`
        });
      }
    });
  });
}

export async function checkSubdomainOwnership(
  subdomain: string,
  subdomainToken: string,
  parentDomainVerified: boolean
): Promise<{ verified: boolean; method: string; error?: string }> {
  const subdomainResult = await verifyDomainOwnership(subdomain, subdomainToken);
  if (subdomainResult.verified) {
    return { verified: true, method: 'subdomain_txt' };
  }

  if (parentDomainVerified) {
    return { verified: true, method: 'parent_domain_verified' };
  }

  return {
    verified: false,
    method: 'none',
    error: `Subdomain ${subdomain} has no TXT record and parent domain is not verified`
  };
}

export function extractParentDomain(domain: string): string | null {
  const parts = domain.split('.');
  if (parts.length <= 2) return null;
  return parts.slice(1).join('.');
}
