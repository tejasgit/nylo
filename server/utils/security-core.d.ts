// SPDX-License-Identifier: MIT
export function isValidDomainName(domain: string): boolean;
export function hostMatchesPattern(host: string, pattern: string): boolean;
export function originAllowed(
  origin: string | undefined,
  allowedOrigins: string[],
  opts?: { production?: boolean; allowDevLoopback?: boolean }
): boolean;
export function isIpAddress(host: string): boolean;
export function getRegistrableDomain(hostname: string | null | undefined): string | null;
export function splitRegistrableDomain(hostname: string | null | undefined): {
  registrableDomain: string | null;
  subdomain: string | null;
};
export function parentDomainOf(hostname: string | null | undefined): string | null;
export const WAITAG_PATTERN: RegExp;
export const FORBIDDEN_FINGERPRINT_FIELDS: string[];
export function stripFingerprintFields<T>(value: T, depth?: number): T;
export function sanitizeUrlForStorage(rawUrl: any): string;
