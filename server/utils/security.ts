/**
 * Server-Side Security Utilities
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

export function sanitizeInput(input: string, maxLength: number = 1000): string {
  if (typeof input !== 'string') return String(input || '');
  return input
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '')
    .replace(/data:/gi, '')
    .substring(0, maxLength);
}

export function sanitizeHtml(input: string): string {
  if (typeof input !== 'string') return String(input || '');
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

export function validateOrigin(origin: string, allowedDomains: string[]): boolean {
  if (!origin) return false;
  try {
    const url = new URL(origin);
    return allowedDomains.some(domain => {
      if (domain.startsWith('*.')) {
        return url.hostname.endsWith(domain.substring(2));
      }
      return url.hostname === domain;
    });
  } catch {
    return false;
  }
}
