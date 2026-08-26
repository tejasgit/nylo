/**
 * SPDX-License-Identifier: MIT
 *
 * Secure ID Generation Utilities
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

import crypto from 'crypto';

// Fail closed: identifiers are security-relevant (they name identities and
// sessions), so if the CSPRNG is somehow unavailable we throw instead of
// silently degrading to predictable Math.random() values.
export function generateSecureId(length: number = 16): string {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * WaiTag derivation: SHA-256 over (CSPRNG random value | timestamp |
 * domain-specific salt). The digest — not the raw inputs — becomes the
 * identifier, so the tag embeds no readable timestamp and no reversible
 * domain marker. Mirrors the browser SDK derivation in src/nylo.js.
 */
export function generateWaiTagId(domain: string = 'server'): string {
  const randomHex = generateSecureId(16); // 128 bits of CSPRNG entropy
  const timestamp = Date.now().toString();
  const salt = `nylo:${String(domain).toLowerCase()}`;
  const digest = crypto
    .createHash('sha256')
    .update(`${randomHex}|${timestamp}|${salt}`)
    .digest('hex');
  return `wai_${digest.slice(0, 19)}_${digest.slice(19, 27)}`;
}

export function generateSessionId(): string {
  return `session-${Date.now()}-${generateSecureId(12)}`;
}

export function generateApiKey(): string {
  return `nylo_${generateSecureId(24)}`;
}

export function isValidWaiTagId(id: string): boolean {
  return /^[a-z]+-\d+-[a-f0-9]+$/.test(id) || /^wai_[0-9a-zA-Z]+_[a-zA-Z0-9]+$/.test(id);
}

export function extractWaiTagTimestamp(id: string): Date | null {
  if (!isValidWaiTagId(id)) return null;
  try {
    const parts = id.split(/[-_]/);
    for (const part of parts) {
      const ts = parseInt(part);
      if (!isNaN(ts) && ts > 1000000000000) return new Date(ts);
    }
    return null;
  } catch {
    return null;
  }
}
