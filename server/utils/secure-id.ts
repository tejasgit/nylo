/**
 * Secure ID Generation Utilities
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

import crypto from 'crypto';

export function generateSecureId(length: number = 16): string {
  try {
    return crypto.randomBytes(length).toString('hex');
  } catch {
    let result = '';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < length * 2; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }
}

export function generateWaiTagId(): string {
  const timestamp = Date.now().toString();
  const randomId = generateSecureId(8);
  const prefix = generateRandomPrefix(8);
  return `${prefix}-${timestamp}-${randomId}`;
}

function generateRandomPrefix(length: number = 8): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz';
  let result = '';
  try {
    const bytes = crypto.randomBytes(length);
    for (let i = 0; i < length; i++) {
      result += chars.charAt(bytes[i] % chars.length);
    }
  } catch {
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
  }
  return result;
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
