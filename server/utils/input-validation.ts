/**
 * SPDX-License-Identifier: MIT
 *
 * Input Validation Utilities
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

import {
  isValidDomainName,
  WAITAG_PATTERN,
  stripFingerprintFields,
  sanitizeUrlForStorage
} from './security-core';

// Fingerprint stripping, URL storage sanitization, and the WaiTag format
// live in security-core.js (plain JS) so the demo servers share the exact
// same implementations. Re-exported here for the TypeScript API surface.
export { FORBIDDEN_FINGERPRINT_FIELDS, stripFingerprintFields, sanitizeUrlForStorage } from './security-core';

const API_KEY_REGEX = /^[a-zA-Z0-9_-]{8,128}$/;
const WAITAG_REGEX = WAITAG_PATTERN;
const URL_REGEX = /^https?:\/\/.{1,2048}$/;
const SESSION_ID_REGEX = /^[a-zA-Z0-9_-]{8,128}$/;

// How far a client-supplied timestamp may drift from server time before we
// reject it. Past skew covers offline queue replays; future skew covers
// ordinary clock drift.
const MAX_TIMESTAMP_PAST_MS = 48 * 60 * 60 * 1000;
const MAX_TIMESTAMP_FUTURE_MS = 5 * 60 * 1000;

const VALID_EVENT_TYPES = [
  'page_view', 'click', 'link_click', 'button_click', 'form_submit',
  'scroll', 'hover', 'error', 'custom', 'file_download', 'outbound_click',
  'video_interaction', 'search', 'element_visible', 'performance',
  'user_engagement', 'conversion', 'cross_domain', 'cross_domain_arrival',
  'cross_domain_identity_match', 'waitag_registration', 'bounce_rate',
  'return_visitor', 'device_info', 'browser_info', 'referrer'
];

export function validateDomain(domain: string): string {
  if (!domain || typeof domain !== 'string') {
    throw new Error('Domain is required');
  }
  const cleaned = domain.trim().toLowerCase();
  if (cleaned.length > 253) throw new Error('Domain too long');
  if (!isValidDomainName(cleaned)) {
    throw new Error('Invalid domain format');
  }
  return cleaned;
}

export function validateApiKey(apiKey: string): string {
  if (!apiKey || typeof apiKey !== 'string') {
    throw new Error('API key is required');
  }
  const cleaned = apiKey.trim();
  if (!API_KEY_REGEX.test(cleaned)) throw new Error('Invalid API key format');
  return cleaned;
}

export function validateWaiTagId(waiTag: string): string {
  if (!waiTag || typeof waiTag !== 'string') {
    throw new Error('WaiTag is required');
  }
  const cleaned = waiTag.trim();
  if (!WAITAG_REGEX.test(cleaned)) throw new Error('Invalid WaiTag format');
  return cleaned;
}

export function validateEventType(eventType: string): string {
  if (!eventType || typeof eventType !== 'string') {
    throw new Error('Event type is required');
  }
  const cleaned = eventType.trim().toLowerCase();
  if (!VALID_EVENT_TYPES.includes(cleaned)) {
    throw new Error(`Invalid event type: ${cleaned}`);
  }
  return cleaned;
}

export function validateURL(url: string): string {
  if (!url || typeof url !== 'string') {
    throw new Error('URL is required');
  }
  if (!URL_REGEX.test(url)) throw new Error('Invalid URL format');
  return url.substring(0, 2048);
}

export function validateSessionId(sessionId: string): string {
  if (!sessionId || typeof sessionId !== 'string') {
    throw new Error('Session id is required');
  }
  const cleaned = sessionId.trim();
  if (!SESSION_ID_REGEX.test(cleaned)) throw new Error('Invalid session id format');
  return cleaned;
}

/**
 * Validates a client-supplied timestamp (ISO string or epoch millis) and
 * bounds it against server time. Rejects unparseable values and values more
 * than 48h in the past or 5min in the future. Returns a normalized ISO string.
 */
export function validateClientTimestamp(value: any, now: number = Date.now()): string {
  let millis: number;
  if (typeof value === 'number') {
    millis = value;
  } else if (typeof value === 'string' && value.trim().length > 0) {
    millis = Date.parse(value.trim());
  } else {
    throw new Error('Invalid timestamp');
  }
  if (!Number.isFinite(millis)) throw new Error('Invalid timestamp');
  if (millis < now - MAX_TIMESTAMP_PAST_MS) throw new Error('Timestamp too far in the past');
  if (millis > now + MAX_TIMESTAMP_FUTURE_MS) throw new Error('Timestamp too far in the future');
  return new Date(millis).toISOString();
}

export function sanitizeFormData(data: Record<string, any>): Record<string, any> {
  const sanitized: Record<string, any> = {};
  for (const [key, value] of Object.entries(data)) {
    if (typeof value === 'string') {
      sanitized[key] = value
        .replace(/[<>]/g, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .substring(0, 10000);
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      sanitized[key] = value;
    } else if (value && typeof value === 'object') {
      sanitized[key] = sanitizeFormData(value);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

/**
 * Strict tracking-event validation. Invalid input is REJECTED (throws), never
 * silently coerced: an unknown eventType used to be laundered into 'custom'
 * and an invalid domain was passed through — both hid attacks and bugs.
 */
export function validateTrackingEvent(payload: any): any {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Invalid payload');
  }

  const sanitized = stripFingerprintFields(sanitizeFormData(payload));

  sanitized.eventType = validateEventType(sanitized.eventType);

  if (sanitized.domain !== undefined && sanitized.domain !== null && sanitized.domain !== '') {
    sanitized.domain = validateDomain(sanitized.domain);
  }

  if (sanitized.sessionId !== undefined && sanitized.sessionId !== null && sanitized.sessionId !== '') {
    sanitized.sessionId = validateSessionId(sanitized.sessionId);
  }

  if (sanitized.waiTag !== undefined && sanitized.waiTag !== null && sanitized.waiTag !== '') {
    sanitized.waiTag = validateWaiTagId(sanitized.waiTag);
  }

  if (sanitized.timestamp !== undefined && sanitized.timestamp !== null && sanitized.timestamp !== '') {
    sanitized.timestamp = validateClientTimestamp(sanitized.timestamp);
  }

  return sanitized;
}
