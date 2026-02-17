/**
 * Input Validation Utilities
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

const DOMAIN_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
const API_KEY_REGEX = /^[a-zA-Z0-9_-]{8,128}$/;
const WAITAG_REGEX = /^(wai_[0-9a-zA-Z]+_[a-zA-Z0-9]+|[a-z]+-\d+-[a-f0-9]+)$/;
const URL_REGEX = /^https?:\/\/.{1,2048}$/;

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
  if (!DOMAIN_REGEX.test(cleaned) && !cleaned.includes('localhost')) {
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

export function validateTrackingEvent(payload: any): any {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Invalid payload');
  }

  const sanitized = sanitizeFormData(payload);

  if (sanitized.eventType) {
    try {
      sanitized.eventType = validateEventType(sanitized.eventType);
    } catch {
      sanitized.eventType = 'custom';
    }
  }

  if (sanitized.domain) {
    try {
      sanitized.domain = validateDomain(sanitized.domain);
    } catch {}
  }

  return sanitized;
}
