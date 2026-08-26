/**
 * SPDX-License-Identifier: MIT
 *
 * Nylo Security Core — pure, dependency-free helpers shared by the
 * TypeScript server modules, the demo server, and the unit tests.
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */

'use strict';

const DOMAIN_REGEX = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

/**
 * Validates a bare domain name (no scheme, no port, no path).
 * `localhost` is allowed only as an exact match — never as a substring.
 */
function isValidDomainName(domain) {
  if (!domain || typeof domain !== 'string') return false;
  const cleaned = domain.trim().toLowerCase();
  if (cleaned.length === 0 || cleaned.length > 253) return false;
  return DOMAIN_REGEX.test(cleaned);
}

/**
 * Exact host-boundary matching.
 * - `example.com` matches only `example.com`
 * - `*.example.com` matches `example.com` and `a.example.com`
 *   but NEVER `evilexample.com` or `example.com.evil.io`
 */
function hostMatchesPattern(host, pattern) {
  if (!host || !pattern || typeof host !== 'string' || typeof pattern !== 'string') return false;
  host = host.trim().toLowerCase();
  pattern = pattern.trim().toLowerCase();
  if (!host || !pattern) return false;

  if (pattern.startsWith('*.')) {
    const base = pattern.substring(2);
    if (!base || !isValidDomainName(base)) return false;
    return host === base || host.endsWith('.' + base);
  }
  return host === pattern;
}

const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '::1', '[::1]'];

/**
 * Central CORS origin decision. Fail-closed:
 * - Non-http(s) origins are rejected.
 * - Empty allowlist in production rejects everything.
 * - Empty allowlist outside production only allows loopback origins
 *   (and only when `allowDevLoopback` is set).
 * Allowlist entries can be bare hosts (`example.com`), wildcard hosts
 * (`*.example.com`) or full origins (`https://example.com:8443`).
 */
function originAllowed(origin, allowedOrigins, opts) {
  opts = opts || {};
  if (!origin || typeof origin !== 'string') return false;

  let url;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;

  const list = (allowedOrigins || []).map(function (a) { return String(a).trim(); }).filter(Boolean);

  if (list.length === 0) {
    if (opts.production) return false;
    return !!opts.allowDevLoopback && LOOPBACK_HOSTS.indexOf(url.hostname) !== -1;
  }

  return list.some(function (allowed) {
    if (allowed.indexOf('://') !== -1) {
      try {
        return new URL(allowed).origin === url.origin;
      } catch {
        return false;
      }
    }
    return hostMatchesPattern(url.hostname, allowed);
  });
}

// ---------------------------------------------------------------------------
// Public-suffix-aware domain parsing.
//
// Manual "strip one label" parsing is wrong for multi-label public suffixes
// (example.co.uk, foo.com.au, …) and silently groups unrelated sites that
// merely share a suffix. All registrable-domain decisions go through the
// `psl` public suffix list instead.
// ---------------------------------------------------------------------------

const psl = require('psl');

const IPV4_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;

function isIpAddress(host) {
  if (!host || typeof host !== 'string') return false;
  return IPV4_REGEX.test(host) || host.indexOf(':') !== -1;
}

function cleanHostname(hostname) {
  if (!hostname || typeof hostname !== 'string') return null;
  const cleaned = hostname.trim().toLowerCase().replace(/\.$/, '');
  return cleaned.length > 0 ? cleaned : null;
}

/**
 * Returns the registrable domain (eTLD+1) for a hostname using the public
 * suffix list: `shop.example.co.uk` → `example.co.uk`.
 * IPs, `localhost`, single labels, and bare public suffixes are returned
 * unchanged — they have no meaningful parent.
 */
function getRegistrableDomain(hostname) {
  const cleaned = cleanHostname(hostname);
  if (!cleaned) return null;
  if (isIpAddress(cleaned) || cleaned.indexOf('.') === -1) return cleaned;
  const parsed = psl.parse(cleaned);
  if (parsed && !parsed.error && parsed.domain) return parsed.domain;
  // Bare public suffix (e.g. "co.uk") or unlisted TLD: treat the whole host
  // as its own registrable unit rather than inventing a bogus parent.
  return cleaned;
}

/**
 * Splits a hostname into { registrableDomain, subdomain } with public-suffix
 * awareness. `shop.example.co.uk` → { registrableDomain: 'example.co.uk',
 * subdomain: 'shop' }.
 */
function splitRegistrableDomain(hostname) {
  const cleaned = cleanHostname(hostname);
  const registrable = getRegistrableDomain(cleaned);
  if (!cleaned || !registrable || cleaned === registrable) {
    return { registrableDomain: registrable, subdomain: null };
  }
  const sub = cleaned.slice(0, cleaned.length - registrable.length - 1);
  return { registrableDomain: registrable, subdomain: sub || null };
}

/**
 * One DNS label up, but never above the registrable domain:
 * `a.b.example.co.uk` → `b.example.co.uk`; `example.co.uk` → null
 * (its "parent" would be the public suffix `co.uk`, which nobody owns).
 */
function parentDomainOf(hostname) {
  const cleaned = cleanHostname(hostname);
  if (!cleaned || isIpAddress(cleaned)) return null;
  const registrable = getRegistrableDomain(cleaned);
  if (!registrable || cleaned === registrable) return null;
  const idx = cleaned.indexOf('.');
  return idx === -1 ? null : cleaned.slice(idx + 1);
}

/**
 * WaiTag identifier format (pseudonymous cross-domain ID). Single source for
 * every server-side surface — the TS API and the plain-JS demo servers.
 */
const WAITAG_PATTERN = /^(wai_[0-9a-zA-Z]{10,}_[a-zA-Z0-9]{1,}|[a-z]+-\d+-[a-f0-9]+)$/;

// ---------------------------------------------------------------------------
// Fingerprint stripping — semantic, not a fixed key list.
//
// Nylo's public promise is "no fingerprinting". The SDK never collects these
// fields, and the server strips them from anything a client sends (defense
// in depth against modified clients and direct API callers). Matching is
// SEMANTIC: keys are normalized (lowercased, separators removed) and checked
// against exact names and unambiguous stems, so `user-agent`, `User Agent`,
// and `browserUserAgent` are all caught — not just `userAgent`.
// ---------------------------------------------------------------------------

/**
 * Documented reference list of forbidden telemetry keys (canonical,
 * normalized spellings). Matching goes through isForbiddenTelemetryKey(),
 * which catches separator/alias/compound variants of these as well.
 */
const FORBIDDEN_FINGERPRINT_FIELDS = [
  'useragent', 'user_agent', 'ua', 'uastring',
  'language', 'languages', 'locale',
  'timezone', 'time_zone', 'timezoneoffset',
  'screensize', 'screenwidth', 'screenheight', 'screenresolution',
  'viewportwidth', 'viewportheight', 'viewportsize',
  'colordepth', 'pixeldepth', 'pixelratio', 'devicepixelratio',
  'platform', 'oscpu', 'cpuclass', 'hardwareconcurrency', 'devicememory',
  'plugins', 'mimetypes', 'fonts', 'capabilities',
  'canvasfingerprint', 'webglfingerprint', 'audiofingerprint',
  'webglvendor', 'webglrenderer',
  'clickx', 'clicky', 'pagex', 'pagey', 'screenx', 'screeny',
  'clientx', 'clienty', 'offsetx', 'offsety', 'mousex', 'mousey',
  'cursorx', 'cursory', 'touchx', 'touchy', 'coordx', 'coordy',
  'xcoord', 'ycoord',
  'touchsupport', 'maxtouchpoints', 'cookiesenabled', 'donottrack',
  'battery', 'connectiontype', 'downlink'
];

// Short/ambiguous names: forbidden only as a whole (normalized) key, so
// legitimate fields like `platformFee` or `programmingLanguage` survive.
const FORBIDDEN_EXACT = new Set([
  'ua', 'dnt', 'language', 'languages', 'locale', 'platform', 'fonts',
  'plugins', 'mimetypes', 'battery', 'downlink', 'capabilities',
  'clickx', 'clicky', 'pagex', 'pagey', 'screenx', 'screeny',
  'clientx', 'clienty', 'offsetx', 'offsety', 'mousex', 'mousey',
  'cursorx', 'cursory', 'touchx', 'touchy', 'coordx', 'coordy',
  'xcoord', 'ycoord'
]);

// Unambiguous stems: any key whose normalized form CONTAINS one of these is
// fingerprint-capable (`browserUserAgent`, `deviceCapabilities`,
// `webglRendererInfo`, `tzTimezoneOffset`, …).
const FORBIDDEN_STEMS = [
  'useragent', 'uastring', 'fingerprint', 'timezone', 'viewport',
  'colordepth', 'pixeldepth', 'pixelratio', 'devicepixel',
  'hardwareconcurrency', 'devicememory', 'maxtouchpoints', 'touchsupport',
  'oscpu', 'cpuclass', 'mimetype', 'webgl', 'capabilit',
  'screenwidth', 'screenheight', 'screensize', 'screenres', 'screendepth',
  'availwidth', 'availheight', 'connectiontype', 'cookiesenabled',
  'donottrack'
];

function normalizeTelemetryKey(key) {
  return String(key).toLowerCase().replace(/[^a-z0-9]/g, '');
}

function isForbiddenTelemetryKey(key) {
  const norm = normalizeTelemetryKey(key);
  if (!norm) return false;
  if (FORBIDDEN_EXACT.has(norm)) return true;
  for (let i = 0; i < FORBIDDEN_STEMS.length; i++) {
    if (norm.indexOf(FORBIDDEN_STEMS[i]) !== -1) return true;
  }
  return false;
}

// Serialized-JSON handling: SDK metadata travels as a JSON string, and a
// hostile client could wrap anything in a string to dodge key filtering.
// Parseable JSON strings are therefore parsed, stripped, and re-serialized.
const MAX_EMBEDDED_JSON_BYTES = 8192;

function sanitizeTelemetryString(str, depth) {
  const trimmed = str.trim();
  // Absolute URLs anywhere in the payload (referrer, href, link, custom
  // fields…) are minimized to origin + path: query strings and fragments
  // routinely carry tokens, emails, and search terms.
  if (/^https?:\/\//i.test(trimmed)) {
    return sanitizeUrlForStorage(trimmed);
  }
  if (str.length <= MAX_EMBEDDED_JSON_BYTES && (trimmed[0] === '{' || trimmed[0] === '[')) {
    try {
      const parsed = JSON.parse(str);
      if (parsed && typeof parsed === 'object') {
        return JSON.stringify(stripFingerprintFields(parsed, depth + 1));
      }
    } catch (e) {
      // Not JSON — treat as plain text.
    }
  }
  return str;
}

/**
 * Deeply removes fingerprint-capable keys from a value (semantic,
 * case/separator-insensitive), minimizes URL string values to origin + path,
 * and sanitizes serialized-JSON strings recursively. Returns a new
 * structure; depth-limited to keep it cheap.
 */
function stripFingerprintFields(value, depth) {
  depth = depth || 0;
  if (depth > 6 || value === null || value === undefined) return value;
  if (typeof value === 'string') {
    return sanitizeTelemetryString(value, depth);
  }
  if (Array.isArray(value)) {
    return value.map((item) => stripFingerprintFields(item, depth + 1));
  }
  if (typeof value === 'object') {
    const out = {};
    for (const [key, val] of Object.entries(value)) {
      if (isForbiddenTelemetryKey(key)) continue;
      out[key] = stripFingerprintFields(val, depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * Reduces a URL to origin + path for storage: query strings and fragments
 * routinely carry tokens, emails, and search terms and are never stored.
 * Non-http(s) and unparseable URLs become '' (rejected, not "normalized").
 */
function sanitizeUrlForStorage(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
    return (parsed.origin + parsed.pathname).substring(0, 2048);
  } catch (e) {
    return '';
  }
}

module.exports = {
  isValidDomainName,
  hostMatchesPattern,
  originAllowed,
  isIpAddress,
  getRegistrableDomain,
  splitRegistrableDomain,
  parentDomainOf,
  WAITAG_PATTERN,
  FORBIDDEN_FINGERPRINT_FIELDS,
  isForbiddenTelemetryKey,
  normalizeTelemetryKey,
  stripFingerprintFields,
  sanitizeUrlForStorage
};
