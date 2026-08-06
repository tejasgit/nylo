/**
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

module.exports = {
  isValidDomainName,
  hostMatchesPattern,
  originAllowed
};
