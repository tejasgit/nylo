// SPDX-License-Identifier: MIT
/**
 * Shared write-grant issuance and WaiTag registration for demo servers.
 * Tenant identity is resolved from a server-owned domain allowlist; browser
 * bodies never select a tenant.
 */
'use strict';

const {
  signWriteGrant,
  verifyWriteGrant,
  DEFAULT_GRANT_TTL_MS
} = require('../server/utils/write-grant');
const {
  WAITAG_PATTERN,
  isValidDomainName
} = require('../server/utils/security-core');

function registerDemoWriteRoutes(app, options) {
  options = options || {};
  const secret = options.secret;
  if (!secret) throw new Error('registerDemoWriteRoutes requires a signing secret');

  const tenantId = String(options.tenantId || '1');
  const domains = new Set(['localhost', '127.0.0.1']);
  if (process.env.REPLIT_DEV_DOMAIN) domains.add(process.env.REPLIT_DEV_DOMAIN.toLowerCase());
  String(process.env.NYLO_DEMO_DOMAINS || '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean)
    .forEach((value) => domains.add(value));

  app.post('/api/tracking/grant', (req, res) => {
    const domain = String((req.body && req.body.domain) || '').trim().toLowerCase();
    if (!domain || (domain !== 'localhost' && domain !== '127.0.0.1' && !isValidDomainName(domain))) {
      return res.status(400).json({ success: false, error: 'INVALID_DOMAIN', message: 'A valid page domain is required' });
    }

    const origin = req.headers.origin;
    if (origin) {
      let originHost = null;
      try { originHost = new URL(String(origin)).hostname.toLowerCase(); } catch {}
      if (originHost !== domain) {
        return res.status(403).json({ success: false, error: 'ORIGIN_MISMATCH', message: 'Origin does not match the requested domain' });
      }
    }
    if (!domains.has(domain)) {
      return res.status(403).json({ success: false, error: 'UNKNOWN_DOMAIN', message: 'No tenant is configured for this domain' });
    }

    const grant = signWriteGrant({ tenantId, domain, scopes: ['ingest', 'register'] }, secret);
    return res.json({
      success: true,
      grant,
      expiresAt: new Date(Date.now() + DEFAULT_GRANT_TTL_MS).toISOString(),
      scopes: ['ingest', 'register']
    });
  });

  app.post('/api/tracking/register-waitag', async (req, res) => {
    const rawGrant = req.headers['x-nylo-grant'];
    const grantValue = Array.isArray(rawGrant) ? rawGrant[0] : rawGrant;
    if (!grantValue) {
      return res.status(401).json({ success: false, error: 'GRANT_REQUIRED', message: 'A write grant is required' });
    }
    const grantResult = verifyWriteGrant(String(grantValue), secret, { requiredScope: 'register' });
    if (!grantResult.valid) {
      return res.status(403).json({ success: false, error: 'GRANT_' + (grantResult.error || 'INVALID'), message: 'Write grant rejected' });
    }

    const body = req.body || {};
    if (typeof body.waiTag !== 'string' || !WAITAG_PATTERN.test(body.waiTag) ||
        typeof body.sessionId !== 'string' || body.sessionId.length < 1 || body.sessionId.length > 256) {
      return res.status(400).json({ success: false, error: 'INVALID_IDENTITY', message: 'Invalid WaiTag or session identifier' });
    }
    const bodyDomain = String(body.domain || '').trim().toLowerCase();
    if (bodyDomain && bodyDomain !== grantResult.payload.domain) {
      return res.status(403).json({ success: false, error: 'DOMAIN_MISMATCH', message: 'Domain does not match the write grant' });
    }
    if (body.customerId !== undefined && body.customerId !== null &&
        String(body.customerId) !== String(grantResult.payload.tenantId)) {
      return res.status(403).json({ success: false, error: 'TENANT_MISMATCH', message: 'Tenant does not match the write grant' });
    }

    const registration = {
      waiTag: body.waiTag,
      sessionId: body.sessionId,
      domain: grantResult.payload.domain,
      customerId: String(grantResult.payload.tenantId),
      registeredAt: new Date().toISOString()
    };
    if (typeof options.storeRegistration === 'function') {
      await options.storeRegistration(registration);
    }
    return res.json({ success: true, waiTag: registration.waiTag, sessionId: registration.sessionId, message: 'WaiTag registered' });
  });
}

module.exports = { registerDemoWriteRoutes };