// SPDX-License-Identifier: MIT
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const { createTrackHandler } = require('./track-ingestion');
const { LIMITS } = require('../shared/event-envelope');
const { createCorsMiddleware } = require('./demo-cors');
const { registerTokenVerification } = require('./demo-token-routes');
const {
  signCrossDomainToken,
  verifyCrossDomainToken,
  hashToken,
  createInMemoryReplayStore,
  DEFAULT_TTL_MS
} = require('../server/utils/token-core');
const {
  signWriteGrant,
  verifyWriteGrant,
  DEFAULT_GRANT_TTL_MS
} = require('../server/utils/write-grant');
const { WAITAG_PATTERN, isValidDomainName } = require('../server/utils/security-core');

const app = express();
app.use(express.json({ limit: LIMITS.MAX_BATCH_BYTES }));

const ALLOWED_ORIGINS = (process.env.NYLO_ALLOWED_ORIGINS || '').split(',').filter(Boolean);
const ENFORCE_HTTPS = process.env.NODE_ENV === 'production';

const NYLO_TOKEN_SECRET = (function() {
  if (process.env.NYLO_TOKEN_SECRET) {
    return process.env.NYLO_TOKEN_SECRET;
  }
  const ephemeral = crypto.randomBytes(32).toString('hex');
  console.warn('[SECURITY] NYLO_TOKEN_SECRET not set — generated ephemeral secret for this session.');
  console.warn('[SECURITY] Cross-domain tokens will not survive server restarts.');
  console.warn('[SECURITY] Set NYLO_TOKEN_SECRET environment variable for production use.');
  return ephemeral;
})();

if (process.env.NODE_ENV === 'production') {
  console.error(
    '[SECURITY] examples/demo-server.js is development-only: its event and ' +
    'token-replay stores are in-memory (lost on restart, not shared across ' +
    'instances), so token single-use cannot be guaranteed. Use the ' +
    'production server with durable storage, or the SQLite/Postgres demos.'
  );
  process.exit(1);
}

// Development-only in-memory replay store (production refuses to start above).
const replayStore = createInMemoryReplayStore();

/**
 * Server-side domain→tenant mapping — the single source of tenant identity.
 * The demo maps loopback and the Replit dev domain to demo tenant '1'.
 * Real deployments configure NYLO_DEMO_DOMAINS or implement a real lookup.
 */
const DEMO_TENANT_ID = '1';
const grantDomains = new Set(['localhost', '127.0.0.1']);
if (process.env.REPLIT_DEV_DOMAIN) grantDomains.add(process.env.REPLIT_DEV_DOMAIN.toLowerCase());
(process.env.NYLO_DEMO_DOMAINS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
  .forEach(d => grantDomains.add(d));

function getTenantIdForDomain(domain) {
  return grantDomains.has(domain) ? DEMO_TENANT_ID : null;
}

if (ENFORCE_HTTPS) {
  // Redirect targets are never built from the client-controlled Host
  // header. Without a configured canonical host, redirecting is unsafe —
  // terminate TLS at the proxy instead.
  const canonicalHost = (process.env.NYLO_CANONICAL_HOST || '').trim().toLowerCase();
  if (canonicalHost) {
    app.set('trust proxy', 1);
    app.use((req, res, next) => {
      if (req.secure) return next();
      return res.redirect(301, 'https://' + canonicalHost + req.url);
    });
  } else {
    console.warn('[SECURITY] NYLO_CANONICAL_HOST not set — HTTP→HTTPS redirect disabled (redirects must never trust the Host header). Terminate TLS at your proxy.');
  }
}

app.use((req, res, next) => {
  res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.header('Pragma', 'no-cache');
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-XSS-Protection', '1; mode=block');
  res.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// Centralized fail-closed CORS shared by all demo servers (see demo-cors.js).
app.use(createCorsMiddleware({ allowedOrigins: ALLOWED_ORIGINS, production: ENFORCE_HTTPS }));

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX = 100;

setInterval(() => { rateLimitMap.clear(); }, RATE_LIMIT_WINDOW);

app.use('/api/', (req, res, next) => {
  const key = req.ip || req.connection.remoteAddress || 'unknown';
  const current = rateLimitMap.get(key) || 0;
  if (current >= RATE_LIMIT_MAX) {
    return res.status(429).json({ 
      success: false, 
      message: 'Rate limit exceeded. Try again later.',
      retryAfter: Math.ceil(RATE_LIMIT_WINDOW / 1000)
    });
  }
  rateLimitMap.set(key, current + 1);
  res.header('X-RateLimit-Limit', String(RATE_LIMIT_MAX));
  res.header('X-RateLimit-Remaining', String(RATE_LIMIT_MAX - current - 1));
  next();
});

app.get('/nylo.js', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'src', 'nylo.js'));
});

app.get('/', (req, res) => {
  res.redirect('/demo.html');
});

app.use(express.static(path.join(__dirname)));

const interactions = [];
const waiTags = [];

/**
 * Write-grant issuance. The browser asks for write authorization for the
 * domain it is running on; the server resolves the tenant from its own
 * mapping and Origin-checks the request. No customer IDs from the client.
 */
app.post('/api/tracking/grant', (req, res) => {
  const rawDomain = String((req.body && req.body.domain) || '').trim().toLowerCase();
  if (!rawDomain || (rawDomain !== 'localhost' && rawDomain !== '127.0.0.1' && !isValidDomainName(rawDomain))) {
    return res.status(400).json({ success: false, error: 'INVALID_DOMAIN', message: 'A valid page domain is required' });
  }

  // A browser cannot forge its Origin header, so a page can only obtain
  // grants for the domain it is actually served from.
  const origin = req.headers.origin;
  if (origin) {
    let originHost = null;
    try { originHost = new URL(String(origin)).hostname.toLowerCase(); } catch (e) { originHost = null; }
    if (originHost !== rawDomain) {
      return res.status(403).json({ success: false, error: 'ORIGIN_MISMATCH', message: 'Origin header does not match the requested domain' });
    }
  }

  const tenantId = getTenantIdForDomain(rawDomain);
  if (!tenantId) {
    return res.status(403).json({ success: false, error: 'UNKNOWN_DOMAIN', message: 'No tenant is configured for this domain' });
  }

  const grant = signWriteGrant(
    { tenantId, domain: rawDomain, scopes: ['ingest', 'register'] },
    NYLO_TOKEN_SECRET
  );
  res.json({
    success: true,
    grant,
    expiresAt: new Date(Date.now() + DEFAULT_GRANT_TTL_MS).toISOString(),
    scopes: ['ingest', 'register']
  });
});

app.post('/api/track', createTrackHandler((event) => {
  const interaction = {
    id: interactions.length + 1,
    eventId: event.eventId,
    eventType: event.eventType,
    domain: event.domain,
    sessionId: event.sessionId,
    userId: event.userId,
    waiTag: event.waiTag,
    customerId: event.customerId,
    url: event.url,
    metadata: event.metadata,
    clientTimestamp: event.clientTimestamp,
    timestamp: event.receivedAt
  };
  interactions.push(interaction);
}, { grantSecret: () => NYLO_TOKEN_SECRET }));

app.post('/api/tracking/register-waitag', (req, res) => {
  // Registration requires a write grant with the 'register' scope; the
  // tenant is the grant's tenant and the domain must match the grant.
  const rawGrant = req.headers['x-nylo-grant'];
  const grantValue = Array.isArray(rawGrant) ? rawGrant[0] : rawGrant;
  if (!grantValue) {
    return res.status(401).json({ success: false, error: 'GRANT_REQUIRED', message: 'A write grant is required' });
  }
  const grantResult = verifyWriteGrant(String(grantValue), NYLO_TOKEN_SECRET, { requiredScope: 'register' });
  if (!grantResult.valid) {
    return res.status(403).json({ success: false, error: 'GRANT_' + (grantResult.error || 'INVALID'), message: 'Write grant rejected: ' + (grantResult.error || 'INVALID') });
  }

  const { waiTag, sessionId, domain } = req.body;
  if (!waiTag || !sessionId) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }
  // Malformed identifiers are rejected, not stored.
  if (typeof waiTag !== 'string' || !WAITAG_PATTERN.test(waiTag)) {
    return res.status(400).json({ success: false, error: 'INVALID_WAITAG', message: 'WaiTag format is invalid' });
  }
  const boundDomain = String(domain || '').trim().toLowerCase();
  if (boundDomain && boundDomain !== grantResult.payload.domain) {
    return res.status(403).json({ success: false, error: 'DOMAIN_MISMATCH', message: 'Domain does not match the write grant' });
  }

  const registration = {
    waiTag,
    sessionId,
    domain: grantResult.payload.domain,
    customerId: String(grantResult.payload.tenantId),
    registeredAt: new Date().toISOString()
  };

  waiTags.push(registration);

  res.json({
    success: true,
    waiTag,
    sessionId,
    message: 'WaiTag registered'
  });
});

// WTX-1 token verification with replay protection (shared, see demo-token-routes.js).
// Grant-gated: unauthenticated callers can no longer consume (burn) tokens.
registerTokenVerification(app, { secret: NYLO_TOKEN_SECRET, replayStore, grantSecret: NYLO_TOKEN_SECRET });

app.post('/api/tracking/generate-cross-domain-token', (req, res) => {
  // Server-to-server only. Requires an explicitly configured API key —
  // the signing secret must never double as an API key, otherwise handing
  // out "API access" would also hand out the ability to forge tokens.
  if (!process.env.NYLO_API_KEY) {
    return res.status(503).json({
      success: false,
      error: 'NOT_CONFIGURED',
      message: 'Token generation requires NYLO_API_KEY to be configured'
    });
  }
  const apiKey = req.headers['x-api-key'];
  const expected = Buffer.from(process.env.NYLO_API_KEY);
  const provided = Buffer.from(String(apiKey || ''));
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
    return res.status(401).json({
      success: false,
      error: 'UNAUTHORIZED',
      message: 'Valid X-API-Key header is required to generate tokens'
    });
  }

  const { waiTag, sessionId, userId, customerId, sourceDomain, destinationDomain } = req.body;

  if (!waiTag || !sessionId) {
    return res.status(400).json({ success: false, message: 'waiTag and sessionId are required' });
  }
  if (!customerId || !sourceDomain || !destinationDomain) {
    return res.status(400).json({
      success: false,
      message: 'customerId, sourceDomain and destinationDomain are required — tokens are bound to tenant + source + destination'
    });
  }

  let token;
  try {
    token = signCrossDomainToken({
      tenantId: customerId,
      sourceDomain,
      destinationDomain,
      waiTag,
      sessionId,
      userId: userId || null
    }, NYLO_TOKEN_SECRET);
  } catch (e) {
    return res.status(400).json({ success: false, message: e.message });
  }

  res.json({
    success: true,
    token,
    expiresAt: new Date(Date.now() + DEFAULT_TTL_MS).toISOString()
  });
});

app.get('/api/events', (req, res) => {
  res.json({
    total: interactions.length,
    events: interactions.slice(-100),
    waiTags: waiTags.slice(-20)
  });
});

app.get('/api/events/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  let lastSent = interactions.length;

  const interval = setInterval(() => {
    if (interactions.length > lastSent) {
      const newEvents = interactions.slice(lastSent);
      for (const event of newEvents) {
        res.write(`data: ${JSON.stringify(event)}\n\n`);
      }
      lastSent = interactions.length;
    }
  }, 500);

  req.on('close', () => {
    clearInterval(interval);
  });
});

app.get('/api/stats', (req, res) => {
  const eventTypes = {};
  const domains = {};
  const uniqueSessions = new Set();
  const uniqueWaiTags = new Set();

  for (const event of interactions) {
    eventTypes[event.eventType] = (eventTypes[event.eventType] || 0) + 1;
    domains[event.domain] = (domains[event.domain] || 0) + 1;
    if (event.sessionId) uniqueSessions.add(event.sessionId);
    if (event.waiTag) uniqueWaiTags.add(event.waiTag);
  }

  res.json({
    totalEvents: interactions.length,
    uniqueSessions: uniqueSessions.size,
    uniqueWaiTags: uniqueWaiTags.size,
    registeredWaiTags: waiTags.length,
    eventTypes,
    domains
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Nylo Demo Server running at http://localhost:${PORT}`);
  console.log(`Open http://localhost:${PORT}/demo.html to see the interactive demo`);
  console.log(`View collected events at http://localhost:${PORT}/api/events`);
  console.log(`View stats at http://localhost:${PORT}/api/stats`);
});
