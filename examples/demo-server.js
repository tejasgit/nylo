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

const replayStore = createInMemoryReplayStore();

if (ENFORCE_HTTPS) {
  app.use((req, res, next) => {
    if (!req.secure && req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, 'https://' + req.headers.host + req.url);
    }
    next();
  });
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

app.use(express.static(path.join(__dirname)));

const interactions = [];
const waiTags = [];

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
}));

app.post('/api/tracking/register-waitag', (req, res) => {
  const { waiTag, sessionId, domain, customerId } = req.body;
  if (!waiTag || !sessionId) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  const registration = {
    waiTag,
    sessionId,
    domain: domain || 'localhost',
    customerId: customerId || '1',
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
registerTokenVerification(app, { secret: NYLO_TOKEN_SECRET, replayStore });

app.post('/api/tracking/generate-cross-domain-token', (req, res) => {
  var apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== (process.env.NYLO_API_KEY || NYLO_TOKEN_SECRET)) {
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
    if (event.userId) uniqueWaiTags.add(event.userId);
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
