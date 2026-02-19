const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());

app.use((req, res, next) => {
  res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.header('Pragma', 'no-cache');
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'SAMEORIGIN');
  res.header('X-XSS-Protection', '1; mode=block');
  res.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'");
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers',
      'Origin, X-Requested-With, Content-Type, Accept, X-API-Key, X-Customer-ID, X-Session-ID, X-WaiTag, X-Batch-Size, X-SDK-Version');
    res.header('Access-Control-Expose-Headers',
      'X-WaiTag, X-Cross-Domain-WaiTag, X-Session-ID');
  }
  if (req.method === 'OPTIONS') return res.status(200).send();
  next();
});

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

app.post('/api/track', (req, res) => {
  let events = [];
  let common = {};

  if (req.body.common && req.body.events) {
    common = req.body.common;
    events = req.body.events;
  } else if (Array.isArray(req.body.events)) {
    events = req.body.events;
  } else if (Array.isArray(req.body)) {
    events = req.body;
  } else {
    events = [req.body];
  }

  let processedCount = 0;

  const customerId = req.headers['x-customer-id'] || common.customerId || '1';

  for (const event of events) {
    const eventType = event.eventType || event.interactionType;
    const sessionId = event.sessionId || common.sessionId || req.headers['x-session-id'];
    const domain = event.domain || common.domain || 'localhost';
    const waiTag = event.waiTag || common.waiTag || req.headers['x-waitag'] || null;
    const userId = event.userId || common.userId || waiTag;

    if (!eventType) continue;

    const interaction = {
      id: interactions.length + 1,
      eventType,
      domain,
      sessionId: sessionId || 'unknown',
      userId,
      waiTag,
      customerId,
      url: event.url || event.pageUrl || '',
      metadata: event.metadata || {},
      timestamp: new Date().toISOString()
    };
    interactions.push(interaction);
    processedCount++;
  }

  res.json({ success: true, eventsProcessed: processedCount, totalEvents: events.length });
});

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

app.post('/api/tracking/verify-cross-domain-token', (req, res) => {
  const { token, domain, customerId } = req.body;
  res.json({
    success: true,
    verified: true,
    identity: {
      sessionId: 'demo-session-' + Date.now().toString(36),
      waiTag: 'wai_' + Date.now().toString(36) + '_demo',
      userId: null
    },
    domain,
    message: 'Token verified (demo mode)'
  });
});

app.post('/api/tracking/sync-identity', (req, res) => {
  const { waiTag, sessionId, domain } = req.body;
  res.json({
    success: true,
    synced: true,
    waiTag,
    sessionId,
    domain,
    message: 'Identity synced (demo mode)'
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
