/**
 * Nylo Demo Server with SQLite Persistence
 *
 * A version of the demo server that uses SQLite for storage instead of
 * in-memory arrays. Events persist across server restarts.
 *
 * Usage:
 *   cd examples
 *   npm install
 *   npm install better-sqlite3
 *   node demo-server-sqlite.js
 *   # Open http://localhost:5000/demo.html
 */

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { createSqliteStorage } = require('./storage-sqlite');

const { createTrackHandler } = require('./track-ingestion');
const { LIMITS } = require('../shared/event-envelope');
const { createCorsMiddleware } = require('./demo-cors');
const { registerTokenVerification } = require('./demo-token-routes');

const NYLO_TOKEN_SECRET = (function() {
  if (process.env.NYLO_TOKEN_SECRET) return process.env.NYLO_TOKEN_SECRET;
  const ephemeral = crypto.randomBytes(32).toString('hex');
  console.warn('[SECURITY] NYLO_TOKEN_SECRET not set — generated ephemeral secret for this session.');
  return ephemeral;
})();

const app = express();
app.use(express.json({ limit: LIMITS.MAX_BATCH_BYTES }));

app.use((req, res, next) => {
  res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.header('Pragma', 'no-cache');
  next();
});

// Centralized fail-closed CORS (see examples/demo-cors.js).
app.use(createCorsMiddleware());

const storage = createSqliteStorage(path.join(__dirname, 'nylo-demo.db'));

app.get('/nylo.js', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'src', 'nylo.js'));
});

app.use(express.static(path.join(__dirname)));

app.post('/api/track', createTrackHandler(async (event) => {
  await storage.createInteraction({
    sessionId: event.sessionId,
    userId: event.userId,
    waiTag: event.waiTag,
    pageUrl: event.url,
    domain: event.domain,
    mainDomain: event.domain.split('.').length > 2 ? event.domain.split('.').slice(1).join('.') : event.domain,
    subdomain: event.domain.split('.').length > 2 ? event.domain.split('.')[0] : null,
    interactionType: event.eventType,
    content: event.metadata,
    customerId: event.customerId,
    featureName: event.eventType,
    featureCategory: 'tracking',
    context: {
      metadata: event.metadata,
      eventId: event.eventId,
      clientTimestamp: event.clientTimestamp,
      serverReceivedAt: event.receivedAt
    }
  });
}));

app.post('/api/tracking/register-waitag', async (req, res) => {
  const { waiTag, sessionId, domain, customerId } = req.body;
  if (!waiTag || !sessionId) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  res.json({ success: true, waiTag, sessionId, message: 'WaiTag registered' });
});

// WTX-1 token verification with replay protection (shared, see demo-token-routes.js).
registerTokenVerification(app, { secret: NYLO_TOKEN_SECRET });

app.get('/api/events', (req, res) => {
  const events = storage.getRecentEvents(100);
  res.json({ total: events.length, events });
});

app.get('/api/events/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  let lastId = 0;

  const interval = setInterval(() => {
    const events = storage.getRecentEvents(10);
    const newEvents = events.filter(e => e.id > lastId);
    for (const event of newEvents) {
      res.write(`data: ${JSON.stringify(event)}\n\n`);
      lastId = event.id;
    }
  }, 500);

  req.on('close', () => clearInterval(interval));
});

app.get('/api/stats', (req, res) => {
  res.json(storage.getStats());
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Nylo Demo Server (SQLite) running at http://localhost:${PORT}`);
  console.log(`Open http://localhost:${PORT}/demo.html to see the interactive demo`);
  console.log(`Data persisted to nylo-demo.db`);
});

process.on('SIGINT', () => {
  storage.close();
  process.exit(0);
});
