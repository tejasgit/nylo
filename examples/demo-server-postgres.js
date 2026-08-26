// SPDX-License-Identifier: MIT
/**
 * Nylo Demo Server with PostgreSQL Persistence
 *
 * A version of the demo server that uses PostgreSQL for storage instead of
 * in-memory arrays. Events persist across server restarts.
 *
 * Usage:
 *   cd examples
 *   npm install
 *   npm install pg
 *   export DATABASE_URL=postgres://user:password@localhost:5432/nylo
 *   node demo-server-postgres.js
 *   # Open http://localhost:5000/demo.html
 */

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { createPostgresStorage } = require('./storage-postgres');

const { createTrackHandler } = require('./track-ingestion');
const { LIMITS } = require('../shared/event-envelope');
const { createCorsMiddleware } = require('./demo-cors');
const { registerTokenVerification } = require('./demo-token-routes');
const { registerDemoWriteRoutes } = require('./demo-write-routes');

const NYLO_TOKEN_SECRET = (function() {
  if (process.env.NYLO_TOKEN_SECRET) return process.env.NYLO_TOKEN_SECRET;
  if (process.env.NODE_ENV === 'production') {
    throw new Error('[Nylo] NYLO_TOKEN_SECRET is required in production');
  }
  const ephemeral = crypto.randomBytes(32).toString('hex');
  console.warn('[SECURITY] NYLO_TOKEN_SECRET not set — generated ephemeral secret for this session.');
  return ephemeral;
})();

if (process.env.NODE_ENV === 'production') {
  throw new Error(
    '[Nylo] examples/demo-server-postgres.js is development-only because its ' +
    'event viewer routes are intentionally unauthenticated. Use setupNyloRoutes ' +
    'with authenticated administrative routes in production.'
  );
}

const app = express();
app.use(express.json({ limit: LIMITS.MAX_BATCH_BYTES }));

app.use((req, res, next) => {
  res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.header('Pragma', 'no-cache');
  next();
});

// Centralized fail-closed CORS (see examples/demo-cors.js).
app.use(createCorsMiddleware());

async function startServer() {
  let storage;
  try {
    storage = await createPostgresStorage();
  } catch (err) {
    console.error('Could not initialize PostgreSQL storage. Make sure DATABASE_URL is set and the database exists.', err);
    process.exit(1);
  }

  app.get('/nylo.js', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'src', 'nylo.js'));
  });

  app.use(express.static(path.join(__dirname)));

  registerDemoWriteRoutes(app, { secret: NYLO_TOKEN_SECRET });

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
  }, { grantSecret: NYLO_TOKEN_SECRET }));

  // WTX-1 token verification with replay protection (shared, see demo-token-routes.js).
  registerTokenVerification(app, {
    secret: NYLO_TOKEN_SECRET,
    grantSecret: NYLO_TOKEN_SECRET,
    // Durable, atomic replay store shared across instances via Postgres.
    replayStore: storage.tokenReplayStore
  });

  app.get('/api/events', async (req, res) => {
    try {
      const events = await storage.getRecentEvents(100);
      res.json({ total: events.length, events });
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch events' });
    }
  });

  app.get('/api/events/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    let lastId = 0;

    const interval = setInterval(async () => {
      try {
        const events = await storage.getRecentEvents(10);
        const newEvents = events.filter(e => e.id > lastId);
        for (const event of newEvents) {
          res.write(`data: ${JSON.stringify(event)}\n\n`);
          lastId = event.id;
        }
      } catch (err) {
        console.error('Error fetching stream events:', err.message);
      }
    }, 500);

    req.on('close', () => clearInterval(interval));
  });

  app.get('/api/stats', async (req, res) => {
    try {
      res.json(await storage.getStats());
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch stats' });
    }
  });

  const PORT = process.env.PORT || 5000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Nylo Demo Server (PostgreSQL) running at http://localhost:${PORT}`);
    console.log(`Make sure DATABASE_URL is properly configured!`);
    console.log(`Open http://localhost:${PORT}/demo.html to see the interactive demo`);
  });

  process.on('SIGINT', async () => {
    await storage.close();
    process.exit(0);
  });
}

startServer();
