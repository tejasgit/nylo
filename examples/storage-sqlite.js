// SPDX-License-Identifier: MIT
/**
 * Nylo SQLite Storage Adapter — Reference Implementation
 *
 * A minimal storage implementation using better-sqlite3 that satisfies
 * the NyloStorage interface. Drop this into your server to get a
 * fully working Nylo backend in minutes.
 *
 * Usage:
 *   cd examples
 *   npm install better-sqlite3
 *   node demo-server-sqlite.js
 *
 * This stores all data in a local `nylo.db` file. For production,
 * swap this out for PostgreSQL, MySQL, or your preferred database.
 */

const Database = require('better-sqlite3');

function createSqliteStorage(dbPath) {
  const db = new Database(dbPath || 'nylo.db');

  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS interactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      user_id TEXT,
      wai_tag TEXT,
      timestamp TEXT NOT NULL,
      page_url TEXT,
      domain TEXT NOT NULL,
      main_domain TEXT,
      subdomain TEXT,
      interaction_type TEXT NOT NULL,
      content TEXT,
      customer_id TEXT,
      feature_name TEXT,
      feature_category TEXT,
      context TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      api_key TEXT UNIQUE NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS domain_verifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT NOT NULL,
      customer_id INTEGER NOT NULL,
      token TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      verified_at TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(domain, customer_id)
    );

    CREATE INDEX IF NOT EXISTS idx_interactions_session ON interactions(session_id);
    CREATE INDEX IF NOT EXISTS idx_interactions_domain ON interactions(domain);
    CREATE INDEX IF NOT EXISTS idx_interactions_type ON interactions(interaction_type);
    CREATE INDEX IF NOT EXISTS idx_domain_verifications_lookup ON domain_verifications(domain, customer_id);
  `);

  const defaultCustomer = db.prepare(
    'INSERT OR IGNORE INTO customers (id, name, api_key) VALUES (?, ?, ?)'
  );
  defaultCustomer.run(1, 'Demo Customer', 'demo_api_key_12345678');

  db.exec(`
    CREATE TABLE IF NOT EXISTS consumed_tokens (
      token_hash TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL
    );
  `);

  return {
    // Durable atomic replay store for WTX-1 tokens: INSERT OR IGNORE is
    // atomic in SQLite, so of N concurrent consumes exactly one wins, and
    // consumed hashes survive server restarts (unlike the in-memory store).
    tokenReplayStore: {
      consumeToken(tokenHash, ttlMs) {
        db.prepare('DELETE FROM consumed_tokens WHERE expires_at < ?').run(Date.now());
        const result = db.prepare(
          'INSERT OR IGNORE INTO consumed_tokens (token_hash, expires_at) VALUES (?, ?)'
        ).run(tokenHash, Date.now() + (ttlMs || 300000));
        return result.changes === 1;
      }
    },

    async createInteraction(data) {
      const stmt = db.prepare(`
        INSERT INTO interactions
          (session_id, user_id, wai_tag, timestamp, page_url, domain,
           main_domain, subdomain, interaction_type, content,
           customer_id, feature_name, feature_category, context)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const result = stmt.run(
        data.sessionId,
        data.userId || null,
        data.waiTag || null,
        new Date().toISOString(),
        data.pageUrl || '',
        data.domain,
        data.mainDomain || null,
        data.subdomain || null,
        data.interactionType,
        typeof data.content === 'string' ? data.content : JSON.stringify(data.content || ''),
        data.customerId || null,
        data.featureName || null,
        data.featureCategory || null,
        JSON.stringify(data.context || {})
      );

      return { id: result.lastInsertRowid, ...data };
    },

    async getCustomer(id) {
      return db.prepare('SELECT * FROM customers WHERE id = ?').get(id) || null;
    },

    async getCustomerByApiKey(apiKey) {
      return db.prepare('SELECT * FROM customers WHERE api_key = ?').get(apiKey) || null;
    },

    parseDomain(domain) {
      const parts = domain.split('.');
      if (parts.length > 2) {
        return { mainDomain: parts.slice(1).join('.'), subdomain: parts[0] };
      }
      return { mainDomain: domain, subdomain: null };
    },

    async getDomainVerification(domain, customerId) {
      return db.prepare(
        'SELECT * FROM domain_verifications WHERE domain = ? AND customer_id = ?'
      ).get(domain, customerId) || null;
    },

    async createDomainVerification(data) {
      const stmt = db.prepare(`
        INSERT INTO domain_verifications (domain, customer_id, token, status)
        VALUES (?, ?, ?, ?)
      `);
      const result = stmt.run(data.domain, data.customerId, data.token, data.status || 'pending');
      return { id: result.lastInsertRowid, ...data, createdAt: new Date().toISOString() };
    },

    async updateDomainVerification(domain, customerId, data) {
      const sets = [];
      const values = [];

      if (data.status) {
        sets.push('status = ?');
        values.push(data.status);
      }
      if (data.status === 'verified') {
        sets.push("verified_at = datetime('now')");
      }

      if (sets.length === 0) return null;

      values.push(domain, customerId);
      db.prepare(
        `UPDATE domain_verifications SET ${sets.join(', ')} WHERE domain = ? AND customer_id = ?`
      ).run(...values);

      return this.getDomainVerification(domain, customerId);
    },

    async isDomainVerified(domain, customerId) {
      const record = db.prepare(
        'SELECT status FROM domain_verifications WHERE domain = ? AND customer_id = ?'
      ).get(domain, customerId);
      return record?.status === 'verified';
    },

    getRecentEvents(limit) {
      return db.prepare(
        'SELECT * FROM interactions ORDER BY id DESC LIMIT ?'
      ).all(limit || 50);
    },

    getStats() {
      const total = db.prepare('SELECT COUNT(*) as count FROM interactions').get();
      const sessions = db.prepare('SELECT COUNT(DISTINCT session_id) as count FROM interactions').get();
      const domains = db.prepare('SELECT domain, COUNT(*) as count FROM interactions GROUP BY domain').all();
      const types = db.prepare('SELECT interaction_type, COUNT(*) as count FROM interactions GROUP BY interaction_type').all();

      return {
        totalEvents: total.count,
        uniqueSessions: sessions.count,
        domains: Object.fromEntries(domains.map(d => [d.domain, d.count])),
        eventTypes: Object.fromEntries(types.map(t => [t.interaction_type, t.count]))
      };
    },

    close() {
      db.close();
    }
  };
}

module.exports = { createSqliteStorage };
