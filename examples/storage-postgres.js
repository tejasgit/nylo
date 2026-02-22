/**
 * Nylo PostgreSQL Storage Adapter — Reference Implementation
 *
 * A robust storage implementation using the 'pg' package that satisfies
 * the NyloStorage interface. Suitable for production environments.
 *
 * Usage:
 *   cd examples
 *   npm install pg
 *   node demo-server-postgres.js
 *   # Note: You can require this adapter in your server setup.
 *
 * Setup Instructions:
 *   1. Ensure PostgreSQL is installed and running.
 *   2. Create a database for Nylo (e.g., `createdb nylo`).
 *   3. Set the DATABASE_URL environment variable to point to your DB:
 *      export DATABASE_URL=postgres://user:password@localhost:5432/nylo
 *   4. The adapter will automatically run migrations to create tables
 *      on the first connection initialization.
 */

const { Pool } = require('pg');

async function createPostgresStorage(connectionString) {
  // Use provided connectionString or default to DATABASE_URL environment variable
  const pool = new Pool({
    connectionString: connectionString || process.env.DATABASE_URL,
    // Connection pool configuration
    max: 20, // maximum number of clients in the pool
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  });

  // Test connection and run migrations
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Create tables and indexes
    await client.query(`
      CREATE TABLE IF NOT EXISTS customers (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        api_key TEXT UNIQUE NOT NULL,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS interactions (
        id SERIAL PRIMARY KEY,
        session_id TEXT NOT NULL,
        user_id TEXT,
        wai_tag TEXT,
        timestamp TIMESTAMPTZ NOT NULL,
        page_url TEXT,
        domain TEXT NOT NULL,
        main_domain TEXT,
        subdomain TEXT,
        interaction_type TEXT NOT NULL,
        content JSONB,
        customer_id INTEGER,
        feature_name TEXT,
        feature_category TEXT,
        context JSONB,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS domain_verifications (
        id SERIAL PRIMARY KEY,
        domain TEXT NOT NULL,
        customer_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        verified_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(domain, customer_id)
      );

      CREATE INDEX IF NOT EXISTS idx_interactions_session ON interactions(session_id);
      CREATE INDEX IF NOT EXISTS idx_interactions_domain ON interactions(domain);
      CREATE INDEX IF NOT EXISTS idx_interactions_type ON interactions(interaction_type);
      CREATE INDEX IF NOT EXISTS idx_domain_verifications_lookup ON domain_verifications(domain, customer_id);
    `);

    // Insert a default customer for demo purposes if not exists
    await client.query(`
      INSERT INTO customers (id, name, api_key)
      VALUES (1, 'Demo Customer', 'demo_api_key_12345678')
      ON CONFLICT (id) DO NOTHING;
    `);

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Failed to initialize PostgreSQL schema', err);
    throw err;
  } finally {
    client.release();
  }

  return {
    async createInteraction(data) {
      const query = `
        INSERT INTO interactions
        (session_id, user_id, wai_tag, timestamp, page_url, domain,
        main_domain, subdomain, interaction_type, content,
        customer_id, feature_name, feature_category, context)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING id;
      `;

      const values = [
        data.sessionId,
        data.userId || null,
        data.waiTag || null,
        new Date().toISOString(),
        data.pageUrl || '',
        data.domain,
        data.mainDomain || null,
        data.subdomain || null,
        data.interactionType,
        data.content ? JSON.stringify(data.content) : null,
        data.customerId || null,
        data.featureName || null,
        data.featureCategory || null,
        data.context ? JSON.stringify(data.context) : '{}'
      ];

      const result = await pool.query(query, values);
      return { id: result.rows[0].id, ...data };
    },

    async getCustomer(id) {
      const result = await pool.query('SELECT * FROM customers WHERE id = $1', [id]);
      return result.rows[0] || null;
    },

    async getCustomerByApiKey(apiKey) {
      const result = await pool.query('SELECT * FROM customers WHERE api_key = $1', [apiKey]);
      return result.rows[0] || null;
    },

    parseDomain(domain) {
      const parts = domain.split('.');
      if (parts.length > 2) {
        return { mainDomain: parts.slice(1).join('.'), subdomain: parts[0] };
      }
      return { mainDomain: domain, subdomain: null };
    },

    async getDomainVerification(domain, customerId) {
      const result = await pool.query(
        'SELECT * FROM domain_verifications WHERE domain = $1 AND customer_id = $2',
        [domain, customerId]
      );
      return result.rows[0] || null;
    },

    async createDomainVerification(data) {
      const query = `
        INSERT INTO domain_verifications (domain, customer_id, token, status)
        VALUES ($1, $2, $3, $4)
        RETURNING id, created_at;
      `;
      const values = [data.domain, data.customerId, data.token, data.status || 'pending'];

      const result = await pool.query(query, values);
      return {
        id: result.rows[0].id,
        ...data,
        createdAt: result.rows[0].created_at
      };
    },

    async updateDomainVerification(domain, customerId, data) {
      const sets = [];
      const values = [];
      let paramIndex = 1;

      if (data.status) {
        sets.push(`status = ${paramIndex++}`);
        values.push(data.status);
      }
      if (data.status === 'verified') {
        sets.push(`verified_at = CURRENT_TIMESTAMP`);
      }

      if (sets.length === 0) return null;

      values.push(domain, customerId);
      const query = `
        UPDATE domain_verifications 
        SET ${sets.join(', ')} 
        WHERE domain = ${paramIndex++} AND customer_id = ${paramIndex}
        RETURNING *;
      `;

      const result = await pool.query(query, values);
      return result.rows[0] || null;
    },

    async isDomainVerified(domain, customerId) {
      const result = await pool.query(
        'SELECT status FROM domain_verifications WHERE domain = $1 AND customer_id = $2',
        [domain, customerId]
      );
      return result.rows[0]?.status === 'verified';
    },

    async getRecentEvents(limit = 50) {
      const result = await pool.query(
        'SELECT * FROM interactions ORDER BY id DESC LIMIT $1',
        [limit]
      );
      return result.rows;
    },

    async getStats() {
      const totalResult = await pool.query('SELECT COUNT(*) as count FROM interactions');
      const sessionsResult = await pool.query('SELECT COUNT(DISTINCT session_id) as count FROM interactions');
      const domainsResult = await pool.query('SELECT domain, COUNT(*) as count FROM interactions GROUP BY domain');
      const typesResult = await pool.query('SELECT interaction_type, COUNT(*) as count FROM interactions GROUP BY interaction_type');

      return {
        totalEvents: parseInt(totalResult.rows[0].count, 10),
        uniqueSessions: parseInt(sessionsResult.rows[0].count, 10),
        domains: Object.fromEntries(domainsResult.rows.map(d => [d.domain, parseInt(d.count, 10)])),
        eventTypes: Object.fromEntries(typesResult.rows.map(t => [t.interaction_type, parseInt(t.count, 10)]))
      };
    },

    async close() {
      await pool.end();
    }
  };
}

module.exports = { createPostgresStorage };
