// ============================================================
// src/lib/db.js
// FIX P0: set_config is_local=true funziona SOLO in transaction
// Pattern: BEGIN -> SET LOCAL -> query -> COMMIT (rollback on error)
// ============================================================

const { Pool } = require('pg');
const { logger } = require('./logger');

// Pool configurazione
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: Number(process.env.PG_POOL_MAX || 20),
  idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT_MS || 30000),
  connectionTimeoutMillis: Number(process.env.PG_CONN_TIMEOUT_MS || 5000),
});

pool.on('error', (err) => {
  logger.error({ err }, 'Unexpected PG pool error');
});

// ============================================================
// Query semplice (senza context) - per auth, health
// ============================================================
async function query(sql, params = []) {
  const result = await pool.query(sql, params);
  return result.rows;
}

// ============================================================
// Helper: esegui con client dedicato
// ============================================================
async function withClient(fn) {
  const client = await pool.connect();
  try {
    return await fn(client);
  } finally {
    client.release();
  }
}

// ============================================================
// Normalizza context (evita null/undefined)
// ============================================================
function normalizeContext(ctx) {
  return {
    userId: ctx.userId || '',
    tenantId: ctx.tenantId || '',
    role: ctx.role || '',
    sessionId: ctx.sessionId || '',
    requestId: ctx.requestId || '',
    ip: ctx.ip || '',
    userAgent: ctx.userAgent || '',
  };
}

// ============================================================
// FIX P0: Query CON context IN TRANSAZIONE
// ============================================================
async function queryWithContext(sql, params = [], context) {
  const ctx = normalizeContext(context);

  // requestId OBBLIGATORIO per audit/correlation
  if (!ctx.requestId) {
    throw new Error('GOV_CTX_MISSING_REQUEST_ID');
  }

  return withClient(async (client) => {
    // 1. BEGIN transazione
    await client.query('BEGIN');

    try {
      // 2. SET LOCAL (is_local=true) -> vale per tutta la transazione
      await client.query(
        `SELECT
          set_config('app.current_user_id', $1, true),
          set_config('app.current_tenant_id', $2, true),
          set_config('app.current_role', $3, true),
          set_config('app.current_session_id', $4, true),
          set_config('app.request_id', $5, true),
          set_config('app.current_ip', $6, true),
          set_config('app.current_user_agent', $7, true)`,
        [ctx.userId, ctx.tenantId, ctx.role, ctx.sessionId, ctx.requestId, ctx.ip, ctx.userAgent]
      );

      // 3. Esegui query applicativa
      const result = await client.query(sql, params);

      // 4. COMMIT
      await client.query('COMMIT');
      
      return result.rows;
    } catch (err) {
      // 5. ROLLBACK su errore
      try {
        await client.query('ROLLBACK');
      } catch (rbErr) {
        logger.error({ rbErr }, 'ROLLBACK failed');
      }
      throw err;
    }
  });
}

// ============================================================
// Query multiple in stessa transazione
// ============================================================
async function queryMultipleWithContext(queries, context) {
  const ctx = normalizeContext(context);

  if (!ctx.requestId) {
    throw new Error('GOV_CTX_MISSING_REQUEST_ID');
  }

  // Fail-fast se queries vuoto
  if (queries.length === 0) return [];

  return withClient(async (client) => {
    await client.query('BEGIN');

    try {
      await client.query(
        `SELECT
          set_config('app.current_user_id', $1, true),
          set_config('app.current_tenant_id', $2, true),
          set_config('app.current_role', $3, true),
          set_config('app.current_session_id', $4, true),
          set_config('app.request_id', $5, true),
          set_config('app.current_ip', $6, true),
          set_config('app.current_user_agent', $7, true)`,
        [ctx.userId, ctx.tenantId, ctx.role, ctx.sessionId, ctx.requestId, ctx.ip, ctx.userAgent]
      );

      const results = [];
      for (const q of queries) {
        const result = await client.query(q.sql, q.params);
        results.push(result.rows);
      }

      await client.query('COMMIT');
      return results;
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (rbErr) {
        logger.error({ rbErr }, 'ROLLBACK failed');
      }
      throw err;
    }
  });
}

module.exports = { query, queryWithContext, queryMultipleWithContext, pool };
