// ============================================================
// src/middleware/gov-guard.js
// PLATINUM++: Blocca richieste runtime se kill_switch/maintenance ON
// Pattern: Cache TTL 8s + FAIL-CLOSED enterprise
// ============================================================

const { query } = require('../lib/db');
const { logger } = require('../lib/logger');

// Cache con TTL
let cache = null;
const DEFAULT_TTL_MS = 8000; // 8 secondi

// Allowlist: endpoint che bypassano GOV Guard
const ALLOWLIST = [
  /^\/api\/v1\/health$/,
  /^\/api\/v1\/auth\/login$/,
  /^\/api\/v1\/auth\/logout$/,
  /^\/api\/v1\/gov\/status$/,
];

function getUrl(req) {
  return (req.originalUrl || req.url || '').split('?')[0];
}

async function readGovMode() {
  const now = Date.now();
  const ttl = Number(process.env.GOV_MODE_CACHE_TTL_MS || DEFAULT_TTL_MS);

  if (cache && cache.expiresAt > now) {
    return cache.value;
  }

  const rows = await query(`
    SELECT
      (SELECT value #>> '{}' FROM app.gov_config WHERE key = 'kill_switch') AS kill_switch,
      (SELECT value #>> '{}' FROM app.gov_config WHERE key = 'maintenance_mode') AS maintenance_mode,
      (SELECT value #>> '{}' FROM app.gov_config WHERE key = 'maintenance_message') AS maintenance_message
  `);

  const value = {
    kill_switch: rows[0] && rows[0].kill_switch === 'true',
    maintenance_mode: rows[0] && rows[0].maintenance_mode === 'true',
    maintenance_message: String((rows[0] && rows[0].maintenance_message) || 'Sistema in manutenzione'),
  };

  cache = { value, expiresAt: now + ttl };
  return value;
}

// Invalidate cache (chiamare dopo toggle kill-switch/maintenance)
function invalidateGovCache() {
  cache = null;
}

async function govGuard(req, res, next) {
  const url = getUrl(req);

  // Bypass per endpoint critici
  if (ALLOWLIST.some((rx) => rx.test(url))) {
    return next();
  }

  let mode;
  try {
    mode = await readGovMode();
  } catch (err) {
    logger.error({ err }, 'GOV Guard: failed to read mode');

    // ✅ FAIL-CLOSED enterprise:
    // se non posso verificare lo stato, blocco tutto tranne allowlist
    return res.status(503).json({
      error: 'SAFE_MODE',
      message: 'Sistema in modalita di sicurezza (temporaneamente non disponibile).',
    });
  }

  if (mode.kill_switch) {
    logger.warn({ path: url, ip: req.ip }, 'GOV Guard: blocked by kill_switch');
    return res.status(503).json({
      error: 'KILL_SWITCH',
      message: 'Sistema temporaneamente sospeso. Riprova tra poco.',
    });
  }

  if (mode.maintenance_mode) {
    logger.info({ path: url }, 'GOV Guard: blocked by maintenance');
    return res.status(503).json({
      error: 'MAINTENANCE',
      message: mode.maintenance_message,
    });
  }

  return next();
}

module.exports = { govGuard, invalidateGovCache };
