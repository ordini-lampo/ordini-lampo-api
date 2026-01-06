// ============================================================
// src/middleware/gov-guard.js
// DEFINITIVA BLINDATA v1.2 (Business-first + Arch Integrity)
// + getGovStatus() for debug/monitoring (safe, no secrets)
// + NEVER_BLOCK: /api/v1/restaurants (lista + dettaglio)
//
// Pattern: NEVER_BLOCK sacra + BLACKLIST (kill/maint) + FAIL-OPEN + LKG + Circuit + Alert throttled
//
// Filosofia Ordini-Lampo:
// - Il business NON deve fermarsi per micro-glitch DB.
// - Blocca SOLO quando sei CERTO (lettura DB OK) che kill/maintenance sono ON.
// - Ordini/Menu/Webhook/Auth/Health: SEMPRE PASSA (NEVER_BLOCK).
// ============================================================

const { query } = require('../lib/db');
const { logger } = require('../lib/logger');

// ============================
// CONFIG
// ============================

const DEFAULT_TTL_MS = 8000; // cache lettura GOV
const TTL_MS = Number(process.env.GOV_MODE_CACHE_TTL_MS || DEFAULT_TTL_MS);

/**
 * GOV_FAIL_MODE:
 * - "open"  (default): in errore DB lascia passare (degraded) usando LKG/fallback.
 * - "closed": in errore DB blocca (SAFE_MODE) — disponibile, ma sconsigliato per Ordini-Lampo.
 */
const GOV_FAIL_MODE = String(process.env.GOV_FAIL_MODE || 'open').toLowerCase(); // open|closed

// Circuit breaker (anti-storm DB)
const CIRCUIT_FAIL_THRESHOLD = 3; // dopo 3 errori consecutivi
const CIRCUIT_COOLDOWN_MS = 15000; // cooldown prima di riprovare DB

// Alert throttling (anti-spam)
const ALERT_THROTTLE_MS = 60000; // max 1 alert/min

// ============================
// ROUTE UTILITIES
// ============================

function getUrl(req) {
  return String(req.originalUrl || req.url || '').split('?')[0];
}

function matchesAny(url, list) {
  for (const re of list) {
    if (re.test(url)) return true;
  }
  return false;
}

function parseBoolFromText(raw, fallback = false) {
  if (raw === null || raw === undefined) return fallback;
  const s = String(raw).trim().toLowerCase();
  if (['true', '1', 'on', 'yes', 'y'].includes(s)) return true;
  if (['false', '0', 'off', 'no', 'n'].includes(s)) return false;
  return fallback;
}

// ============================
// NEVER_BLOCK (SACRA): passa SEMPRE, anche con kill/maintenance e anche in errore DB
// Nota: alcune route non esistono ancora — è voluto (future-proof).
// ============================

const NEVER_BLOCK = [
  // Health
  /^\/health\/?$/,
  /^\/api\/v1\/health\/?$/,

  // Auth base
  /^\/api\/v1\/auth\/login\/?$/,
  /^\/api\/v1\/auth\/logout\/?$/,
  /^\/api\/v1\/auth\/me\/?$/,
  /^\/api\/v1\/auth\/csrf\/?$/,
  /^\/api\/v1\/auth\/forgot\/?$/,
  /^\/api\/v1\/auth\/reset\/?$/,
  /^\/api\/v1\/auth\/refresh\/?$/,

  // GOV status (monitoring)
  /^\/api\/v1\/gov\/status\/?$/,

  // Webhooks (pagamenti/notifiche) - quando esisteranno
  /^\/api\/v1\/webhooks?\//,
  /^\/api\/v1\/stripe\/webhook/,
  /^\/api\/v1\/wati\/webhook/,

  // Ordini (quando esisteranno)
  /^\/api\/v1\/orders?\//,
  /^\/api\/v1\/checkout\//,

  // Menu pubblico (quando esisterà)
  /^\/api\/v1\/menus?\//,
  /^\/api\/v1\/restaurants\/[^\/]+\/menu/,

  // Ristoranti (lista + dettaglio) — sempre visibile
  /^\/api\/v1\/restaurants\/?$/,
  /^\/api\/v1\/restaurants\/[^\/]+\/?$/,
];

// ============================
// BLACKLIST: blocca SOLO queste superfici quando kill_switch/maintenance sono ON (confermati da DB)
// Minimalista e sicura: admin/control plane + operazioni distruttive
// ============================

const BLOCKLIST_WHEN_KILL = [
  // GOV/control
  /^\/api\/v1\/gov\//, // (tranne status già in NEVER_BLOCK)

  // System/settings
  /^\/api\/v1\/system\//,
  /^\/api\/v1\/settings\//,

  // Tenant management
  /^\/api\/v1\/tenants?\//,
  /^\/api\/v1\/tenant-memberships?\//,

  // User/role/permission management
  /^\/api\/v1\/users\//,
  /^\/api\/v1\/roles?\//,
  /^\/api\/v1\/permissions?\//,

  // Admin panels
  /^\/api\/v1\/admin\//,
  /^\/api\/v1\/superadmin\//,

  // Billing management (NON webhook)
  /^\/api\/v1\/billing\//,

  // Bulk/import/export
  /^\/api\/v1\/import\//,
  /^\/api\/v1\/export\//,
  /^\/api\/v1\/bulk\//,
];

// In manutenzione, blocchiamo anche più ampio (ma sempre NEVER_BLOCK passa)
const BLOCKLIST_WHEN_MAINT = [
  // in maint tendi a bloccare tutto ciò che non è sacro/health/auth/webhook/menu/orders
  /^\/api\/v1\//,
];

// ============================
// STATE: cache + LKG + circuit + metrics
// ============================

let cache = null; // { expiresAt, value }
let lastKnownGood = null; // { value, at }

let consecutiveFails = 0;
let circuitOpenUntil = 0;

let lastAlertAt = 0;

const metrics = {
  requests_total: 0,
  never_block_hits: 0,
  db_reads: 0,
  db_failures: 0,
  circuit_opens: 0,
  blocked_kill: 0,
  blocked_maint: 0,
};

function invalidateGovCache() {
  cache = null;
}

function nowMs() {
  return Date.now();
}

function shouldAlert() {
  const t = nowMs();
  if (t - lastAlertAt < ALERT_THROTTLE_MS) return false;
  lastAlertAt = t;
  return true;
}

/**
 * readGovMode() returns:
 * {
 *   kill_switch: boolean,
 *   maintenance_mode: boolean,
 *   maintenance_message: string,
 *   source: 'db' | 'cache' | 'lkg' | 'fallback' | 'circuit',
 * }
 */
async function readGovMode() {
  const t = nowMs();

  // Cache TTL
  if (cache && cache.expiresAt > t) {
    return { ...cache.value, source: 'cache' };
  }

  // Circuit breaker: se aperto, non martellare DB
  if (circuitOpenUntil > t) {
    if (lastKnownGood) return { ...lastKnownGood.value, source: 'circuit' };
    return {
      kill_switch: false,
      maintenance_mode: false,
      maintenance_message: 'DEGRADED (circuit open)',
      source: 'circuit',
    };
  }

  try {
    metrics.db_reads++;

    // IMPORTANT: app.gov_config.value è TEXT → niente operatori JSON (#>>, ->, ecc.)
    const rows = await query(
      `SELECT key, value FROM app.gov_config
       WHERE key IN ('kill_switch', 'maintenance_mode', 'maintenance_message')`
    );

    const map = Object.create(null);
    for (const r of rows || []) {
      map[String(r.key)] = r.value;
    }

    const value = {
      kill_switch: parseBoolFromText(map.kill_switch, false),
      maintenance_mode: parseBoolFromText(map.maintenance_mode, false),
      maintenance_message: String(map.maintenance_message || 'Sistema in manutenzione'),
      source: 'db',
    };

    // Reset fail counters
    consecutiveFails = 0;
    circuitOpenUntil = 0;

    // Update cache + LKG
    cache = { expiresAt: t + TTL_MS, value };
    lastKnownGood = { value, at: t };

    return value;
  } catch (err) {
    metrics.db_failures++;
    consecutiveFails++;

    logger.error({ err, consecutiveFails }, 'GOV Guard: DB read failed');

    // Open circuit after threshold
    if (consecutiveFails >= CIRCUIT_FAIL_THRESHOLD) {
      circuitOpenUntil = t + CIRCUIT_COOLDOWN_MS;
      metrics.circuit_opens++;
      logger.warn({ circuitOpenUntil }, 'GOV Guard: circuit opened');
    }

    // Alert throttled
    if (shouldAlert()) {
      logger.warn(
        { err: String(err && err.message ? err.message : err), mode: GOV_FAIL_MODE },
        'GOV Guard: degraded mode active (DB read fail)'
      );
    }

    // FAIL MODE
    if (GOV_FAIL_MODE === 'closed') {
      // Fail-closed: blocca (SAFE_MODE) — NON consigliato per Ordini-Lampo
      return {
        kill_switch: true,
        maintenance_mode: false,
        maintenance_message: 'SAFE_MODE attivo (errore lettura config)',
        source: 'fallback',
      };
    }

    // Default: FAIL-OPEN con LKG
    if (lastKnownGood) {
      return { ...lastKnownGood.value, source: 'lkg' };
    }

    // Nessuna LKG disponibile: fallback open
    return {
      kill_switch: false,
      maintenance_mode: false,
      maintenance_message: 'DEGRADED (no LKG yet)',
      source: 'fallback',
    };
  }
}

// ============================
// MIDDLEWARE
// ============================

async function govGuard(req, res, next) {
  const url = getUrl(req);
  metrics.requests_total++;

  // REGOLA 1: NEVER_BLOCK passa SEMPRE
  if (matchesAny(url, NEVER_BLOCK)) {
    metrics.never_block_hits++;
    return next();
  }

  // REGOLA 2: leggi GOV mode
  const mode = await readGovMode();

  // REGOLA 3: Maintenance — applica SOLO se confermata da DB
  if (mode.source === 'db' && mode.maintenance_mode) {
    // blocca quasi tutto, tranne NEVER_BLOCK
    if (matchesAny(url, BLOCKLIST_WHEN_MAINT)) {
      metrics.blocked_maint++;
      return res.status(503).json({
        error: 'MAINTENANCE',
        message: mode.maintenance_message,
      });
    }
    return next();
  }

  // REGOLA 4: Kill switch — applica SOLO se confermato da DB
  if (mode.source === 'db' && mode.kill_switch) {
    if (matchesAny(url, BLOCKLIST_WHEN_KILL)) {
      metrics.blocked_kill++;
      return res.status(503).json({
        error: 'SAFE_MODE',
        message: 'Servizio temporaneamente non disponibile',
      });
    }
    // NON in blocklist → passa (bulldozer)
    return next();
  }

  // REGOLA 5: Default = PASSA
  return next();
}

// ============================
// STATUS (per debug/monitoring)
// Safe-by-default: no secrets, no env dumps, no error objects.
// ============================

function getGovStatus() {
  const t = nowMs();

  const sanitizeValue = (v) => {
    if (!v) return null;
    return {
      kill_switch: Boolean(v.kill_switch),
      maintenance_mode: Boolean(v.maintenance_mode),
      maintenance_message: String(v.maintenance_message || ''),
      source: v.source ? String(v.source) : undefined,
    };
  };

  return {
    version: 'DEFINITIVA_BLINDATA_v1.2',
    mode: 'BLACKLIST_FAIL_OPEN_DB_CONFIRMED',
    gov_fail_mode: GOV_FAIL_MODE,

    cache: cache
      ? {
          expiresAt: cache.expiresAt,
          expiresInMs: Math.max(0, cache.expiresAt - t),
          value: sanitizeValue(cache.value),
        }
      : null,

    lkg: lastKnownGood
      ? {
          at: lastKnownGood.at,
          ageMs: Math.max(0, t - lastKnownGood.at),
          value: sanitizeValue(lastKnownGood.value),
        }
      : null,

    circuit: {
      openUntil: circuitOpenUntil,
      isOpen: circuitOpenUntil > t,
      consecutiveFails,
      threshold: CIRCUIT_FAIL_THRESHOLD,
      cooldownMs: CIRCUIT_COOLDOWN_MS,
    },

    metrics: { ...metrics },

    timing: {
      ttlMs: TTL_MS,
      alertThrottleMs: ALERT_THROTTLE_MS,
    },
  };
}

module.exports = { govGuard, invalidateGovCache, getGovStatus };
