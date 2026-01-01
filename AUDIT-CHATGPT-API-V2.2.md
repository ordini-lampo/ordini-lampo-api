# ============================================================
# AUDIT REQUEST: Ordini-Lampo API v2.2
# ============================================================
# Data: 31/12/2025
# Stack: Railway + Express + PostgreSQL + Session Auth Custom
# Score Target: 99+/100
# ============================================================

## CONTESTO

Questo è il codice COMPLETO dell'API backend per Ordini-Lampo.
Sostituisce la versione precedente che usava Clerk (JWT).

**Stack definitivo (3 attori):**
- Netlify (Frontend)
- Railway (API + PostgreSQL + Auth Session-Based)
- Stripe (Payments)

**Decisione architetturale:** Auth custom session-based invece di Clerk JWT.

---

## RICHIESTA AUDIT

Analizza TUTTO il codice seguente e verifica:

1. **Sicurezza**
   - Nessuna SQL injection
   - CSRF protection corretta
   - Session handling sicuro
   - Password hashing corretto (bcrypt cost 12)
   - Timing-safe comparisons dove necessario

2. **Pattern P0 (Critico)**
   - set_config() SEMPRE in transazione (is_local=true)
   - queryWithContext usa BEGIN/COMMIT
   - Nessun context leak tra richieste

3. **Fail-closed**
   - GOV Guard ritorna 503 se DB non raggiungibile
   - Auth middleware blocca se sessione invalida

4. **Anti-replay**
   - Switch-token ha JTI
   - JTI viene claimato in DB con UNIQUE constraint

5. **Cross-site cookies**
   - SameSite=none + Secure=true (corretto per cross-site)
   - clearCookie include tutti i parametri

6. **Errori comuni**
   - Nessun console.log (usa logger)
   - Error handling completo
   - Nessun leak di stack trace in production

---

## FILE 1: src/index.js (Entry Point)

```javascript
// ============================================================
// src/index.js
// Express Server - Ordini-Lampo API v2.2
// Stack: Railway + Session Auth + CSRF PLATINUM++
// ============================================================

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');

const { logger } = require('./lib/logger');
const { requestIdMiddleware } = require('./middleware/request-id');
const { authMiddleware } = require('./middleware/auth');
const { csrfProtect } = require('./middleware/csrf');
const { govGuard } = require('./middleware/gov-guard');

const authRoutes = require('./routes/auth');
const govRoutes = require('./routes/gov');

// ============================================================
// CONFIG
// ============================================================

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';

// CORS allowed origins
const ALLOWED_ORIGINS = new Set(
  (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
);

// ============================================================
// EXPRESS APP
// ============================================================

const app = express();

// Trust proxy (Railway)
app.set('trust proxy', 1);

// ============================================================
// GLOBAL MIDDLEWARE (ORDER MATTERS!)
// ============================================================

// 1. Request ID (first - needed for all logging)
app.use(requestIdMiddleware);

// 2. Security headers
app.use(helmet({
  contentSecurityPolicy: false, // API only
  crossOriginEmbedderPolicy: false,
}));

// 3. Cookie parser (before CORS and auth)
app.use(cookieParser());

// 4. CORS (cross-site cookie support)
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (curl, Postman) in dev only
    if (!origin) {
      return callback(null, NODE_ENV !== 'production');
    }
    if (ALLOWED_ORIGINS.has(origin)) {
      return callback(null, true);
    }
    logger.warn({ origin }, 'CORS blocked origin');
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Request-Id', 'X-OL-CSRF', 'Authorization'],
  exposedHeaders: ['X-Request-Id'],
  maxAge: 86400,
}));

// Handle preflight
app.options('*', cors());

// 5. Body parser
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ============================================================
// HEALTH CHECK (bypasses all guards)
// ============================================================

app.get('/api/v1/health', async (req, res) => {
  try {
    // Quick DB check
    const { query } = require('./lib/db');
    await query('SELECT 1');

    res.json({
      status: 'ok',
      module: 'GOV',
      version: '2.2',
      stack: 'railway',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error({ err: error }, 'Health check failed');
    res.status(503).json({
      status: 'error',
      message: 'Database connection failed',
    });
  }
});

// Railway health check alias
app.get('/health', (req, res) => {
  res.redirect('/api/v1/health');
});

// ============================================================
// AUTH ROUTES (before auth middleware - public)
// ============================================================

app.use('/api/v1/auth', authRoutes);

// ============================================================
// PROTECTED ROUTES
// ============================================================

// 6. GOV Guard (kill-switch / maintenance) - fail-closed
app.use(govGuard);

// 7. Auth middleware (session validation)
app.use(authMiddleware);

// 8. CSRF protection (on non-safe methods)
app.use(csrfProtect);

// ============================================================
// API ROUTES
// ============================================================

app.use('/api/v1/gov', govRoutes);

// Future routes:
// app.use('/api/v1/orders', orderRoutes);
// app.use('/api/v1/menu', menuRoutes);
// app.use('/api/v1/tenants', tenantRoutes);

// ============================================================
// 404 HANDLER
// ============================================================

app.use((req, res) => {
  res.status(404).json({
    error: 'NOT_FOUND',
    message: `Route ${req.method} ${req.path} not found`,
  });
});

// ============================================================
// ERROR HANDLER
// ============================================================

app.use((err, req, res, next) => {
  logger.error({
    err,
    requestId: req.requestId,
    method: req.method,
    path: req.path,
  }, 'Unhandled error');

  // Don't leak error details in production
  const message = NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message;

  res.status(500).json({
    error: 'INTERNAL_ERROR',
    message,
    requestId: req.requestId,
  });
});

// ============================================================
// START SERVER
// ============================================================

app.listen(PORT, '0.0.0.0', () => {
  logger.info({
    port: PORT,
    env: NODE_ENV,
    origins: Array.from(ALLOWED_ORIGINS),
  }, `🚀 Ordini-Lampo API v2.2 running on port ${PORT}`);
});

module.exports = app;
```

---

## FILE 2: src/lib/db.js (Database Layer - P0 CRITICO)

```javascript
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
```

---

## FILE 3: src/lib/logger.js

```javascript
// ============================================================
// src/lib/logger.js
// Pino logger (CommonJS)
// ============================================================

const pino = require('pino');

const NODE_ENV = process.env.NODE_ENV || 'development';

const logger = pino({
  level: process.env.LOG_LEVEL || (NODE_ENV === 'production' ? 'info' : 'debug'),
  transport: NODE_ENV !== 'production' ? {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'HH:MM:ss',
      ignore: 'pid,hostname',
    },
  } : undefined,
  base: {
    env: NODE_ENV,
  },
});

module.exports = { logger };
```

---

## FILE 4: src/lib/switch-token.js (Anti-replay)

```javascript
// ============================================================
// src/lib/switch-token.js
// Switch-tenant token HMAC-SHA256 (99+ anti-replay ready)
// Adds: aud + iat + jti + timingSafeEqual + payload verify
// ============================================================

const crypto = require('crypto');

const SWITCH_TENANT_SECRET = process.env.SWITCH_TENANT_SECRET;
const TOKEN_TTL_MS = Number(process.env.SWITCH_TOKEN_TTL_MS || 5 * 60 * 1000); // 5 min
const CLOCK_SKEW_MS = Number(process.env.SWITCH_TOKEN_SKEW_MS || 30000); // 30s
const AUD = 'tenant_switch_v1';

function mustSecret() {
  if (!SWITCH_TENANT_SECRET) throw new Error('MISSING_SWITCH_TENANT_SECRET');
  return SWITCH_TENANT_SECRET;
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function hmac(payloadB64) {
  return crypto.createHmac('sha256', mustSecret()).update(payloadB64).digest('base64url');
}

function safeEq(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function randomJti() {
  return crypto.randomBytes(16).toString('base64url');
}

// Genera token firmato
function generateSwitchToken(tenantId, sessionId) {
  mustSecret();

  const now = Date.now();
  const payload = {
    aud: AUD,
    tenant_id: tenantId,
    sid: sessionId,
    iat: now,
    exp: now + TOKEN_TTL_MS,
    jti: randomJti(),
  };

  const payloadB64 = b64urlJson(payload);
  const sig = hmac(payloadB64);
  return `${payloadB64}.${sig}`;
}

// Verifica e ritorna payload completo (serve per claim jti)
function verifySwitchTokenPayload(token, sessionId) {
  mustSecret();

  const parts = token.split('.');
  const payloadB64 = parts[0];
  const sig = parts[1];
  
  if (!payloadB64 || !sig) throw new Error('BAD_SWITCH_TOKEN_FORMAT');

  const expectedSig = hmac(payloadB64);
  if (!safeEq(expectedSig, sig)) throw new Error('BAD_SWITCH_TOKEN_SIGNATURE');

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    throw new Error('BAD_SWITCH_TOKEN_PAYLOAD');
  }

  if (
    !payload ||
    payload.aud !== AUD ||
    !payload.tenant_id ||
    !payload.sid ||
    !payload.iat ||
    !payload.exp ||
    !payload.jti
  ) {
    throw new Error('BAD_SWITCH_TOKEN_FIELDS');
  }

  if (payload.sid !== sessionId) throw new Error('BAD_SWITCH_TOKEN_SESSION_MISMATCH');

  const now = Date.now();
  if (payload.iat > now + CLOCK_SKEW_MS) throw new Error('SWITCH_TOKEN_IAT_IN_FUTURE');
  if (now > payload.exp) throw new Error('SWITCH_TOKEN_EXPIRED');
  if (payload.exp - payload.iat > TOKEN_TTL_MS + CLOCK_SKEW_MS) throw new Error('SWITCH_TOKEN_TTL_INVALID');

  return payload;
}

// Verifica e ritorna solo tenant_id (backward compatible)
function verifySwitchToken(token, sessionId) {
  return verifySwitchTokenPayload(token, sessionId).tenant_id;
}

module.exports = { 
  generateSwitchToken, 
  verifySwitchToken, 
  verifySwitchTokenPayload, 
  sha256Hex 
};
```

---

## FILE 5: src/middleware/request-id.js

```javascript
// ============================================================
// src/middleware/request-id.js
// Correlation ID middleware
// ============================================================

const crypto = require('crypto');

function requestIdMiddleware(req, res, next) {
  // Use existing header or generate new
  const existing = req.headers['x-request-id'];
  const requestId = (existing && typeof existing === 'string' && existing.length >= 16)
    ? existing
    : crypto.randomUUID();
  
  req.requestId = requestId;
  res.setHeader('X-Request-Id', requestId);
  
  next();
}

module.exports = { requestIdMiddleware };
```

---

## FILE 6: src/middleware/auth.js (Session Middleware)

```javascript
// ============================================================
// src/middleware/auth.js
// Session-based auth middleware (PLATINUM++)
// Fix P0: NO set_config(..., false) on pooled connections
// Uses queryWithContext to set LOCAL context safely
// ============================================================

const crypto = require('crypto');
const { queryWithContext } = require('../lib/db');
const { logger } = require('../lib/logger');

const SESSION_COOKIE = process.env.SESSION_COOKIE_NAME || 'ol_session';
const SESSION_SAMESITE = process.env.SESSION_SAMESITE || 'lax';

const PUBLIC_ROUTES = [
  /^\/api\/v1\/health$/,
  /^\/api\/v1\/auth\//,
];

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === 'production';
  const sameSite = SESSION_SAMESITE;
  const secureFinal = sameSite === 'none' ? true : secure;
  
  res.clearCookie(SESSION_COOKIE, {
    path: '/',
    secure: secureFinal,
    sameSite,
  });
}

function getIp(req) {
  // Richiede app.set('trust proxy', 1) in index.js su Railway
  return String(req.ip || '');
}

function getUA(req) {
  return String(req.headers['user-agent'] || '');
}

async function authMiddleware(req, res, next) {
  if (PUBLIC_ROUTES.some((rx) => rx.test(req.path))) return next();

  try {
    const token = req.cookies && req.cookies[SESSION_COOKIE];
    if (!token || typeof token !== 'string') {
      return res.status(401).json({ error: 'UNAUTHORIZED' });
    }

    // Sanity guard (anti header/cookie abuse)
    if (token.length < 20 || token.length > 256) {
      clearSessionCookie(res);
      return res.status(401).json({ error: 'UNAUTHORIZED' });
    }

    const tokenHash = sha256Hex(token);
    const ip = getIp(req);
    const ua = getUA(req);

    // P0 FIX:
    // queryWithContext apre transazione e fa set_config(..., true) LOCAL
    // => validate_session vede SEMPRE current_ip nella stessa connessione/tx
    const sessions = await queryWithContext(
      'SELECT * FROM app.validate_session($1)',
      [tokenHash],
      {
        // non conosciamo userId/tenantId prima della validate_session: ok vuoti
        userId: '',
        tenantId: '',
        role: '',
        sessionId: '',
        requestId: req.requestId, // deve essere settato dal middleware request-id
        ip,
        userAgent: ua,
      }
    );

    if (sessions.length === 0) {
      clearSessionCookie(res);
      return res.status(401).json({ error: 'UNAUTHORIZED' });
    }

    req.session = sessions[0];

    logger.debug(
      {
        userId: req.session.user_id,
        tenantId: req.session.tenant_id,
        role: req.session.tenant_role || req.session.global_role,
      },
      'Session validated'
    );

    return next();
  } catch (error) {
    logger.error({ err: error }, 'Auth middleware error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
}

// Require authenticated user (base guard)
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user_id) {
    return res.status(401).json({ error: 'UNAUTHORIZED' });
  }
  return next();
}

// Require admin role
function requireAdmin(req, res, next) {
  const role = req.session && (req.session.tenant_role || req.session.global_role);
  if (!role || !['owner', 'admin', 'superadmin'].includes(role)) {
    return res.status(403).json({ error: 'FORBIDDEN' });
  }
  return next();
}

// Require owner role
function requireOwner(req, res, next) {
  const role = req.session && (req.session.tenant_role || req.session.global_role);
  if (!role || !['owner', 'superadmin'].includes(role)) {
    return res.status(403).json({ error: 'FORBIDDEN' });
  }
  return next();
}

module.exports = { authMiddleware, requireAuth, requireAdmin, requireOwner };
```

---

## FILE 7: src/middleware/csrf.js (PLATINUM++)

```javascript
// ============================================================
// src/middleware/csrf.js
// PLATINUM++: Double-submit + Origin/Referer allowlist + secure none + constant-time
// ============================================================

const crypto = require('crypto');

const CSRF_COOKIE = process.env.CSRF_COOKIE_NAME || 'ol_csrf';
const CSRF_HEADER = process.env.CSRF_HEADER_NAME || 'x-ol-csrf';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// Se hai frontend su piu' domini: "https://ordini-lampo.it,https://admin.ordini-lampo.it"
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

function constantTimeEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function isOriginAllowed(req) {
  if (ALLOWED_ORIGINS.length === 0) return true; // se non configuri, non blocchiamo

  const origin = req.header('origin');
  if (origin) return ALLOWED_ORIGINS.includes(origin);

  // fallback: some browsers omit Origin for same-site POST; use Referer
  const referer = req.header('referer');
  if (!referer) return false;
  try {
    const url = new URL(referer);
    return ALLOWED_ORIGINS.includes(url.origin);
  } catch {
    return false;
  }
}

function cookieOpts() {
  const secureEnv = process.env.NODE_ENV === 'production';
  const sameSite = process.env.SESSION_SAMESITE || 'lax';

  // RFC / browser behavior: SameSite=None requires Secure
  const secure = sameSite === 'none' ? true : secureEnv;

  return {
    httpOnly: false, // Client must read it
    secure,
    sameSite,
    maxAge: 24 * 60 * 60 * 1000,
    path: '/',
  };
}

// Middleware: verifica CSRF su metodi non-safe
function csrfProtect(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();

  // P0 hardening: Origin/Referer allowlist (soprattutto con SameSite=None)
  if (!isOriginAllowed(req)) {
    return res.status(403).json({
      error: 'CSRF_ORIGIN',
      message: 'Origin/Referer non consentito',
    });
  }

  const cookieToken = req.cookies && req.cookies[CSRF_COOKIE];
  const headerToken = req.header(CSRF_HEADER);

  if (!cookieToken || !headerToken || !constantTimeEqual(String(cookieToken), String(headerToken))) {
    return res.status(403).json({
      error: 'CSRF',
      message: 'CSRF token mancante o non valido',
    });
  }

  return next();
}

// Helper: genera e setta CSRF cookie (chiamare al login)
function setCsrfCookie(res) {
  const token = crypto.randomBytes(32).toString('base64url');
  res.cookie(CSRF_COOKIE, token, cookieOpts());
  return token;
}

// Helper: pulisci CSRF cookie (chiamare al logout)
function clearCsrfCookie(res) {
  res.clearCookie(CSRF_COOKIE, { path: '/' });
}

module.exports = { csrfProtect, setCsrfCookie, clearCsrfCookie };
```

---

## FILE 8: src/middleware/gov-guard.js (Fail-closed)

```javascript
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
      (SELECT value FROM app.gov_config WHERE key = 'kill_switch') AS kill_switch,
      (SELECT value FROM app.gov_config WHERE key = 'maintenance_mode') AS maintenance_mode,
      (SELECT value FROM app.gov_config WHERE key = 'maintenance_message') AS maintenance_message
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
```

---

## FILE 9: src/routes/auth.js (Login/Logout/Register)

```javascript
// ============================================================
// src/routes/auth.js
// Auth routes: login, logout, register, me
// Stack: Session-based auth (NO Clerk, NO JWT)
// ============================================================

const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { z } = require('zod');
const { query, queryWithContext } = require('../lib/db');
const { setCsrfCookie, clearCsrfCookie } = require('../middleware/csrf');
const { logger } = require('../lib/logger');

const router = express.Router();

// ============================================================
// CONFIG
// ============================================================

const SESSION_COOKIE = process.env.SESSION_COOKIE_NAME || 'ol_session';
const SESSION_SAMESITE = process.env.SESSION_SAMESITE || 'lax';
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 24 * 60 * 60 * 1000); // 24h
const BCRYPT_COST = Number(process.env.BCRYPT_COST || 12);
const MAX_LOGIN_ATTEMPTS = Number(process.env.MAX_LOGIN_ATTEMPTS || 5);
const LOCKOUT_DURATION_MS = Number(process.env.LOCKOUT_DURATION_MS || 15 * 60 * 1000); // 15 min
const MAX_SESSIONS_PER_USER = Number(process.env.MAX_SESSIONS_PER_USER || 10);

// ============================================================
// SCHEMAS
// ============================================================

const LoginSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(128),
});

const RegisterSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(128),
  first_name: z.string().max(100).optional(),
  last_name: z.string().max(100).optional(),
});

// ============================================================
// HELPERS
// ============================================================

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function getIp(req) {
  return String(req.ip || '');
}

function getUA(req) {
  return String(req.headers['user-agent'] || '').slice(0, 500);
}

function cookieOpts(maxAge) {
  const secureEnv = process.env.NODE_ENV === 'production';
  const sameSite = SESSION_SAMESITE;
  // SameSite=none richiede Secure=true
  const secure = sameSite === 'none' ? true : secureEnv;

  return {
    httpOnly: true,
    secure,
    sameSite,
    maxAge,
    path: '/',
  };
}

function clearSessionCookie(res) {
  const secureEnv = process.env.NODE_ENV === 'production';
  const sameSite = SESSION_SAMESITE;
  const secure = sameSite === 'none' ? true : secureEnv;

  res.clearCookie(SESSION_COOKIE, {
    path: '/',
    secure,
    sameSite,
  });
}

// ============================================================
// POST /auth/register
// ============================================================

router.post('/register', async (req, res) => {
  try {
    const body = RegisterSchema.parse(req.body);
    const { email, password, first_name, last_name } = body;

    // Check existing user
    const existing = await query(
      'SELECT id FROM app.users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (existing.length > 0) {
      return res.status(409).json({
        error: 'EMAIL_EXISTS',
        message: 'Email gia registrata',
      });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

    // Create user
    const users = await query(
      `INSERT INTO app.users (email, password_hash, first_name, last_name)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email`,
      [email.toLowerCase(), passwordHash, first_name || null, last_name || null]
    );

    const user = users[0];

    logger.info({
      action: 'USER_REGISTERED',
      userId: user.id,
      email: user.email,
      requestId: req.requestId,
    }, 'User registered');

    return res.status(201).json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
      },
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        details: error.errors,
      });
    }

    logger.error({ err: error, requestId: req.requestId }, 'Register error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ============================================================
// POST /auth/login
// ============================================================

router.post('/login', async (req, res) => {
  try {
    const body = LoginSchema.parse(req.body);
    const { email, password } = body;
    const ip = getIp(req);
    const ua = getUA(req);

    // Find user
    const users = await query(
      `SELECT id, email, password_hash, global_role, 
              failed_login_attempts, locked_until
       FROM app.users 
       WHERE email = $1`,
      [email.toLowerCase()]
    );

    if (users.length === 0) {
      // Timing-safe: hash anyway to prevent timing attacks
      await bcrypt.hash(password, BCRYPT_COST);
      return res.status(401).json({
        error: 'INVALID_CREDENTIALS',
        message: 'Email o password non validi',
      });
    }

    const user = users[0];

    // Check lockout
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      logger.warn({
        action: 'LOGIN_LOCKED',
        userId: user.id,
        ip,
        requestId: req.requestId,
      }, 'Login attempt on locked account');

      return res.status(429).json({
        error: 'ACCOUNT_LOCKED',
        message: 'Account temporaneamente bloccato. Riprova tra qualche minuto.',
      });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      // Increment failed attempts
      const newAttempts = user.failed_login_attempts + 1;
      const shouldLock = newAttempts >= MAX_LOGIN_ATTEMPTS;

      await query(
        `UPDATE app.users 
         SET failed_login_attempts = $1,
             locked_until = $2
         WHERE id = $3`,
        [
          newAttempts,
          shouldLock ? new Date(Date.now() + LOCKOUT_DURATION_MS).toISOString() : null,
          user.id,
        ]
      );

      logger.warn({
        action: 'LOGIN_FAILED',
        userId: user.id,
        attempts: newAttempts,
        locked: shouldLock,
        ip,
        requestId: req.requestId,
      }, 'Invalid password');

      return res.status(401).json({
        error: 'INVALID_CREDENTIALS',
        message: 'Email o password non validi',
      });
    }

    // Reset failed attempts on successful login
    await query(
      `UPDATE app.users 
       SET failed_login_attempts = 0, 
           locked_until = NULL,
           last_login_at = NOW()
       WHERE id = $1`,
      [user.id]
    );

    // Generate session token
    const token = generateToken();
    const tokenHash = sha256Hex(token);
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

    // Create session
    const sessions = await query(
      `INSERT INTO app.sessions (user_id, token_hash, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3::inet, $4, $5)
       RETURNING id, current_tenant_id`,
      [user.id, tokenHash, ip || null, ua, expiresAt.toISOString()]
    );

    const session = sessions[0];

    // Prune old sessions (keep max N)
    await query(
      'SELECT app.gov_prune_old_sessions($1, $2)',
      [user.id, MAX_SESSIONS_PER_USER]
    );

    // Set cookies
    res.cookie(SESSION_COOKIE, token, cookieOpts(SESSION_TTL_MS));
    const csrfToken = setCsrfCookie(res);

    logger.info({
      action: 'LOGIN_SUCCESS',
      userId: user.id,
      sessionId: session.id,
      ip,
      requestId: req.requestId,
    }, 'User logged in');

    // Get tenant info if any
    let tenant = null;
    if (session.current_tenant_id) {
      const tenants = await query(
        'SELECT id, name, slug FROM app.tenants WHERE id = $1',
        [session.current_tenant_id]
      );
      tenant = tenants[0] || null;
    }

    return res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        global_role: user.global_role,
      },
      tenant,
      csrf_token: csrfToken,
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        details: error.errors,
      });
    }

    logger.error({ err: error, requestId: req.requestId }, 'Login error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ============================================================
// POST /auth/logout
// ============================================================

router.post('/logout', async (req, res) => {
  try {
    const token = req.cookies && req.cookies[SESSION_COOKIE];

    if (token && typeof token === 'string') {
      const tokenHash = sha256Hex(token);

      // Revoke session
      await query(
        `UPDATE app.sessions 
         SET revoked_at = NOW(), revoke_reason = 'LOGOUT'
         WHERE token_hash = $1`,
        [tokenHash]
      );

      logger.info({
        action: 'LOGOUT',
        requestId: req.requestId,
      }, 'User logged out');
    }

    // Clear cookies
    clearSessionCookie(res);
    clearCsrfCookie(res);

    return res.json({ success: true });

  } catch (error) {
    logger.error({ err: error, requestId: req.requestId }, 'Logout error');
    // Clear cookies anyway
    clearSessionCookie(res);
    clearCsrfCookie(res);
    return res.json({ success: true });
  }
});

// ============================================================
// GET /auth/me
// ============================================================

router.get('/me', async (req, res) => {
  try {
    const token = req.cookies && req.cookies[SESSION_COOKIE];

    if (!token || typeof token !== 'string') {
      return res.status(401).json({ error: 'UNAUTHORIZED' });
    }

    const tokenHash = sha256Hex(token);
    const ip = getIp(req);
    const ua = getUA(req);

    // Validate session using queryWithContext
    const sessions = await queryWithContext(
      'SELECT * FROM app.validate_session($1)',
      [tokenHash],
      {
        requestId: req.requestId,
        ip,
        userAgent: ua,
      }
    );

    if (sessions.length === 0) {
      clearSessionCookie(res);
      return res.status(401).json({ error: 'UNAUTHORIZED' });
    }

    const session = sessions[0];

    // Get tenant info if any
    let tenant = null;
    if (session.tenant_id) {
      const tenants = await query(
        'SELECT id, name, slug FROM app.tenants WHERE id = $1',
        [session.tenant_id]
      );
      tenant = tenants[0] || null;
    }

    return res.json({
      user: {
        id: session.user_id,
        email: session.user_email,
        global_role: session.global_role,
      },
      tenant,
      tenant_role: session.tenant_role,
    });

  } catch (error) {
    logger.error({ err: error, requestId: req.requestId }, 'Get me error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

module.exports = router;
```

---

## FILE 10: src/routes/gov.js (GOV Control Tower)

```javascript
// ============================================================
// src/routes/gov.js
// GOV Routes - Control Tower (99+ PLATINUM++)
// Anti-replay reale su switch-tenant
// ============================================================

const express = require('express');
const { z } = require('zod');
const { queryWithContext, queryMultipleWithContext } = require('../lib/db');
const { requireAuth, requireAdmin, requireOwner } = require('../middleware/auth');
const { rateLimiter } = require('../middleware/rate-limit');
const { logger } = require('../lib/logger');
const { invalidateGovCache } = require('../middleware/gov-guard');
const { verifySwitchTokenPayload, generateSwitchToken, sha256Hex } = require('../lib/switch-token');

const router = express.Router();

// Helper: costruisce context dalla request (SAFE: sempre stringa)
function getContext(req) {
  return {
    userId: req.session && req.session.user_id,
    tenantId: (req.session && req.session.tenant_id) || undefined,
    role: req.session && (req.session.tenant_role || req.session.global_role),
    sessionId: req.session && req.session.session_id,
    requestId: req.requestId,
    ip: String(req.ip || ''),
    userAgent: String(req.headers['user-agent'] || '')
  };
}

// ============================================================
// GET /gov/status - Stato sistema
// ============================================================

router.get('/status', rateLimiter.govRead, async (req, res) => {
  try {
    const result = await queryWithContext(
      'SELECT app.gov_get_status() as status',
      [],
      getContext(req)
    );
    return res.json(result[0].status);
  } catch (error) {
    logger.error({ err: error, requestId: req.requestId }, 'GET /gov/status error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ============================================================
// POST /gov/kill-switch - Toggle (owner only)
// ============================================================

const KillSwitchSchema = z.object({ active: z.boolean() });

router.post('/kill-switch', requireOwner, rateLimiter.govWrite, async (req, res) => {
  try {
    const { active } = KillSwitchSchema.parse(req.body);

    const result = await queryWithContext(
      'SELECT app.gov_set_kill_switch($1) as result',
      [active],
      getContext(req)
    );

    // Invalida cache GOV Guard
    invalidateGovCache();

    logger.warn({
      action: active ? 'KILL_SWITCH_ON' : 'KILL_SWITCH_OFF',
      actor: req.session && req.session.user_id,
      requestId: req.requestId
    }, 'Kill-switch toggled');

    return res.json(result[0].result);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', details: error.errors });
    }
    logger.error({ err: error, requestId: req.requestId }, 'POST /gov/kill-switch error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ============================================================
// POST /gov/maintenance - Toggle (admin)
// ============================================================

const MaintenanceSchema = z.object({ active: z.boolean() });

router.post('/maintenance', requireAdmin, rateLimiter.govWrite, async (req, res) => {
  try {
    const { active } = MaintenanceSchema.parse(req.body);

    const result = await queryWithContext(
      'SELECT app.gov_set_maintenance($1) as result',
      [active],
      getContext(req)
    );

    // Invalida cache GOV Guard
    invalidateGovCache();

    logger.info({
      action: active ? 'MAINTENANCE_ON' : 'MAINTENANCE_OFF',
      actor: req.session && req.session.user_id,
      requestId: req.requestId
    }, 'Maintenance toggled');

    return res.json(result[0].result);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', details: error.errors });
    }
    logger.error({ err: error, requestId: req.requestId }, 'POST /gov/maintenance error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ============================================================
// GET /gov/feature/:key - Check feature flag
// ============================================================

router.get('/feature/:key', rateLimiter.govRead, async (req, res) => {
  try {
    const result = await queryWithContext(
      'SELECT app.gov_is_feature_enabled_safe($1) as enabled',
      [req.params.key],
      getContext(req)
    );
    return res.json({ flag: req.params.key, enabled: result[0].enabled });
  } catch (error) {
    logger.error({ err: error, requestId: req.requestId }, 'GET /gov/feature error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ============================================================
// GET /gov/setting/:key - Get system setting
// ============================================================

router.get('/setting/:key', rateLimiter.govRead, async (req, res) => {
  try {
    const result = await queryWithContext(
      'SELECT app.gov_get_setting_safe($1) as value',
      [req.params.key],
      getContext(req)
    );
    return res.json({ setting: req.params.key, value: result[0].value });
  } catch (error) {
    logger.error({ err: error, requestId: req.requestId }, 'GET /gov/setting error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ============================================================
// GET /gov/tenants - Lista tenant con switch_token
// ============================================================

router.get('/tenants', requireAuth, async (req, res) => {
  try {
    const result = await queryWithContext(
      `SELECT t.id as tenant_id, t.name, tm.role
       FROM app.tenant_memberships tm
       JOIN app.tenants t ON t.id = tm.tenant_id
       WHERE tm.user_id = app.current_user_id()
         AND tm.is_active = true
         AND t.status = 'active'`,
      [],
      getContext(req)
    );

    // Genera switch_token per ogni tenant
    const tenants = result.map(t => ({
      ...t,
      switch_token: generateSwitchToken(t.tenant_id, req.session.session_id)
    }));

    return res.json({ tenants });
  } catch (error) {
    logger.error({ err: error, requestId: req.requestId }, 'GET /gov/tenants error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ============================================================
// POST /gov/tenant/switch - Switch con token firmato + anti-replay
// ============================================================

const SwitchTenantSchema = z.object({ switch_token: z.string().min(20) });

router.post('/tenant/switch', requireAuth, async (req, res) => {
  try {
    const { switch_token } = SwitchTenantSchema.parse(req.body);

    // Verifica token e ottieni payload completo
    const payload = verifySwitchTokenPayload(switch_token, req.session.session_id);
    const tenantId = payload.tenant_id;

    // ✅ Anti-replay reale: claim jti_hash in DB (UNIQUE)
    const jtiHash = sha256Hex(payload.jti);
    const expIso = new Date(payload.exp).toISOString();

    // Claim + switch in STESSA transazione (atomico)
    const results = await queryMultipleWithContext(
      [
        {
          sql: 'SELECT app.gov_claim_switch_token($1, $2::timestamptz, $3::uuid) AS ok',
          params: [jtiHash, expIso, req.session.session_id],
        },
        {
          sql: 'SELECT app.switch_tenant($1) AS result',
          params: [tenantId],
        },
      ],
      getContext(req)
    );

    const claimRows = results[0];
    const switchRows = results[1];

    // Check anti-replay
    if (!claimRows || !claimRows[0] || !claimRows[0].ok) {
      logger.warn({
        action: 'SWITCH_TOKEN_REPLAY',
        actor: req.session && req.session.user_id,
        jtiHash,
        requestId: req.requestId
      }, 'Switch token replay detected');

      return res.status(400).json({
        error: 'SWITCH_TOKEN_REPLAY',
        message: 'Token gia usato o non valido (replay). Richiedi un nuovo token.',
      });
    }

    logger.info({
      action: 'TENANT_SWITCH',
      actor: req.session && req.session.user_id,
      newTenant: tenantId,
      requestId: req.requestId
    }, 'Tenant switched');

    return res.json(switchRows[0].result);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', details: error.errors });
    }
    if (error.message && error.message.includes('FORBIDDEN')) {
      return res.status(403).json({ error: 'FORBIDDEN', message: 'No membership in tenant' });
    }
    if (String(error.message || '').includes('SWITCH_TOKEN') || String(error.message || '').includes('BAD_SWITCH')) {
      return res.status(400).json({ error: 'BAD_SWITCH_TOKEN', message: error.message });
    }
    logger.error({ err: error, requestId: req.requestId }, 'POST /gov/tenant/switch error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

module.exports = router;
```

---

## FILE 11: package.json

```json
{
  "name": "ordini-lampo-api",
  "version": "2.2.0",
  "description": "Ordini-Lampo API - Railway Express + Session Auth",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js",
    "dev": "node --watch src/index.js"
  },
  "engines": {
    "node": ">=18.0.0"
  },
  "dependencies": {
    "bcrypt": "^5.1.1",
    "cookie-parser": "^1.4.6",
    "cors": "^2.8.5",
    "express": "^4.18.2",
    "helmet": "^7.1.0",
    "pg": "^8.11.3",
    "pino": "^8.17.2",
    "pino-pretty": "^10.3.1",
    "zod": "^3.22.4"
  },
  "keywords": ["ordini-lampo", "railway", "express", "api"],
  "license": "UNLICENSED",
  "private": true
}
```

---

## CHECKLIST AUDIT

Per ogni punto, rispondi: ✅ OK | ⚠️ WARNING | ❌ CRITICO

| # | Check | Status | Note |
|---|-------|--------|------|
| 1 | SQL injection prevention (parametrized queries) | ? | |
| 2 | CSRF double-submit + Origin check | ? | |
| 3 | Session token SHA-256 hashed (mai in chiaro) | ? | |
| 4 | Password bcrypt cost 12 | ? | |
| 5 | timingSafeEqual su CSRF e switch-token | ? | |
| 6 | queryWithContext usa BEGIN/COMMIT | ? | |
| 7 | GOV Guard fail-closed (503 su errore DB) | ? | |
| 8 | Switch-token ha JTI + claim atomico | ? | |
| 9 | SameSite=none + Secure=true per cross-site | ? | |
| 10 | clearCookie include path, secure, sameSite | ? | |
| 11 | Nessun console.log (solo logger) | ? | |
| 12 | Error handling completo (no stack leak in prod) | ? | |
| 13 | Lockout brute-force su login | ? | |
| 14 | Session pruning (max N per user) | ? | |
| 15 | Nessun riferimento a Clerk/JWT | ? | |

---

## OUTPUT RICHIESTO

1. Tabella checklist compilata
2. Lista errori critici (se presenti)
3. Lista warning (se presenti)
4. Suggerimenti miglioramento
5. Verdetto finale: DEPLOY READY / NEEDS FIX
