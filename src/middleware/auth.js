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
  /^\/api\/v1\/auth\/csrf$/,
  /^\/api\/v1\/auth\/login$/,
  /^\/api\/v1\/auth\/forgot$/,
  /^\/api\/v1\/auth\/reset$/,
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

  // ============================================================
  // AUTH BYPASS - FASE DEV (rimuovere prima del pilot)
  // Permette accesso Admin senza login mentre non ci sono clienti
  // ============================================================
  if (process.env.AUTH_BYPASS === 'true') {
    req.session = {
      user_id: 'dev-superadmin-001',
      user_email: 'paolo@ordini-lampo.it',
      global_role: 'superadmin',
      tenant_id: null,
      tenant_role: 'owner',
      session_id: 'dev-bypass-session'
    };
    logger.info({ bypass: true }, 'AUTH_BYPASS attivo - sessione dev iniettata');
    return next();
  }
  // ============================================================
  // FINE AUTH BYPASS
  // ============================================================

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
