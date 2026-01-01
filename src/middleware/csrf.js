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
  // ✅ FIX W-3: Fail-closed in produzione se ALLOWED_ORIGINS vuoto
  if (ALLOWED_ORIGINS.length === 0) {
    // In dev permettiamo tutto, in prod blocchiamo
    return process.env.NODE_ENV !== 'production';
  }

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
// ✅ FIX W-1: Include secure/sameSite per cross-site
function clearCsrfCookie(res) {
  const secureEnv = process.env.NODE_ENV === 'production';
  const sameSite = process.env.SESSION_SAMESITE || 'lax';
  const secure = sameSite === 'none' ? true : secureEnv;

  res.clearCookie(CSRF_COOKIE, {
    path: '/',
    secure,
    sameSite,
  });
}

module.exports = { csrfProtect, setCsrfCookie, clearCsrfCookie };
