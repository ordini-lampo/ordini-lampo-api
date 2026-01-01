// ============================================================
// src/middleware/rate-limit.js
// ✅ FIX W-2: Rate limiting reale con express-rate-limit
// ============================================================

const rateLimit = require('express-rate-limit');

function key(req) {
  return String(req.ip || '');
}

const rateLimiter = {
  global: rateLimit({
    windowMs: 60 * 1000, // 1 minuto
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: key,
    message: { error: 'RATE_LIMIT', message: 'Troppe richieste. Riprova tra poco.' },
  }),

  auth: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minuti
    limit: 30,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: key,
    message: { error: 'RATE_LIMIT', message: 'Troppi tentativi. Riprova tra 15 minuti.' },
  }),

  govRead: rateLimit({
    windowMs: 60 * 1000,
    limit: 120,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: key,
    message: { error: 'RATE_LIMIT', message: 'Troppe richieste. Riprova tra poco.' },
  }),

  govWrite: rateLimit({
    windowMs: 60 * 1000,
    limit: 30,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: key,
    message: { error: 'RATE_LIMIT', message: 'Troppe richieste. Riprova tra poco.' },
  }),
};

module.exports = { rateLimiter };
