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
const { rateLimiter } = require('../middleware/rate-limit');

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

router.post('/register', rateLimiter.auth, async (req, res) => {
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

router.post('/login', rateLimiter.auth, async (req, res) => {
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
