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
// GET /auth/csrf  (public)
// Bootstrap CSRF cookie + token for browser clients
// ============================================================
router.get('/csrf', (req, res) => {
  const csrfToken = setCsrfCookie(res);
  return res.json({ csrf_token: csrfToken });
});

// ============================================================
// POST /auth/forgot  (public)
// NOTE: SAFE placeholder that MUST NEVER 503.
// It returns a generic success response to avoid user enumeration.
// When email delivery/reset-token storage is implemented, replace the TODO block.
// ============================================================
router.post('/forgot', rateLimiter.auth, async (req, res) => {
  try {
    const BodySchema = z.object({
      email: z.string().email().transform((v) => v.trim().toLowerCase()),
    });

    const parsed = BodySchema.safeParse(req.body || {});
    if (!parsed.success) {
      // We still respond 200 to avoid leaking validation details + avoid upstream guards triggering SAFE_MODE.
      return res.json({ success: true });
    }

    const { email } = parsed.data;

    // TODO (Phase NTF/MSG): generate reset token + persist + send email.
    // For Bulldozer P0 we keep this endpoint non-destructive and always-available.
    logger.info({ email, requestId: req.requestId }, 'Auth forgot requested (placeholder)');

    return res.json({ success: true });
  } catch (error) {
    // HARD RULE: auth/forgot must never trip SAFE_MODE.
    logger.error({ err: error, requestId: req.requestId }, 'Auth forgot error (forced non-503)');
    return res.json({ success: true });
  }
});

// ============================================================
// POST /auth/reset  (public)
// Placeholder endpoint: validates shape and returns controlled errors.
// ============================================================
router.post('/reset', rateLimiter.auth, async (req, res) => {
  try {
    const BodySchema = z.object({
      token: z.string().min(10).max(512),
      password: z.string().min(8).max(200),
    });

    const parsed = BodySchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ error: 'INVALID_BODY' });
    }

    // TODO (Phase NTF/MSG): verify token + set new password_hash + invalidate token.
    return res.status(400).json({ error: 'INVALID_TOKEN' });
  } catch (error) {
    logger.error({ err: error, requestId: req.requestId }, 'Auth reset error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ============================================================
// CONFIG
// ============================================================

const BCRYPT_COST = Number(process.env.BCRYPT_COST || 12);

// ============================================================
// POST /auth/register (public)
// ============================================================
router.post('/register', rateLimiter.auth, async (req, res) => {
  try {
    const BodySchema = z.object({
      email: z.string().email().transform((v) => v.trim().toLowerCase()),
      password: z.string().min(8).max(200),
      first_name: z.string().min(1).max(100).optional(),
      last_name: z.string().min(1).max(100).optional(),
    });

    const parsed = BodySchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ error: 'INVALID_BODY' });
    }

    const { email, password, first_name, last_name } = parsed.data;

    // Check if exists
    const existing = await query('SELECT id FROM app.users WHERE lower(email) = lower($1)', [email]);
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
       RETURNING id, email, global_role, created_at`,
      [email, passwordHash, first_name || null, last_name || null]
    );

    const user = users[0];

    return res.status(201).json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        global_role: user.global_role,
        created_at: user.created_at,
      },
    });
  } catch (error) {
    logger.error({ err: error, requestId: req.requestId }, 'Register error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ============================================================
// POST /auth/login (public)
// ============================================================
// ============================================================
// GET /auth/login  (HTML minimal form)
// ============================================================
router.get('/login', (req, res) => {
  const returnTo = typeof req.query.returnTo === 'string' ? req.query.returnTo : '/admin';

  // HTML volutamente minimale: serve solo a fare POST /auth/login
  // e poi lasciare che il frontend prosegua con cookie-session.
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(`<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Ordini-Lampo — Login</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial;max-width:420px;margin:48px auto;padding:0 16px}
    label{display:block;margin:12px 0 6px}
    input{width:100%;padding:10px;border:1px solid #bbb;border-radius:8px}
    button{margin-top:16px;width:100%;padding:10px;border:0;border-radius:8px;cursor:pointer}
    .muted{opacity:.75;font-size:12px;margin-top:10px}
  </style>
</head>
<body>
  <h2>Login</h2>

  <form method="post" action="/auth/login">
    <input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}" />
    <label>Email</label>
    <input name="email" type="email" autocomplete="email" required />

    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password" required />

    <button type="submit">Entra</button>
    <div class="muted">Dopo il login verrai reindirizzato.</div>
  </form>

  <script>
    // mini-helper: se il browser invia form-url-encoded va bene.
  </script>
</body>
</html>`);
});

// escapeHtml super minimale (evita XSS su returnTo)
function escapeHtml(str) {
  return String(str)
    .replaceAll('&','&amp;')
    .replaceAll('<','&lt;')
    .replaceAll('>','&gt;')
    .replaceAll('"','&quot;')
    .replaceAll("'","&#039;");
}

router.post('/login', rateLimiter.auth, async (req, res) => {
  try {
    const body = req.body;
    const { email, password } = body;
    const emailNorm = String(email || "").trim().toLowerCase();

    // Guardrail P0: input minimo, mai 500 per payload incompleto
    if (!emailNorm || !password) {
      console.log("[LOGIN] early_400_reason INVALID_INPUT", {
        email_norm: emailNorm,
        has_password: Boolean(password),
      });
      return res.status(400).json({ error: "INVALID_INPUT" });
    }

    const ip = getIp(req);
    const ua = getUA(req);
    console.log("[LOGIN] start", {
      email_raw: email,
      email_norm: String(email || "").toLowerCase(),
      has_password: Boolean(password),
      ip,
      ua,
});



    // Load user
    const users = await query(
      `SELECT id, email, global_role, password_hash, failed_login_attempts, locked_until
       FROM app.users
       WHERE lower(email) = lower($1)
       LIMIT 1`,
      [email]
    );
    console.log("[LOGIN] user_lookup", {
      found: users.length > 0,
      count: users.length,
    });


    if (users.length === 0) {
      // Timing-safe: hash anyway to prevent timing attacks
      await bcrypt.hash(password, BCRYPT_COST);
      console.log("[LOGIN] early_401_reason", "USER_NOT_FOUND");
      return res.status(401).json({
        error: 'INVALID_CREDENTIALS',
        message: 'Email o password non validi',
      });
    }

    const user = users[0];
      console.log("[LOGIN] user_state", {
      user_id: user.id,
      failed_login_attempts: user.failed_login_attempts,
      locked_until: user.locked_until,
      global_role: user.global_role,
      has_password_hash: Boolean(user.password_hash),
      password_hash_prefix: String(user.password_hash || "").slice(0, 4),    });


    // Check lock
    if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
      return res.status(429).json({ error: 'ACCOUNT_LOCKED' });
    }

    if (!user || !user.password_hash) {
      console.log("[LOGIN] early_401_reason USER_NOT_FOUND_OR_NO_PASSWORD", {
        email_norm: emailNorm,
        has_password_hash: Boolean(user?.password_hash),
      });
      return res.status(401).json({ error: "INVALID_CREDENTIALS" });
    }

    const ok = await bcrypt.compare(password, user.password_hash || '');
    if (!ok) {
      // Increment failed attempts
      const attempts = (user.failed_login_attempts || 0) + 1;
      let lockedUntil = null;

      // Simple lock policy
      if (attempts >= 8) {
        lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 min
      }

      await query(
        `UPDATE app.users
         SET failed_login_attempts = $2,
             locked_until = $3
         WHERE id = $1`,
        [user.id, attempts, lockedUntil]
      );

      return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
    }

    // Reset failed attempts on success
    await query(
      `UPDATE app.users
       SET failed_login_attempts = 0,
           locked_until = NULL
       WHERE id = $1`,
      [user.id]
    );

    // Create session
    // session cookie auth: store in app.sessions
    const sessionId = crypto.randomUUID();
    const csrfToken = crypto.randomBytes(24).toString('hex');

// tenant role resolution (optional)
let tenantRole = null;
const tenant_id = body?.tenant_id || null;  // Fix P0: definire tenant_id ed evitare crash
if (tenant_id) {
  const memberships = await query(
    `SELECT role
     FROM app.tenant_memberships
     WHERE tenant_id = $1 AND user_id = $2
     LIMIT 1`,
    [tenant_id, user.id]
  );
  tenantRole = memberships[0]?.role || null;
}
    await queryWithContext(
      req,
      `INSERT INTO app.sessions
        (id, user_id, user_email, global_role, tenant_id, tenant_role, csrf_token, created_at, last_seen_at)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())`,
      [sessionId, user.id, user.email, user.global_role, tenant_id || null, tenantRole, csrfToken]
    );

    // Set session cookie (httpOnly)
    // NOTE: Cookie options should match cors/secure settings (handled elsewhere)
    res.cookie('ol_session', sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // Set CSRF cookie (readable by frontend)
    res.cookie('ol_csrf', csrfToken, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const rawReturnTo =
      (typeof req.body?.returnTo === 'string' && req.body.returnTo) ||
      (typeof req.query?.returnTo === 'string' && req.query.returnTo) ||
      null;

    // Hardening: allow only internal admin paths
    let returnTo = null;
    if (rawReturnTo && rawReturnTo.startsWith('/admin')) {
      returnTo = rawReturnTo;
    }

    // Se arriva returnTo valido, redirect sicuro
    if (returnTo) {
      return res.redirect(302, returnTo);
    }


    return res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        global_role: user.global_role,
      },
      tenant_id: tenant_id || null,
      tenant_role: tenantRole,
      csrf_token: csrfToken,
    });


  } catch (error) {
    logger.error({ err: error, requestId: req.requestId }, 'Login error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ============================================================
// POST /auth/logout  (auth required)
// ============================================================
router.post('/logout', async (req, res) => {
  try {
    const sessionId = req.cookies?.ol_session;
    if (sessionId) {
      await queryWithContext(req, 'DELETE FROM app.sessions WHERE id = $1', [sessionId]);
    }
    res.clearCookie('ol_session', { path: '/' });
    clearCsrfCookie(res);
    return res.json({ success: true });
  } catch (error) {
    logger.error({ err: error, requestId: req.requestId }, 'Logout error');
    return res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ============================================================
// GET /auth/me  (auth required)
// ============================================================
router.get('/me', async (req, res) => {
  try {
    // Expect authMiddleware to have set req.session
    const session = req.session;
    if (!session) {
      return res.status(401).json({ error: 'UNAUTHORIZED' });
    }

    // Load tenant (optional)
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

/**
 * Helpers minimalisti per logging (non-security critical).
 * Evitano crash in produzione se mancavano import/utility.
 */
function getIp(req) {
  // preferisci X-Forwarded-For (Railway/proxy), fallback su socket
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) return xff.split(',')[0].trim();
  return req.socket?.remoteAddress || null;
}

function getUA(req) {
  return req.headers['user-agent'] || null;
}
