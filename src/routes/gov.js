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

router.get('/tenants', requireAuth, rateLimiter.govRead, async (req, res) => {
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

router.post('/tenant/switch', requireAuth, rateLimiter.govWrite, async (req, res) => {
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
