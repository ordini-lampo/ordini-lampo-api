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
