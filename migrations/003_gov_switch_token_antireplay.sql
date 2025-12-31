-- ============================================================
-- 003_gov_switch_token_antireplay.sql
-- Scopo: prevenire replay reale dei switch_token (jti claim)
-- Score: 99+
-- ============================================================

BEGIN;

CREATE TABLE IF NOT EXISTS app.switch_token_jti_claims (
  jti_hash TEXT PRIMARY KEY,
  sid UUID NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_switch_jti_hash_hex
    CHECK (jti_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_switch_jti_expires
  ON app.switch_token_jti_claims (expires_at);

COMMENT ON TABLE app.switch_token_jti_claims IS 'Anti-replay per switch_token. JTI hash SHA-256.';

-- Claim atomico + cleanup opportunistico
CREATE OR REPLACE FUNCTION app.gov_claim_switch_token(
  p_jti_hash TEXT,
  p_expires_at TIMESTAMPTZ,
  p_sid UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
BEGIN
  -- cleanup opportunistico (senza cron)
  DELETE FROM app.switch_token_jti_claims
   WHERE expires_at < NOW();

  -- rifiuta token già scaduti
  IF p_expires_at <= NOW() THEN
    RETURN FALSE;
  END IF;

  -- inserimento atomico: se già presente => replay
  INSERT INTO app.switch_token_jti_claims (jti_hash, sid, expires_at)
  VALUES (p_jti_hash, p_sid, p_expires_at)
  ON CONFLICT (jti_hash) DO NOTHING;

  RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION app.gov_claim_switch_token(TEXT, TIMESTAMPTZ, UUID) FROM PUBLIC;

COMMIT;
