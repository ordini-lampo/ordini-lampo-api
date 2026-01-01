-- ============================================================
-- MIGRATION: 001_gov_v2.1_enterprise.sql
-- Modulo: GOV (Control Tower)
-- Versione: 2.1 ENTERPRISE
-- Data: 31/12/2025
-- Stack: Railway PostgreSQL (EU West)
-- 
-- NOTA: Questo file è COMPLETO e RUNNABLE
--       Nessun placeholder, nessun TODO
--       Eseguire con: psql $DATABASE_URL < 001_gov_v2.1_enterprise.sql
-- ============================================================

BEGIN;

-- ============================================================
-- 0. ESTENSIONI
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- 1. SCHEMA
-- ============================================================

CREATE SCHEMA IF NOT EXISTS app;

-- ============================================================
-- 2. TABELLE
-- ============================================================

-- 2.1 tenants
CREATE TABLE IF NOT EXISTS app.tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug VARCHAR(100) NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active' 
    CHECK (status IN ('active', 'suspended', 'deleted')),
  email VARCHAR(255) NOT NULL,
  phone VARCHAR(50),
  stripe_customer_id VARCHAR(255),
  pricing_plan TEXT NOT NULL DEFAULT 'freedom'
    CHECK (pricing_plan IN ('freedom', 'lampo500', 'lampomax')),
  settings JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON app.tenants(slug) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_tenants_status ON app.tenants(status);
CREATE INDEX IF NOT EXISTS idx_tenants_email ON app.tenants(email);

COMMENT ON TABLE app.tenants IS 'Tenant = Ristorante/Organization';

-- 2.2 users
CREATE TABLE IF NOT EXISTS app.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT false,
  last_login_at TIMESTAMPTZ,
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  global_role TEXT NOT NULL DEFAULT 'user'
    CHECK (global_role IN ('user', 'superadmin')),
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  phone VARCHAR(50),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON app.users(email);
CREATE INDEX IF NOT EXISTS idx_users_locked ON app.users(locked_until) WHERE locked_until IS NOT NULL;

COMMENT ON TABLE app.users IS 'Utenti con auth nativa. password_hash = bcrypt cost 12';

-- 2.3 sessions
CREATE TABLE IF NOT EXISTS app.sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  ip_address INET,
  user_agent TEXT,
  current_tenant_id UUID REFERENCES app.tenants(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ,
  revoke_reason TEXT,
  CONSTRAINT chk_session_expiry CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON app.sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON app.sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON app.sessions(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON app.sessions(current_tenant_id);

COMMENT ON TABLE app.sessions IS 'Sessioni auth. Token mai salvato, solo SHA-256 hash';

-- 2.4 tenant_memberships
CREATE TABLE IF NOT EXISTS app.tenant_memberships (
  tenant_id UUID NOT NULL REFERENCES app.tenants(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'staff', 'customer')),
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_memberships_user ON app.tenant_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_tenant ON app.tenant_memberships(tenant_id);

COMMENT ON TABLE app.tenant_memberships IS 'Associazione user-tenant con ruolo';

-- 2.5 gov_config
CREATE TABLE IF NOT EXISTS app.gov_config (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key VARCHAR(100) NOT NULL UNIQUE,
  value TEXT NOT NULL,
  description TEXT,
  category VARCHAR(50) DEFAULT 'general',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by UUID REFERENCES app.users(id),
  CONSTRAINT chk_gov_config_key CHECK (key ~ '^[a-z][a-z0-9_]*$')
);

CREATE INDEX IF NOT EXISTS idx_gov_config_key ON app.gov_config(key);
CREATE INDEX IF NOT EXISTS idx_gov_config_category ON app.gov_config(category);

COMMENT ON TABLE app.gov_config IS 'Configurazioni critiche - kill-switch, maintenance, auth';

-- 2.6 feature_flags
CREATE TABLE IF NOT EXISTS app.feature_flags (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  flag_key VARCHAR(100) NOT NULL,
  tenant_id UUID REFERENCES app.tenants(id) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT false,
  percentage INTEGER DEFAULT 100 CHECK (percentage >= 0 AND percentage <= 100),
  config JSONB DEFAULT '{}',
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES app.users(id),
  updated_by UUID REFERENCES app.users(id),
  CONSTRAINT uq_feature_flag UNIQUE (flag_key, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_feature_flags_key ON app.feature_flags(flag_key);
CREATE INDEX IF NOT EXISTS idx_feature_flags_tenant ON app.feature_flags(tenant_id);
CREATE INDEX IF NOT EXISTS idx_feature_flags_enabled ON app.feature_flags(enabled);

COMMENT ON TABLE app.feature_flags IS 'Feature flags. tenant_id NULL = globale';

-- 2.7 system_settings
CREATE TABLE IF NOT EXISTS app.system_settings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  setting_key VARCHAR(100) NOT NULL,
  setting_value JSONB NOT NULL,
  tenant_id UUID REFERENCES app.tenants(id) ON DELETE CASCADE,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by UUID REFERENCES app.users(id),
  CONSTRAINT uq_system_setting UNIQUE (setting_key, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_system_settings_key ON app.system_settings(setting_key);
CREATE INDEX IF NOT EXISTS idx_system_settings_tenant ON app.system_settings(tenant_id);

COMMENT ON TABLE app.system_settings IS 'Impostazioni sistema. tenant_id NULL = globale';

-- 2.8 gov_audit_log
CREATE TABLE IF NOT EXISTS app.gov_audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  tenant_id UUID REFERENCES app.tenants(id),
  user_id UUID REFERENCES app.users(id),
  session_id UUID REFERENCES app.sessions(id),
  request_id TEXT,
  ip_address INET,
  user_agent TEXT,
  details JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gov_audit_tenant ON app.gov_audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_audit_user ON app.gov_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_gov_audit_action ON app.gov_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_gov_audit_created ON app.gov_audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_gov_audit_request ON app.gov_audit_log(request_id);

COMMENT ON TABLE app.gov_audit_log IS 'Audit trail GOV. APPEND-ONLY';


-- ============================================================
-- 3. FUNZIONI CONTEXT
-- ============================================================

CREATE OR REPLACE FUNCTION app.current_user_id()
RETURNS UUID LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_user_id', true), '')::UUID;
$$;

CREATE OR REPLACE FUNCTION app.current_tenant_id()
RETURNS UUID LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::UUID;
$$;

CREATE OR REPLACE FUNCTION app.current_role()
RETURNS TEXT LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_role', true), '');
$$;

CREATE OR REPLACE FUNCTION app.current_session_id()
RETURNS UUID LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_session_id', true), '')::UUID;
$$;

CREATE OR REPLACE FUNCTION app.current_request_id()
RETURNS TEXT LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.request_id', true), '');
$$;

CREATE OR REPLACE FUNCTION app.current_ip()
RETURNS INET LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_ip', true), '')::INET;
$$;

CREATE OR REPLACE FUNCTION app.current_user_agent()
RETURNS TEXT LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_user_agent', true), '');
$$;

CREATE OR REPLACE FUNCTION app.require_admin()
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
  r TEXT;
BEGIN
  r := app.current_role();
  IF r IS NULL OR r NOT IN ('owner', 'admin', 'superadmin') THEN
    RAISE EXCEPTION 'FORBIDDEN: role % cannot perform admin action', COALESCE(r, 'NULL');
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.gov_bucket(p_tenant_id UUID, p_key TEXT)
RETURNS INT LANGUAGE sql IMMUTABLE AS $$
  SELECT (('x' || substr(md5(p_tenant_id::text || ':' || p_key), 1, 8))::bit(32)::int % 100 + 100) % 100;
$$;

REVOKE ALL ON FUNCTION app.current_user_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.current_tenant_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.current_role() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.current_session_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.require_admin() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.gov_bucket(UUID, TEXT) FROM PUBLIC;


-- ============================================================
-- 4. FUNZIONE AUDIT (v2.1)
-- ============================================================

CREATE OR REPLACE FUNCTION app.gov_audit(
  p_action TEXT,
  p_target TEXT,
  p_tenant_id UUID DEFAULT NULL,
  p_details JSONB DEFAULT '{}'::jsonb
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
BEGIN
  INSERT INTO app.gov_audit_log (
    action, target, tenant_id, user_id, session_id, 
    request_id, ip_address, user_agent, details
  )
  VALUES (
    p_action, p_target, 
    COALESCE(p_tenant_id, app.current_tenant_id()), 
    app.current_user_id(), 
    app.current_session_id(), 
    app.current_request_id(), 
    app.current_ip(), 
    app.current_user_agent(),
    COALESCE(p_details, '{}'::jsonb)
  );
END;
$$;

REVOKE ALL ON FUNCTION app.gov_audit(TEXT, TEXT, UUID, JSONB) FROM PUBLIC;


-- ============================================================
-- 5. FUNZIONI AUTH
-- ============================================================

-- 5.1 create_session
CREATE OR REPLACE FUNCTION app.create_session(
  p_user_id UUID,
  p_token_hash VARCHAR(64),
  p_ip_address INET DEFAULT NULL,
  p_user_agent TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
DECLARE
  v_session_id UUID;
  v_expires_at TIMESTAMPTZ;
  v_duration_hours INT;
BEGIN
  SELECT COALESCE(
    (SELECT value::INT FROM app.gov_config WHERE key = 'session_duration_hours'), 
    24
  ) INTO v_duration_hours;
  
  v_expires_at := NOW() + (v_duration_hours || ' hours')::INTERVAL;
  
  INSERT INTO app.sessions (user_id, token_hash, ip_address, user_agent, expires_at)
  VALUES (p_user_id, p_token_hash, p_ip_address, p_user_agent, v_expires_at)
  RETURNING id INTO v_session_id;
  
  UPDATE app.users 
  SET last_login_at = NOW(), 
      failed_login_attempts = 0,
      locked_until = NULL
  WHERE id = p_user_id;
  
  RETURN jsonb_build_object(
    'session_id', v_session_id,
    'expires_at', v_expires_at
  );
END;
$$;

REVOKE ALL ON FUNCTION app.create_session(UUID, VARCHAR, INET, TEXT) FROM PUBLIC;

-- 5.2 validate_session (v2.1 con IP binding opzionale)
CREATE OR REPLACE FUNCTION app.validate_session(p_token_hash VARCHAR(64))
RETURNS TABLE (
  user_id UUID,
  user_email VARCHAR(255),
  global_role TEXT,
  tenant_id UUID,
  tenant_role TEXT,
  session_id UUID
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
DECLARE
  v_bind_ip BOOLEAN;
  v_req_ip INET;
BEGIN
  SELECT COALESCE(
    (SELECT value::boolean FROM app.gov_config WHERE key = 'session_bind_ip'), 
    false
  ) INTO v_bind_ip;
  
  v_req_ip := app.current_ip();
  
  RETURN QUERY
  SELECT
    u.id,
    u.email,
    u.global_role,
    s.current_tenant_id,
    tm.role,
    s.id
  FROM app.sessions s
  JOIN app.users u ON u.id = s.user_id
  LEFT JOIN app.tenant_memberships tm
    ON tm.user_id = u.id
   AND tm.tenant_id = s.current_tenant_id
   AND tm.is_active = true
  WHERE s.token_hash = p_token_hash
    AND s.expires_at > NOW()
    AND s.revoked_at IS NULL
    AND (u.locked_until IS NULL OR u.locked_until < NOW())
    AND (
      v_bind_ip = false
      OR s.ip_address IS NULL
      OR v_req_ip IS NULL
      OR s.ip_address = v_req_ip
    )
  LIMIT 1;

  IF FOUND THEN
    UPDATE app.sessions
    SET last_activity_at = NOW()
    WHERE token_hash = p_token_hash;
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION app.validate_session(VARCHAR) FROM PUBLIC;

-- 5.3 revoke_session
CREATE OR REPLACE FUNCTION app.revoke_session(
  p_token_hash VARCHAR(64),
  p_reason TEXT DEFAULT 'logout'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
BEGIN
  UPDATE app.sessions
  SET revoked_at = NOW(), revoke_reason = p_reason
  WHERE token_hash = p_token_hash
    AND revoked_at IS NULL;
  
  RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION app.revoke_session(VARCHAR, TEXT) FROM PUBLIC;

-- 5.4 record_failed_login
CREATE OR REPLACE FUNCTION app.record_failed_login(p_email VARCHAR(255))
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
DECLARE
  v_attempts INT;
  v_max_attempts INT;
  v_lockout_minutes INT;
  v_locked_until TIMESTAMPTZ;
BEGIN
  SELECT COALESCE(
    (SELECT value::INT FROM app.gov_config WHERE key = 'max_failed_logins'), 
    5
  ) INTO v_max_attempts;
  
  SELECT COALESCE(
    (SELECT value::INT FROM app.gov_config WHERE key = 'lockout_minutes'), 
    30
  ) INTO v_lockout_minutes;
  
  UPDATE app.users
  SET failed_login_attempts = failed_login_attempts + 1
  WHERE email = p_email
  RETURNING failed_login_attempts INTO v_attempts;
  
  IF NOT FOUND THEN
    RETURN jsonb_build_object('locked', false);
  END IF;
  
  IF v_attempts >= v_max_attempts THEN
    v_locked_until := NOW() + (v_lockout_minutes || ' minutes')::INTERVAL;
    
    UPDATE app.users
    SET locked_until = v_locked_until
    WHERE email = p_email;
    
    PERFORM app.gov_audit(
      'ACCOUNT_LOCKED', 
      'user:' || p_email,
      NULL,
      jsonb_build_object('attempts', v_attempts, 'locked_until', v_locked_until)
    );
    
    RETURN jsonb_build_object('locked', true, 'until', v_locked_until);
  END IF;
  
  RETURN jsonb_build_object('locked', false, 'attempts', v_attempts);
END;
$$;

REVOKE ALL ON FUNCTION app.record_failed_login(VARCHAR) FROM PUBLIC;

-- 5.5 switch_tenant
CREATE OR REPLACE FUNCTION app.switch_tenant(p_tenant_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
DECLARE
  v_user_id UUID := app.current_user_id();
  v_session_id UUID := app.current_session_id();
  v_role TEXT;
BEGIN
  SELECT role INTO v_role
  FROM app.tenant_memberships
  WHERE user_id = v_user_id 
    AND tenant_id = p_tenant_id
    AND is_active = true;
  
  IF NOT FOUND THEN
    RAISE EXCEPTION 'FORBIDDEN: no membership in tenant %', p_tenant_id;
  END IF;
  
  UPDATE app.sessions
  SET current_tenant_id = p_tenant_id
  WHERE id = v_session_id;
  
  PERFORM app.gov_audit(
    'TENANT_SWITCH',
    'session:' || v_session_id::text,
    p_tenant_id,
    jsonb_build_object('new_tenant', p_tenant_id, 'role', v_role)
  );
  
  RETURN jsonb_build_object(
    'ok', true,
    'tenant_id', p_tenant_id,
    'role', v_role
  );
END;
$$;

REVOKE ALL ON FUNCTION app.switch_tenant(UUID) FROM PUBLIC;

-- 5.6 gov_prune_old_sessions (v2.1)
CREATE OR REPLACE FUNCTION app.gov_prune_old_sessions(
  p_user_id UUID, 
  p_keep INT DEFAULT 10
)
RETURNS INT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
DECLARE
  v_pruned INT;
BEGIN
  WITH ranked AS (
    SELECT id,
           row_number() OVER (ORDER BY created_at DESC) AS rn
    FROM app.sessions
    WHERE user_id = p_user_id
      AND revoked_at IS NULL
      AND expires_at > NOW()
  ),
  to_prune AS (
    UPDATE app.sessions s
    SET revoked_at = NOW(),
        revoke_reason = 'AUTO_PRUNE'
    FROM ranked r
    WHERE s.id = r.id
      AND r.rn > p_keep
    RETURNING s.id
  )
  SELECT COUNT(*) INTO v_pruned FROM to_prune;
  
  IF v_pruned > 0 THEN
    PERFORM app.gov_audit(
      'SESSION_PRUNE', 
      'user:' || p_user_id::text,
      NULL,
      jsonb_build_object('pruned_count', v_pruned, 'keep', p_keep)
    );
  END IF;
  
  RETURN v_pruned;
END;
$$;

REVOKE ALL ON FUNCTION app.gov_prune_old_sessions(UUID, INT) FROM PUBLIC;


-- ============================================================
-- 6. FUNZIONI GOV
-- ============================================================

-- 6.1 gov_get_status
CREATE OR REPLACE FUNCTION app.gov_get_status()
RETURNS JSONB
LANGUAGE sql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
  SELECT jsonb_build_object(
    'kill_switch', (SELECT value = 'true' FROM app.gov_config WHERE key = 'kill_switch'),
    'maintenance', (SELECT value = 'true' FROM app.gov_config WHERE key = 'maintenance_mode'),
    'maintenance_message', (SELECT value FROM app.gov_config WHERE key = 'maintenance_message'),
    'timestamp', NOW()
  );
$$;

REVOKE ALL ON FUNCTION app.gov_get_status() FROM PUBLIC;

-- 6.2 gov_set_kill_switch
CREATE OR REPLACE FUNCTION app.gov_set_kill_switch(p_active BOOLEAN)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
DECLARE
  v_old TEXT;
BEGIN
  PERFORM app.require_admin();
  
  SELECT value INTO v_old FROM app.gov_config WHERE key = 'kill_switch';
  
  UPDATE app.gov_config
  SET 
    value = CASE WHEN p_active THEN 'true' ELSE 'false' END,
    updated_at = NOW(),
    updated_by = app.current_user_id()
  WHERE key = 'kill_switch';
  
  PERFORM app.gov_audit(
    'KILL_SWITCH_' || CASE WHEN p_active THEN 'ON' ELSE 'OFF' END, 
    'gov_config:kill_switch',
    NULL,
    jsonb_build_object('old', v_old, 'new', p_active)
  );
  
  RETURN jsonb_build_object(
    'ok', true, 
    'kill_switch', p_active,
    'timestamp', NOW()
  );
END;
$$;

REVOKE ALL ON FUNCTION app.gov_set_kill_switch(BOOLEAN) FROM PUBLIC;

-- 6.3 gov_set_maintenance
CREATE OR REPLACE FUNCTION app.gov_set_maintenance(p_active BOOLEAN)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
BEGIN
  PERFORM app.require_admin();
  
  UPDATE app.gov_config
  SET 
    value = CASE WHEN p_active THEN 'true' ELSE 'false' END,
    updated_at = NOW(),
    updated_by = app.current_user_id()
  WHERE key = 'maintenance_mode';
  
  PERFORM app.gov_audit(
    'MAINTENANCE_' || CASE WHEN p_active THEN 'ON' ELSE 'OFF' END,
    'gov_config:maintenance_mode',
    NULL,
    NULL
  );
  
  RETURN jsonb_build_object(
    'ok', true, 
    'maintenance', p_active,
    'timestamp', NOW()
  );
END;
$$;

REVOKE ALL ON FUNCTION app.gov_set_maintenance(BOOLEAN) FROM PUBLIC;

-- 6.4 gov_is_feature_enabled_safe
CREATE OR REPLACE FUNCTION app.gov_is_feature_enabled_safe(p_flag_key TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
DECLARE
  t UUID := app.current_tenant_id();
  v_enabled BOOLEAN;
  v_pct INT;
BEGIN
  IF t IS NOT NULL THEN
    SELECT enabled, percentage INTO v_enabled, v_pct
    FROM app.feature_flags
    WHERE flag_key = p_flag_key AND tenant_id = t;
    
    IF FOUND THEN
      IF COALESCE(v_pct, 100) < 100 THEN
        IF v_enabled = false THEN RETURN false; END IF;
        RETURN app.gov_bucket(t, p_flag_key) < v_pct;
      END IF;
      RETURN v_enabled;
    END IF;
  END IF;
  
  SELECT enabled, percentage INTO v_enabled, v_pct
  FROM app.feature_flags
  WHERE flag_key = p_flag_key AND tenant_id IS NULL;
  
  IF NOT FOUND THEN RETURN false; END IF;
  
  IF COALESCE(v_pct, 100) < 100 THEN
    IF v_enabled = false THEN RETURN false; END IF;
    IF t IS NULL THEN RETURN false; END IF;
    RETURN app.gov_bucket(t, p_flag_key) < v_pct;
  END IF;
  
  RETURN v_enabled;
END;
$$;

REVOKE ALL ON FUNCTION app.gov_is_feature_enabled_safe(TEXT) FROM PUBLIC;

-- 6.5 gov_get_setting_safe
CREATE OR REPLACE FUNCTION app.gov_get_setting_safe(p_setting_key TEXT)
RETURNS JSONB
LANGUAGE sql
SECURITY DEFINER
SET search_path = app, pg_temp
AS $$
  SELECT setting_value
  FROM app.system_settings
  WHERE setting_key = p_setting_key
    AND (tenant_id IS NULL OR tenant_id = app.current_tenant_id())
  ORDER BY tenant_id NULLS LAST
  LIMIT 1;
$$;

REVOKE ALL ON FUNCTION app.gov_get_setting_safe(TEXT) FROM PUBLIC;


-- ============================================================
-- 7. TRIGGERS
-- ============================================================

-- 7.1 Trigger updated_at
CREATE OR REPLACE FUNCTION app.trg_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

DO $$
DECLARE
  tbl TEXT;
  tables TEXT[] := ARRAY['users', 'tenants', 'tenant_memberships', 
                         'gov_config', 'feature_flags', 'system_settings'];
BEGIN
  FOREACH tbl IN ARRAY tables LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS trg_%s_set_updated_at ON app.%I', tbl, tbl);
    EXECUTE format(
      'CREATE TRIGGER trg_%s_set_updated_at BEFORE UPDATE ON app.%I 
       FOR EACH ROW EXECUTE FUNCTION app.trg_set_updated_at()',
      tbl, tbl
    );
  END LOOP;
END $$;

-- 7.2 Trigger protezione config critiche
CREATE OR REPLACE FUNCTION app.trg_protect_critical_config()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.key IN ('kill_switch', 'maintenance_mode', 'maintenance_message') THEN
      RAISE EXCEPTION 'GOV-001: Cannot delete critical config: %', OLD.key;
    END IF;
  END IF;
  
  IF TG_OP = 'UPDATE' THEN
    IF OLD.key IN ('kill_switch', 'maintenance_mode', 'maintenance_message') 
       AND OLD.key != NEW.key THEN
      RAISE EXCEPTION 'GOV-002: Cannot rename critical config: %', OLD.key;
    END IF;
  END IF;
  
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_gov_config_protect ON app.gov_config;
CREATE TRIGGER trg_gov_config_protect
  BEFORE UPDATE OR DELETE ON app.gov_config
  FOR EACH ROW EXECUTE FUNCTION app.trg_protect_critical_config();


-- ============================================================
-- 8. RLS POLICIES
-- ============================================================

ALTER TABLE app.gov_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.feature_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.system_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.gov_audit_log ENABLE ROW LEVEL SECURITY;

-- gov_config: tutti leggono
DROP POLICY IF EXISTS gov_config_select_all ON app.gov_config;
CREATE POLICY gov_config_select_all ON app.gov_config FOR SELECT USING (true);

-- sessions: solo proprie
DROP POLICY IF EXISTS sessions_select_own ON app.sessions;
CREATE POLICY sessions_select_own ON app.sessions FOR SELECT 
  USING (user_id = app.current_user_id());

-- users: se stesso o admin vede membri tenant
DROP POLICY IF EXISTS users_select ON app.users;
CREATE POLICY users_select ON app.users FOR SELECT USING (
  id = app.current_user_id()
  OR (
    app.current_role() IN ('owner', 'admin', 'superadmin')
    AND id IN (SELECT user_id FROM app.tenant_memberships WHERE tenant_id = app.current_tenant_id())
  )
  OR app.current_role() = 'superadmin'
);

-- tenants: membri vedono proprio tenant
DROP POLICY IF EXISTS tenants_select ON app.tenants;
CREATE POLICY tenants_select ON app.tenants FOR SELECT USING (
  id = app.current_tenant_id()
  OR id IN (SELECT tenant_id FROM app.tenant_memberships WHERE user_id = app.current_user_id())
  OR app.current_role() = 'superadmin'
);

-- tenant_memberships
DROP POLICY IF EXISTS memberships_select ON app.tenant_memberships;
CREATE POLICY memberships_select ON app.tenant_memberships FOR SELECT USING (
  tenant_id = app.current_tenant_id()
  OR user_id = app.current_user_id()
  OR app.current_role() = 'superadmin'
);

-- feature_flags: globali + proprio tenant
DROP POLICY IF EXISTS feature_flags_select ON app.feature_flags;
CREATE POLICY feature_flags_select ON app.feature_flags FOR SELECT USING (
  tenant_id IS NULL OR tenant_id = app.current_tenant_id()
);

-- system_settings: globali + proprio tenant
DROP POLICY IF EXISTS system_settings_select ON app.system_settings;
CREATE POLICY system_settings_select ON app.system_settings FOR SELECT USING (
  tenant_id IS NULL OR tenant_id = app.current_tenant_id()
);

-- gov_audit_log: solo admin
DROP POLICY IF EXISTS gov_audit_select_admin ON app.gov_audit_log;
CREATE POLICY gov_audit_select_admin ON app.gov_audit_log FOR SELECT USING (
  app.current_role() IN ('owner', 'admin', 'superadmin')
  AND (tenant_id IS NULL OR tenant_id = app.current_tenant_id() OR app.current_role() = 'superadmin')
);


-- ============================================================
-- 9. DATI INIZIALI
-- ============================================================

-- Config critiche
INSERT INTO app.gov_config (key, value, description, category) VALUES
  ('kill_switch', 'false', 'Blocca tutte le operazioni critiche', 'critical'),
  ('maintenance_mode', 'false', 'Modalità manutenzione', 'critical'),
  ('maintenance_message', 'Sistema in manutenzione. Riprova tra poco.', 'Messaggio manutenzione', 'critical'),
  ('session_duration_hours', '24', 'Durata sessione in ore', 'auth'),
  ('max_failed_logins', '5', 'Tentativi login prima del lockout', 'auth'),
  ('lockout_minutes', '30', 'Durata lockout in minuti', 'auth'),
  ('session_bind_ip', 'false', 'Binding sessione a IP', 'auth'),
  ('orders_enabled', 'true', 'Accettazione ordini abilitata', 'orders'),
  ('new_registrations', 'true', 'Nuove registrazioni ristoranti', 'onboarding')
ON CONFLICT (key) DO NOTHING;

-- Feature flags globali
INSERT INTO app.feature_flags (flag_key, tenant_id, enabled, description) VALUES
  ('referral_program', NULL, false, 'Programma referral'),
  ('advanced_analytics', NULL, false, 'Dashboard analytics avanzata'),
  ('multi_location', NULL, false, 'Supporto multi-sede'),
  ('api_v2', NULL, false, 'Nuova versione API')
ON CONFLICT (flag_key, tenant_id) DO NOTHING;

-- System settings globali
INSERT INTO app.system_settings (setting_key, setting_value, tenant_id, description) VALUES
  ('platform_fee_freedom', '{"type": "fixed", "value": 49.00, "currency": "EUR"}', NULL, 'Tariffa Freedom'),
  ('platform_fee_lampo500', '{"type": "fixed", "value": 99.00, "currency": "EUR", "included_orders": 500}', NULL, 'Tariffa Lampo500'),
  ('platform_fee_lampomax', '{"type": "fixed", "value": 199.00, "currency": "EUR", "included_orders": "unlimited"}', NULL, 'Tariffa LampoMax'),
  ('order_timeout_minutes', '{"value": 15}', NULL, 'Timeout accettazione ordine'),
  ('max_order_items', '{"value": 50}', NULL, 'Max articoli per ordine'),
  ('supported_languages', '{"languages": ["it", "en", "zh"]}', NULL, 'Lingue supportate'),
  ('business_hours_default', '{"open": "11:00", "close": "23:00", "timezone": "Europe/Rome"}', NULL, 'Orari default'),
  ('password_min_length', '{"value": 8}', NULL, 'Lunghezza minima password'),
  ('session_cookie_name', '{"value": "ol_session"}', NULL, 'Nome cookie sessione'),
  ('csrf_cookie_name', '{"value": "ol_csrf"}', NULL, 'Nome cookie CSRF')
ON CONFLICT (setting_key, tenant_id) DO NOTHING;


-- ============================================================
-- 10. VERIFICA FINALE
-- ============================================================

DO $$
DECLARE
  v_count INT;
BEGIN
  -- Verifica tabelle
  SELECT COUNT(*) INTO v_count FROM pg_tables WHERE schemaname = 'app';
  IF v_count < 8 THEN
    RAISE EXCEPTION 'MIGRATION FAILED: Expected 8+ tables, found %', v_count;
  END IF;
  
  -- Verifica funzioni
  SELECT COUNT(*) INTO v_count FROM pg_proc WHERE pronamespace = 'app'::regnamespace;
  IF v_count < 15 THEN
    RAISE EXCEPTION 'MIGRATION FAILED: Expected 15+ functions, found %', v_count;
  END IF;
  
  -- Verifica config critiche
  SELECT COUNT(*) INTO v_count FROM app.gov_config WHERE key IN ('kill_switch', 'maintenance_mode');
  IF v_count < 2 THEN
    RAISE EXCEPTION 'MIGRATION FAILED: Missing critical config';
  END IF;
  
  -- Verifica RLS
  SELECT COUNT(*) INTO v_count FROM pg_tables WHERE schemaname = 'app' AND rowsecurity = true;
  IF v_count < 8 THEN
    RAISE EXCEPTION 'MIGRATION FAILED: RLS not enabled on all tables';
  END IF;
  
  RAISE NOTICE '✅ MIGRATION 001_gov_v2.1_enterprise.sql COMPLETED SUCCESSFULLY';
  RAISE NOTICE '   Tables: 8, Functions: 15+, RLS: enabled, Config: seeded';
END $$;

COMMIT;

-- ============================================================
-- FINE MIGRATION
-- ============================================================
