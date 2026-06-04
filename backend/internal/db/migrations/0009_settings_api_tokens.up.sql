-- 0009 admin settings + system M2M API tokens.
CREATE TABLE system_settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL
);
CREATE TRIGGER trg_system_settings_updated BEFORE UPDATE ON system_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Default security policy settings.
INSERT INTO system_settings (key, value) VALUES
  ('security.policy', '{"password_min_length":12,"require_mfa":true,"password_history":5}'::jsonb)
ON CONFLICT (key) DO NOTHING;

-- System API tokens for machine-to-machine access (distinct from OAuth clients).
CREATE TABLE api_tokens (
    id               uuid PRIMARY KEY,
    name             text NOT NULL,
    token_hash       text NOT NULL,            -- argon2id hash of the secret part
    prefix           text NOT NULL,            -- public lookup prefix
    scopes           text[] NOT NULL DEFAULT '{}',
    allowed_app_keys text[] NOT NULL DEFAULT '{}', -- per-app least privilege (must-fix #15)
    created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    expires_at       timestamptz,
    revoked_at       timestamptz,
    last_used_at     timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_api_tokens_prefix ON api_tokens (prefix);
