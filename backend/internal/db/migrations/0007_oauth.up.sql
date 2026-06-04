-- 0007 OAuth2/OIDC. Durable tables = clients/scopes/mapping/consent/refresh
-- chains. Ephemeral fosite state (codes, PKCE, access/refresh signatures) lives
-- in Redis with TTL.

CREATE TABLE oauth_clients (
    id                       uuid PRIMARY KEY,
    client_id                text NOT NULL UNIQUE,
    client_name              text NOT NULL,
    secret_hash              text,             -- argon2id; NULL for public clients
    client_secret_enc        bytea,            -- one-time reveal, set NULL after first reveal
    client_secret_nonce      bytea,
    client_secret_dek_version integer REFERENCES crypto_keys(version),
    secret_prev_hash         text,             -- rotation grace window
    secret_prev_expires_at   timestamptz,
    app_id                   uuid REFERENCES applications(id) ON DELETE SET NULL,
    public                   boolean NOT NULL DEFAULT false,
    token_endpoint_auth_method text NOT NULL DEFAULT 'client_secret_basic',
    redirect_uris            text[] NOT NULL DEFAULT '{}',
    post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
    grant_types              text[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
    response_types           text[] NOT NULL DEFAULT '{code}',
    allowed_scopes           text[] NOT NULL DEFAULT '{openid,profile,email}',
    allowed_app_keys         text[] NOT NULL DEFAULT '{}', -- permissions API scoping
    audience                 text[] NOT NULL DEFAULT '{}',
    pkce_required            boolean NOT NULL DEFAULT true,
    skip_consent             boolean NOT NULL DEFAULT false,
    access_token_ttl_s       integer,
    refresh_token_ttl_s      integer,
    id_token_ttl_s           integer,
    active                   boolean NOT NULL DEFAULT true,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_oauth_clients_app ON oauth_clients (app_id);
CREATE INDEX idx_oauth_clients_active ON oauth_clients (active);
CREATE TRIGGER trg_oauth_clients_updated BEFORE UPDATE ON oauth_clients
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE oauth_scopes (
    name             text PRIMARY KEY,
    display_name     text NOT NULL,
    description      text NOT NULL DEFAULT '',
    is_oidc_standard boolean NOT NULL DEFAULT false
);

CREATE TABLE oauth_scope_permission_map (
    scope_name      text NOT NULL REFERENCES oauth_scopes(name) ON DELETE CASCADE,
    claim_key       text NOT NULL,
    mapping_version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (scope_name, claim_key)
);

CREATE TABLE oauth_consent_grants (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id       text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    granted_scopes  text[] NOT NULL DEFAULT '{}',
    mapping_version bigint NOT NULL DEFAULT 1,  -- re-prompt when scope mapping changes
    expires_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, client_id)
);
CREATE INDEX idx_oauth_consent_user ON oauth_consent_grants (user_id);

-- Refresh-token family chains for rotation + reuse detection (must-fix #1).
CREATE TABLE oauth_refresh_chains (
    jti        text PRIMARY KEY,
    family_id  uuid NOT NULL,
    parent_jti text,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  text NOT NULL,
    issued_at  timestamptz NOT NULL DEFAULT now(),
    used_at    timestamptz,
    revoked    boolean NOT NULL DEFAULT false
);
CREATE INDEX idx_refresh_family ON oauth_refresh_chains (family_id);
CREATE INDEX idx_refresh_user ON oauth_refresh_chains (user_id);

-- Standard OIDC scopes seeded.
INSERT INTO oauth_scopes (name, display_name, description, is_oidc_standard) VALUES
  ('openid',  'OpenID',  '标识此为 OIDC 请求，下发 sub。',    true),
  ('profile', '基本资料', '下发用户名、显示名等基本资料。',     true),
  ('email',   '邮箱',    '下发用户邮箱。',                    true),
  ('offline_access', '离线访问', '下发 refresh_token 以便长期访问。', true),
  ('tc.permissions', 'TransCircle 权限', '下发该应用下用户的角色与权限声明。', false)
ON CONFLICT (name) DO NOTHING;

INSERT INTO oauth_scope_permission_map (scope_name, claim_key, mapping_version) VALUES
  ('tc.permissions', 'tc_app',   1),
  ('tc.permissions', 'tc_roles', 1),
  ('tc.permissions', 'tc_perm_version', 1)
ON CONFLICT DO NOTHING;
