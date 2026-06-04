-- 0005 authentication & MFA. Secrets at rest are AES-256-GCM under the DEK.

CREATE TABLE user_credentials (
    user_id                  uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash            text NOT NULL,                 -- argon2id PHC string
    password_change_required boolean NOT NULL DEFAULT true, -- mirror of users.force_password_change
    password_updated_at      timestamptz NOT NULL DEFAULT now(),
    previous_hashes          text[] NOT NULL DEFAULT '{}'   -- reuse prevention (last N)
);

-- Singleton WebAuthn relying-party config, admin-editable, loaded per request.
CREATE TABLE webauthn_rp_config (
    id                smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    rp_id             text NOT NULL,
    rp_display_name   text NOT NULL,
    origins           text[] NOT NULL DEFAULT '{}',
    attestation       text NOT NULL DEFAULT 'none',
    user_verification text NOT NULL DEFAULT 'required',
    updated_at        timestamptz NOT NULL DEFAULT now(),
    updated_by        uuid REFERENCES users(id) ON DELETE SET NULL
);
CREATE TRIGGER trg_webauthn_rp_updated BEFORE UPDATE ON webauthn_rp_config
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE webauthn_credentials (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   bytea NOT NULL UNIQUE,
    public_key      bytea NOT NULL,            -- COSE
    attestation_type text NOT NULL DEFAULT '',
    aaguid          bytea,
    sign_count      bigint NOT NULL DEFAULT 0,
    transports      text[] NOT NULL DEFAULT '{}',
    backup_eligible boolean NOT NULL DEFAULT false,
    backup_state    boolean NOT NULL DEFAULT false,
    name            text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz
);
CREATE INDEX idx_webauthn_creds_user ON webauthn_credentials (user_id);

CREATE TABLE totp_secrets (
    user_id          uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_encrypted bytea NOT NULL,           -- AES-256-GCM(base32 secret) under DEK
    secret_nonce     bytea NOT NULL,
    dek_version      integer NOT NULL REFERENCES crypto_keys(version),
    confirmed_at     timestamptz,              -- NULL until first valid code
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE recovery_codes (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  text NOT NULL,                  -- argon2id hash
    used_at    timestamptz,
    batch_id   uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_recovery_codes_unused ON recovery_codes (user_id) WHERE used_at IS NULL;
