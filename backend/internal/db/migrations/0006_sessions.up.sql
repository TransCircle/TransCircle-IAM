-- 0006 sessions. Postgres is the authoritative device list; Redis mirrors for
-- O(1) middleware lookup plus a revocation tombstone.
CREATE TABLE sessions (
    id                   uuid PRIMARY KEY,
    user_id              uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at           timestamptz NOT NULL DEFAULT now(),
    last_seen_at         timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL,          -- absolute lifetime (authority)
    idle_expires_at      timestamptz NOT NULL,          -- sliding idle deadline
    revoked_at           timestamptz,
    ip                   inet,
    user_agent           text NOT NULL DEFAULT '',
    amr                  text[] NOT NULL DEFAULT '{}',  -- pwd, webauthn, otp, recovery
    aal                  smallint NOT NULL DEFAULT 1,
    mfa_satisfied        boolean NOT NULL DEFAULT false,
    mfa_satisfied_at     timestamptz,                   -- for step-up freshness
    impersonator_user_id uuid REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX idx_sessions_active ON sessions (user_id) WHERE revoked_at IS NULL;
