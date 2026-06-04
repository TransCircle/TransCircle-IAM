-- 0002 cryptography: data-encryption keys (DEK) and OIDC signing keys.

-- DEK table. The active DEK encrypts all business secrets at rest (AES-256-GCM).
-- dek_ciphertext is either the raw DEK (kek_wrapped=false) or KEK-wrapped (opt-in).
CREATE TABLE crypto_keys (
    id             uuid PRIMARY KEY,
    version        integer NOT NULL UNIQUE,
    purpose        text NOT NULL DEFAULT 'dek',
    dek_ciphertext bytea NOT NULL,
    kek_wrapped    boolean NOT NULL DEFAULT false,
    kek_nonce      bytea,
    kek_kid        text,                 -- SHA-256(KEK)[:8], boot mismatch detection
    status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    retired_at     timestamptz
);
CREATE UNIQUE INDEX uniq_active_dek ON crypto_keys (purpose) WHERE status = 'active';

-- OIDC RS256 signing keys. JWKS publishes status IN ('active','previous').
CREATE TABLE signing_keys (
    id              uuid PRIMARY KEY,
    kid             text NOT NULL UNIQUE,   -- base64url(SHA-256(DER pubkey))[:16]
    algorithm       text NOT NULL DEFAULT 'RS256',
    public_jwk      jsonb NOT NULL,
    private_key_enc bytea NOT NULL,         -- PKCS#8 DER, AES-256-GCM under DEK
    private_key_nonce bytea NOT NULL,
    dek_version     integer NOT NULL REFERENCES crypto_keys(version),
    status          text NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','previous','retired')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    activated_at    timestamptz,
    retired_at      timestamptz
);
CREATE UNIQUE INDEX uniq_active_signing ON signing_keys (algorithm) WHERE status = 'active';
CREATE INDEX idx_signing_keys_status ON signing_keys (status);
