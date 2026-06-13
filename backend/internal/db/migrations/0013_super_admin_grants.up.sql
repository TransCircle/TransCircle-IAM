-- 0013 super-admin allowlist: the authoritative source of truth for who holds
-- the built-in super_admin role. On EVERY boot, Reconcile (internal/superadmin)
-- force-aligns user_roles to {config bootstrap admin} ∪ {rows here whose
-- signature verifies}, stripping any super_admin grant — direct OR via group —
-- that is not on this list. A raw INSERT into user_roles therefore cannot create
-- a lasting super admin: it is wiped on the next restart.
--
-- Each row is HMAC-signed with a sub-key derived from the active DEK, so a row
-- hand-inserted into THIS table (without the DEK) fails verification at boot and
-- is ignored. NOTE: when IAM_KEK_ENABLED is off the DEK is stored unwrapped in
-- crypto_keys, so the signature only stops a DB attacker who does not also read
-- the DEK; enable IAM_KEK_ENABLED in prod for the full "can't add via DB" guarantee.
CREATE TABLE super_admin_grants (
    user_id     uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    username    text NOT NULL,
    dek_version int  NOT NULL,
    sig         bytea NOT NULL,
    note        text NOT NULL DEFAULT '',
    added_at    timestamptz NOT NULL DEFAULT now()
);
