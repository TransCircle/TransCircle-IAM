-- 0014 Per-client login access control. An OAuth/OIDC client may restrict which
-- users are allowed to complete authorization (log in to the relying party).
--
-- Semantics (enforced in the authorize endpoint): when all three lists are empty
-- the client is unrestricted (anyone who can authenticate may log in). When any
-- list is non-empty the user must match AT LEAST ONE rule (union / OR):
--   * their user id is in login_allowed_user_ids, OR
--   * one of their identity-group keys is in login_allowed_group_keys, OR
--   * they hold one of login_required_perms (evaluated in the client's bound
--     application when one is set, otherwise across all applications).

ALTER TABLE oauth_clients
    ADD COLUMN login_allowed_user_ids  uuid[] NOT NULL DEFAULT '{}',
    ADD COLUMN login_allowed_group_keys text[] NOT NULL DEFAULT '{}',
    ADD COLUMN login_required_perms     text[] NOT NULL DEFAULT '{}';
