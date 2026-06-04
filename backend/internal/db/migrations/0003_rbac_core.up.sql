-- 0003 RBAC core + identity. Permissions/roles are application-scoped; groups
-- are global org structure. Effective permissions = union of three paths.

CREATE TABLE applications (
    id           uuid PRIMARY KEY,
    key          text NOT NULL,
    display_name text NOT NULL,
    description  text NOT NULL DEFAULT '',
    is_system    boolean NOT NULL DEFAULT false,
    is_active    boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    deleted_at   timestamptz
);
CREATE UNIQUE INDEX uniq_app_key ON applications (key) WHERE deleted_at IS NULL;
CREATE TRIGGER trg_applications_updated BEFORE UPDATE ON applications
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE users (
    id                    uuid PRIMARY KEY,
    username              citext NOT NULL,
    email                 citext NOT NULL DEFAULT '',
    display_name          text NOT NULL DEFAULT '',
    status                text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    is_active             boolean NOT NULL DEFAULT true,
    force_password_change boolean NOT NULL DEFAULT true,
    must_enroll_mfa       boolean NOT NULL DEFAULT true,
    -- Authoritative per-user permission version for cache coherency (must-fix #3).
    perm_version          bigint NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    deleted_at            timestamptz
);
CREATE UNIQUE INDEX uniq_user_username ON users (username) WHERE deleted_at IS NULL;
CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE permissions (
    id             uuid PRIMARY KEY,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    key            text NOT NULL,
    display_name   text NOT NULL,
    description    text NOT NULL DEFAULT '',
    notes          text NOT NULL DEFAULT '',
    category       text NOT NULL DEFAULT '',
    is_system      boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, key)
);
CREATE INDEX idx_permissions_app ON permissions (application_id);
CREATE TRIGGER trg_permissions_updated BEFORE UPDATE ON permissions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE roles (
    id             uuid PRIMARY KEY,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    key            text NOT NULL,
    display_name   text NOT NULL,
    description    text NOT NULL DEFAULT '',
    notes          text NOT NULL DEFAULT '',
    is_system      boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, key)
);
CREATE INDEX idx_roles_app ON roles (application_id);
CREATE TRIGGER trg_roles_updated BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE groups (
    id           uuid PRIMARY KEY,
    key          text NOT NULL UNIQUE,
    display_name text NOT NULL,
    description  text NOT NULL DEFAULT '',
    is_system    boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER trg_groups_updated BEFORE UPDATE ON groups
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- role -> permissions (same-application invariant enforced in service layer)
CREATE TABLE role_permissions (
    role_id       uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);
CREATE INDEX idx_role_permissions_perm ON role_permissions (permission_id);

CREATE TABLE group_members (
    group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX idx_group_members_user ON group_members (user_id);

CREATE TABLE group_roles (
    group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id  uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, role_id)
);
CREATE INDEX idx_group_roles_role ON group_roles (role_id);

CREATE TABLE user_roles (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by uuid REFERENCES users(id) ON DELETE SET NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX idx_user_roles_role ON user_roles (role_id);

CREATE TABLE user_permissions (
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    granted_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, permission_id)
);
CREATE INDEX idx_user_permissions_perm ON user_permissions (permission_id);

-- Global monotonic epoch for bulk cache invalidation (must-fix #3).
CREATE TABLE authz_epoch (
    id    smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    epoch bigint NOT NULL DEFAULT 1
);
INSERT INTO authz_epoch (id, epoch) VALUES (1, 1);
