-- 0004 seed: built-in "system" application, the authoritative IAM permission
-- catalog, and the super_admin role. Idempotent; metadata-only upserts never
-- wipe grants or flip is_system. This catalog is the single contract mirrored
-- by Go constants (authz/catalog.go) and the frontend permission list.

INSERT INTO applications (id, key, display_name, description, is_system, is_active)
VALUES ('00000000-0000-0000-0000-000000000001', 'system', 'TransCircle IAM',
        'IAM 自身的内置应用，承载所有系统级细粒度权限。', true, true)
ON CONFLICT (id) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        description  = EXCLUDED.description;

INSERT INTO permissions (id, application_id, key, display_name, description, category, is_system)
VALUES
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.users.read',                 '查看用户',       '查看用户列表与详情。',                 '用户', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.users.write',                '管理用户',       '创建、编辑、启用/禁用用户。',           '用户', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.users.delete',               '删除用户',       '软删除用户。',                         '用户', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.users.impersonate',          '代登用户',       '以其他用户身份登录排查问题（不可越权）。', '用户', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.users.impersonate.elevated', '越权代登',       '允许代登权限高于自身的用户（受限提权）。', '用户', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.groups.read',                '查看身份组',     '查看身份组与成员。',                   '身份组', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.groups.write',               '管理身份组',     '创建、编辑身份组及其成员/角色。',       '身份组', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.groups.delete',              '删除身份组',     '删除身份组。',                         '身份组', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.roles.read',                 '查看角色',       '查看角色及其权限。',                   '角色', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.roles.write',                '管理角色',       '创建、编辑角色及其权限绑定。',          '角色', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.roles.delete',               '删除角色',       '删除角色。',                           '角色', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.permissions.read',           '查看权限',       '查看权限目录。',                       '权限', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.permissions.write',          '管理权限',       '创建、编辑权限及其描述/备注。',         '权限', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.permissions.delete',         '删除权限',       '删除权限。',                           '权限', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.applications.read',          '查看应用',       '查看接入应用。',                       '应用', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.applications.write',         '管理应用',       '创建、编辑应用及其权限/角色目录。',     '应用', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.applications.delete',        '删除应用',       '软删除应用。',                         '应用', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.clients.read',               '查看 OIDC 客户端', '查看 OAuth/OIDC 客户端。',             '应用', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.clients.write',              '管理 OIDC 客户端', '创建、编辑 OAuth/OIDC 客户端。',        '应用', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.clients.delete',             '删除 OIDC 客户端', '删除 OAuth/OIDC 客户端。',             '应用', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.clients.rotate_secret',      '轮换客户端密钥',  '轮换 OAuth 客户端密钥（敏感，需 step-up）。', '应用', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.sessions.read',              '查看会话',       '查看用户活跃会话/设备。',               '会话', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.sessions.revoke',            '吊销会话',       '远程强制下线一个或全部会话。',          '会话', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.audit.read',                 '查看审计日志',   '检索与查看审计日志。',                 '审计', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.security.read',              '查看安全状态',   '查看签名密钥与 DEK 状态。',             '安全', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.security.rotate',            '轮换密钥',       '轮换签名密钥/DEK（敏感，需 step-up）。', '安全', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.settings.read',              '查看系统设置',   '查看 WebAuthn/安全策略等设置。',        '设置', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.settings.write',             '管理系统设置',   '编辑 WebAuthn RP、安全策略等设置。',     '设置', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.apptokens.read',             '查看 API 令牌',   '查看系统 M2M API 令牌。',              'API 令牌', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.apptokens.write',            '管理 API 令牌',   '创建 API 令牌（敏感）。',              'API 令牌', true),
  (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'iam.apptokens.delete',           '吊销 API 令牌',   '吊销 API 令牌。',                     'API 令牌', true)
ON CONFLICT (application_id, key) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        description  = EXCLUDED.description,
        category     = EXCLUDED.category;

INSERT INTO roles (id, application_id, key, display_name, description, is_system)
VALUES ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001',
        'super_admin', '超级管理员', '拥有全部 IAM 系统权限的内置角色。', true)
ON CONFLICT (id) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        description  = EXCLUDED.description;

-- super_admin binds every system permission.
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000002', p.id
FROM permissions p
WHERE p.application_id = '00000000-0000-0000-0000-000000000001'
ON CONFLICT DO NOTHING;
