-- 0011 add the built-in "admin" role. It carries the same system permissions as
-- super_admin; the distinction (admins cannot modify other admins/super-admins,
-- and cannot grant the admin/super_admin roles) is enforced in the service layer.
-- super_admin remains the bootstrap-only account.
INSERT INTO roles (id, application_id, key, display_name, description, is_system)
VALUES ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000001',
        'admin', '管理员', '内置管理员：拥有除"管理其他管理员/超级管理员"之外的全部系统权限。', true)
ON CONFLICT (id) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        description  = EXCLUDED.description;

INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003', p.id
FROM permissions p
WHERE p.application_id = '00000000-0000-0000-0000-000000000001'
ON CONFLICT DO NOTHING;
