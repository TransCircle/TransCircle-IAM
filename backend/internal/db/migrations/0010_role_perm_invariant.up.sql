-- 0010 defense-in-depth: enforce the same-application invariant for
-- role_permissions at the database level (previously only checked in the service
-- layer). Prevents any code path or manual SQL from binding a permission to a
-- role in a different application.
CREATE OR REPLACE FUNCTION role_permissions_same_app() RETURNS trigger AS $$
DECLARE
    role_app uuid;
    perm_app uuid;
BEGIN
    SELECT application_id INTO role_app FROM roles WHERE id = NEW.role_id;
    SELECT application_id INTO perm_app FROM permissions WHERE id = NEW.permission_id;
    IF role_app IS DISTINCT FROM perm_app THEN
        RAISE EXCEPTION 'role_permissions: role % and permission % belong to different applications',
            NEW.role_id, NEW.permission_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_role_permissions_same_app
    BEFORE INSERT OR UPDATE ON role_permissions
    FOR EACH ROW EXECUTE FUNCTION role_permissions_same_app();
