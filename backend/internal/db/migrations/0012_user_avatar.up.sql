-- 0012 user avatars. The file itself lives on the mounted data volume
-- (<IAM_DATA_DIR>/avatars/<uuid>.<ext>); this column stores the public URL path
-- (e.g. /api/v1/avatars/<uuid>.png) or '' when the user has no avatar.
ALTER TABLE users ADD COLUMN avatar_url text NOT NULL DEFAULT '';
