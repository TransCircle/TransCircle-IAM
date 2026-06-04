package rbac

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/store"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("rbac: not found")

// Repo is a stateless data-access layer; every method takes a store.DBTX so it
// runs inside or outside a transaction.
type Repo struct{}

// ----- Effective permissions (the core of the authorization model) -----

const effectivePermSQL = `
SELECT a.id, a.key, p.key
FROM permissions p
JOIN applications a ON a.id = p.application_id AND a.is_active AND a.deleted_at IS NULL
WHERE p.id IN (
    SELECT rp.permission_id
      FROM group_members gm
      JOIN group_roles gr ON gr.group_id = gm.group_id
      JOIN role_permissions rp ON rp.role_id = gr.role_id
     WHERE gm.user_id = $1
    UNION
    SELECT rp.permission_id
      FROM user_roles ur
      JOIN role_permissions rp ON rp.role_id = ur.role_id
     WHERE ur.user_id = $1
    UNION
    SELECT up.permission_id
      FROM user_permissions up
     WHERE up.user_id = $1
)`

// EffectivePermissions returns the union of a user's permissions across all three
// grant paths. If appID is non-nil, results are restricted to that application.
func (Repo) EffectivePermissions(ctx context.Context, db store.DBTX, userID uuid.UUID, appID *uuid.UUID) ([]EffectivePermission, error) {
	sql := effectivePermSQL
	args := []any{userID}
	if appID != nil {
		sql += " AND a.id = $2"
		args = append(args, *appID)
	}
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EffectivePermission
	for rows.Next() {
		var ep EffectivePermission
		if err := rows.Scan(&ep.AppID, &ep.AppKey, &ep.PermKey); err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

// EffectiveRoles returns the role keys a user holds in an application (via groups
// or direct assignment).
func (Repo) EffectiveRoles(ctx context.Context, db store.DBTX, userID, appID uuid.UUID) ([]string, error) {
	const q = `
SELECT DISTINCT r.key
FROM roles r
WHERE r.application_id = $2 AND r.id IN (
    SELECT gr.role_id FROM group_members gm JOIN group_roles gr ON gr.group_id = gm.group_id WHERE gm.user_id = $1
    UNION
    SELECT ur.role_id FROM user_roles ur WHERE ur.user_id = $1
)`
	rows, err := db.Query(ctx, q, userID, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// PermVersion reads a user's current authoritative permission version.
func (Repo) PermVersion(ctx context.Context, db store.DBTX, userID uuid.UUID) (int64, error) {
	var v int64
	err := db.QueryRow(ctx, `SELECT perm_version FROM users WHERE id=$1`, userID).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return v, err
}

// PermVersionAndEpoch reads a user's perm_version together with the global authz
// epoch in one round trip. The cache is only trusted when BOTH still match.
func (Repo) PermVersionAndEpoch(ctx context.Context, db store.DBTX, userID uuid.UUID) (version, epoch int64, err error) {
	err = db.QueryRow(ctx,
		`SELECT u.perm_version, (SELECT epoch FROM authz_epoch WHERE id=1)
		   FROM users u WHERE u.id=$1`, userID).Scan(&version, &epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, ErrNotFound
	}
	return version, epoch, err
}

// BumpPermVersion increments a user's permission version (call inside the same tx
// as any grant/revoke so the authz cache sees the change atomically).
func (Repo) BumpPermVersion(ctx context.Context, db store.DBTX, userID uuid.UUID) error {
	_, err := db.Exec(ctx, `UPDATE users SET perm_version = perm_version + 1 WHERE id=$1`, userID)
	return err
}

// EnsureRoleHasAllSystemPerms (re)grants every system-app permission to a role.
// Used to self-heal the built-in super_admin / admin roles on startup.
func (Repo) EnsureRoleHasAllSystemPerms(ctx context.Context, db store.DBTX, roleID uuid.UUID) error {
	_, err := db.Exec(ctx,
		`INSERT INTO role_permissions (role_id, permission_id)
		 SELECT $1, p.id FROM permissions p WHERE p.application_id=$2
		 ON CONFLICT DO NOTHING`, roleID, SystemAppID)
	return err
}

// CountActiveUsersWithRole counts active (non-deleted) users that hold a role,
// directly or via a group.
func (Repo) CountActiveUsersWithRole(ctx context.Context, db store.DBTX, roleID uuid.UUID) (int, error) {
	const q = `
SELECT count(*) FROM (
    SELECT ur.user_id AS uid FROM user_roles ur WHERE ur.role_id=$1
    UNION
    SELECT gm.user_id FROM group_members gm JOIN group_roles gr ON gr.group_id=gm.group_id WHERE gr.role_id=$1
) t
JOIN users u ON u.id = t.uid
WHERE u.is_active AND u.deleted_at IS NULL`
	var n int
	err := db.QueryRow(ctx, q, roleID).Scan(&n)
	return n, err
}

// BumpEpoch increments the global authz epoch, invalidating every user's cached
// effective permissions at once. Use for broad changes whose affected-user set is
// expensive to enumerate (permission deletion, application disable/delete).
func (Repo) BumpEpoch(ctx context.Context, db store.DBTX) error {
	_, err := db.Exec(ctx, `UPDATE authz_epoch SET epoch = epoch + 1 WHERE id=1`)
	return err
}

// BumpPermVersionForRole bumps every user affected by a role change.
func (Repo) BumpPermVersionForRole(ctx context.Context, db store.DBTX, roleID uuid.UUID) error {
	const q = `
UPDATE users SET perm_version = perm_version + 1
WHERE id IN (
    SELECT ur.user_id FROM user_roles ur WHERE ur.role_id = $1
    UNION
    SELECT gm.user_id FROM group_members gm JOIN group_roles gr ON gr.group_id = gm.group_id WHERE gr.role_id = $1
)`
	_, err := db.Exec(ctx, q, roleID)
	return err
}

// BumpPermVersionForGroup bumps every member of a group.
func (Repo) BumpPermVersionForGroup(ctx context.Context, db store.DBTX, groupID uuid.UUID) error {
	_, err := db.Exec(ctx,
		`UPDATE users SET perm_version = perm_version + 1
		   WHERE id IN (SELECT user_id FROM group_members WHERE group_id=$1)`, groupID)
	return err
}

// ----- Users -----

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.Status,
		&u.IsActive, &u.ForcePasswordChange, &u.MustEnrollMFA, &u.PermVersion,
		&u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

const userCols = `id, username, email, display_name, status, is_active, force_password_change, must_enroll_mfa, perm_version, created_at, updated_at`

// CreateUser inserts a new user.
func (Repo) CreateUser(ctx context.Context, db store.DBTX, u *User) error {
	if u.ID == uuid.Nil {
		return fmt.Errorf("rbac: user id required")
	}
	_, err := db.Exec(ctx,
		`INSERT INTO users (id, username, email, display_name, status, is_active, force_password_change, must_enroll_mfa)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		u.ID, u.Username, u.Email, u.DisplayName, u.Status, u.IsActive, u.ForcePasswordChange, u.MustEnrollMFA)
	return err
}

// GetUser fetches a user by id (excluding soft-deleted).
func (Repo) GetUser(ctx context.Context, db store.DBTX, id uuid.UUID) (*User, error) {
	return scanUser(db.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE id=$1 AND deleted_at IS NULL`, id))
}

// GetUserByUsername fetches a user by username.
func (Repo) GetUserByUsername(ctx context.Context, db store.DBTX, username string) (*User, error) {
	return scanUser(db.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE username=$1 AND deleted_at IS NULL`, username))
}

// ListUsers returns users matching an optional search, paginated.
func (Repo) ListUsers(ctx context.Context, db store.DBTX, search string, limit, offset int) ([]User, int, error) {
	var total int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE deleted_at IS NULL AND ($1='' OR username ILIKE '%'||$1||'%' OR display_name ILIKE '%'||$1||'%')`,
		search).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.Query(ctx,
		`SELECT `+userCols+` FROM users WHERE deleted_at IS NULL
		   AND ($1='' OR username ILIKE '%'||$1||'%' OR display_name ILIKE '%'||$1||'%')
		 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, search, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *u)
	}
	return out, total, rows.Err()
}

// CountUsers returns the number of non-deleted users (used by bootstrap).
func (Repo) CountUsers(ctx context.Context, db store.DBTX) (int, error) {
	var n int
	err := db.QueryRow(ctx, `SELECT count(*) FROM users WHERE deleted_at IS NULL`).Scan(&n)
	return n, err
}

// UpdateUserProfile updates editable profile + status fields.
func (Repo) UpdateUserProfile(ctx context.Context, db store.DBTX, id uuid.UUID, email, displayName, status string) error {
	ct, err := db.Exec(ctx,
		`UPDATE users SET email=$2, display_name=$3, status=$4, is_active=($4='active') WHERE id=$1 AND deleted_at IS NULL`,
		id, email, displayName, status)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateSelfProfile lets a user edit their own editable profile fields
// (email + display name); the username is immutable.
func (Repo) UpdateSelfProfile(ctx context.Context, db store.DBTX, id uuid.UUID, email, displayName string) error {
	ct, err := db.Exec(ctx,
		`UPDATE users SET email=$2, display_name=$3 WHERE id=$1 AND deleted_at IS NULL`,
		id, email, displayName)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserFlags updates the onboarding gate flags.
func (Repo) SetUserFlags(ctx context.Context, db store.DBTX, id uuid.UUID, forcePwd, mustMFA bool) error {
	_, err := db.Exec(ctx,
		`UPDATE users SET force_password_change=$2, must_enroll_mfa=$3 WHERE id=$1`, id, forcePwd, mustMFA)
	return err
}

// SoftDeleteUser marks a user deleted.
func (Repo) SoftDeleteUser(ctx context.Context, db store.DBTX, id uuid.UUID) error {
	_, err := db.Exec(ctx,
		`UPDATE users SET deleted_at=now(), is_active=false, status='disabled' WHERE id=$1 AND deleted_at IS NULL`, id)
	return err
}
