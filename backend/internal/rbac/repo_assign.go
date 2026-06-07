package rbac

import (
	"context"

	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/store"
)

// AddUserRole grants a role directly to a user.
func (Repo) AddUserRole(ctx context.Context, db store.DBTX, userID, roleID, grantedBy uuid.UUID) error {
	_, err := db.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, granted_by) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
		userID, roleID, nullUUID(grantedBy))
	return err
}

// RemoveUserRole revokes a directly-assigned role.
func (Repo) RemoveUserRole(ctx context.Context, db store.DBTX, userID, roleID uuid.UUID) error {
	_, err := db.Exec(ctx, `DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2`, userID, roleID)
	return err
}

// AddUserPermission grants a single permission directly to a user.
func (Repo) AddUserPermission(ctx context.Context, db store.DBTX, userID, permID, grantedBy uuid.UUID) error {
	_, err := db.Exec(ctx,
		`INSERT INTO user_permissions (user_id, permission_id, granted_by) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
		userID, permID, nullUUID(grantedBy))
	return err
}

// RemoveUserPermission revokes a directly-granted permission.
func (Repo) RemoveUserPermission(ctx context.Context, db store.DBTX, userID, permID uuid.UUID) error {
	_, err := db.Exec(ctx, `DELETE FROM user_permissions WHERE user_id=$1 AND permission_id=$2`, userID, permID)
	return err
}

// AddGroupMember adds a user to a group.
func (Repo) AddGroupMember(ctx context.Context, db store.DBTX, groupID, userID uuid.UUID) error {
	_, err := db.Exec(ctx,
		`INSERT INTO group_members (group_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, groupID, userID)
	return err
}

// RemoveGroupMember removes a user from a group.
func (Repo) RemoveGroupMember(ctx context.Context, db store.DBTX, groupID, userID uuid.UUID) error {
	_, err := db.Exec(ctx, `DELETE FROM group_members WHERE group_id=$1 AND user_id=$2`, groupID, userID)
	return err
}

// AddGroupRole grants a role to all members of a group.
func (Repo) AddGroupRole(ctx context.Context, db store.DBTX, groupID, roleID uuid.UUID) error {
	_, err := db.Exec(ctx,
		`INSERT INTO group_roles (group_id, role_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, groupID, roleID)
	return err
}

// RemoveGroupRole revokes a role from a group.
func (Repo) RemoveGroupRole(ctx context.Context, db store.DBTX, groupID, roleID uuid.UUID) error {
	_, err := db.Exec(ctx, `DELETE FROM group_roles WHERE group_id=$1 AND role_id=$2`, groupID, roleID)
	return err
}

// UserDirectRoles lists role ids directly assigned to a user.
func (Repo) UserDirectRoles(ctx context.Context, db store.DBTX, userID uuid.UUID) ([]uuid.UUID, error) {
	return queryUUIDs(ctx, db, `SELECT role_id FROM user_roles WHERE user_id=$1`, userID)
}

// UserDirectPermissions lists permission ids directly granted to a user.
func (Repo) UserDirectPermissions(ctx context.Context, db store.DBTX, userID uuid.UUID) ([]uuid.UUID, error) {
	return queryUUIDs(ctx, db, `SELECT permission_id FROM user_permissions WHERE user_id=$1`, userID)
}

// UserGroups lists group ids a user belongs to.
func (Repo) UserGroups(ctx context.Context, db store.DBTX, userID uuid.UUID) ([]uuid.UUID, error) {
	return queryUUIDs(ctx, db, `SELECT group_id FROM group_members WHERE user_id=$1`, userID)
}

// UserGroupKeys lists the identity-group keys a user belongs to (global, not
// app-scoped), for OIDC claims and the machine permissions API.
func (Repo) UserGroupKeys(ctx context.Context, db store.DBTX, userID uuid.UUID) ([]string, error) {
	rows, err := db.Query(ctx,
		`SELECT g.key FROM group_members gm JOIN groups g ON g.id = gm.group_id
		  WHERE gm.user_id=$1 ORDER BY g.key`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// GroupMemberIDs lists user ids in a group.
func (Repo) GroupMemberIDs(ctx context.Context, db store.DBTX, groupID uuid.UUID) ([]uuid.UUID, error) {
	return queryUUIDs(ctx, db, `SELECT user_id FROM group_members WHERE group_id=$1`, groupID)
}

// GroupRoleIDs lists role ids granted by a group.
func (Repo) GroupRoleIDs(ctx context.Context, db store.DBTX, groupID uuid.UUID) ([]uuid.UUID, error) {
	return queryUUIDs(ctx, db, `SELECT role_id FROM group_roles WHERE group_id=$1`, groupID)
}

func queryUUIDs(ctx context.Context, db store.DBTX, q string, args ...any) ([]uuid.UUID, error) {
	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}
