package rbac

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/store"
)

// ----- Applications -----

const appCols = `id, key, display_name, description, is_system, is_active, created_at, updated_at`

func scanApp(row pgx.Row) (*Application, error) {
	var a Application
	err := row.Scan(&a.ID, &a.Key, &a.DisplayName, &a.Description, &a.IsSystem, &a.IsActive, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &a, err
}

func (Repo) CreateApplication(ctx context.Context, db store.DBTX, a *Application) error {
	_, err := db.Exec(ctx,
		`INSERT INTO applications (id, key, display_name, description, is_active) VALUES ($1,$2,$3,$4,$5)`,
		a.ID, a.Key, a.DisplayName, a.Description, a.IsActive)
	return err
}

func (Repo) GetApplication(ctx context.Context, db store.DBTX, id uuid.UUID) (*Application, error) {
	return scanApp(db.QueryRow(ctx, `SELECT `+appCols+` FROM applications WHERE id=$1 AND deleted_at IS NULL`, id))
}

func (Repo) ListApplications(ctx context.Context, db store.DBTX) ([]Application, error) {
	rows, err := db.Query(ctx, `SELECT `+appCols+` FROM applications WHERE deleted_at IS NULL ORDER BY is_system DESC, display_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Application
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (Repo) UpdateApplication(ctx context.Context, db store.DBTX, id uuid.UUID, displayName, description string, isActive bool) error {
	ct, err := db.Exec(ctx,
		`UPDATE applications SET display_name=$2, description=$3, is_active=$4
		   WHERE id=$1 AND deleted_at IS NULL AND NOT is_system`, id, displayName, description, isActive)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (Repo) SoftDeleteApplication(ctx context.Context, db store.DBTX, id uuid.UUID) error {
	ct, err := db.Exec(ctx,
		`UPDATE applications SET deleted_at=now(), is_active=false WHERE id=$1 AND deleted_at IS NULL AND NOT is_system`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ----- Permissions -----

const permCols = `id, application_id, key, display_name, description, notes, category, is_system, created_at, updated_at`

func scanPerm(row pgx.Row) (*Permission, error) {
	var p Permission
	err := row.Scan(&p.ID, &p.ApplicationID, &p.Key, &p.DisplayName, &p.Description, &p.Notes, &p.Category, &p.IsSystem, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &p, err
}

func (Repo) CreatePermission(ctx context.Context, db store.DBTX, p *Permission) error {
	_, err := db.Exec(ctx,
		`INSERT INTO permissions (id, application_id, key, display_name, description, notes, category)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		p.ID, p.ApplicationID, p.Key, p.DisplayName, p.Description, p.Notes, p.Category)
	return err
}

func (Repo) GetPermission(ctx context.Context, db store.DBTX, id uuid.UUID) (*Permission, error) {
	return scanPerm(db.QueryRow(ctx, `SELECT `+permCols+` FROM permissions WHERE id=$1`, id))
}

func (Repo) ListPermissions(ctx context.Context, db store.DBTX, appID uuid.UUID) ([]Permission, error) {
	rows, err := db.Query(ctx, `SELECT `+permCols+` FROM permissions WHERE application_id=$1 ORDER BY category, key`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		p, err := scanPerm(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// UpdatePermission edits metadata only (key changes are disallowed for system perms).
func (Repo) UpdatePermission(ctx context.Context, db store.DBTX, id uuid.UUID, displayName, description, notes, category string) error {
	ct, err := db.Exec(ctx,
		`UPDATE permissions SET display_name=$2, description=$3, notes=$4, category=$5 WHERE id=$1`,
		id, displayName, description, notes, category)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (Repo) DeletePermission(ctx context.Context, db store.DBTX, id uuid.UUID) error {
	ct, err := db.Exec(ctx, `DELETE FROM permissions WHERE id=$1 AND NOT is_system`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ----- Roles -----

const roleCols = `id, application_id, key, display_name, description, notes, is_system, created_at, updated_at`

func scanRole(row pgx.Row) (*Role, error) {
	var r Role
	err := row.Scan(&r.ID, &r.ApplicationID, &r.Key, &r.DisplayName, &r.Description, &r.Notes, &r.IsSystem, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &r, err
}

func (Repo) CreateRole(ctx context.Context, db store.DBTX, r *Role) error {
	_, err := db.Exec(ctx,
		`INSERT INTO roles (id, application_id, key, display_name, description, notes) VALUES ($1,$2,$3,$4,$5,$6)`,
		r.ID, r.ApplicationID, r.Key, r.DisplayName, r.Description, r.Notes)
	return err
}

func (Repo) GetRole(ctx context.Context, db store.DBTX, id uuid.UUID) (*Role, error) {
	return scanRole(db.QueryRow(ctx, `SELECT `+roleCols+` FROM roles WHERE id=$1`, id))
}

func (Repo) ListRoles(ctx context.Context, db store.DBTX, appID uuid.UUID) ([]Role, error) {
	rows, err := db.Query(ctx, `SELECT `+roleCols+` FROM roles WHERE application_id=$1 ORDER BY key`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func (Repo) UpdateRole(ctx context.Context, db store.DBTX, id uuid.UUID, displayName, description, notes string) error {
	ct, err := db.Exec(ctx,
		`UPDATE roles SET display_name=$2, description=$3, notes=$4 WHERE id=$1`, id, displayName, description, notes)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (Repo) DeleteRole(ctx context.Context, db store.DBTX, id uuid.UUID) error {
	ct, err := db.Exec(ctx, `DELETE FROM roles WHERE id=$1 AND NOT is_system`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RolePermissionIDs returns the permission ids bound to a role.
func (Repo) RolePermissionIDs(ctx context.Context, db store.DBTX, roleID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := db.Query(ctx, `SELECT permission_id FROM role_permissions WHERE role_id=$1`, roleID)
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

// SetRolePermissions replaces a role's permissions, enforcing the same-application
// invariant. Caller bumps affected users' perm_version in the same tx.
func (Repo) SetRolePermissions(ctx context.Context, db store.DBTX, roleID uuid.UUID, permIDs []uuid.UUID) error {
	var appID uuid.UUID
	if err := db.QueryRow(ctx, `SELECT application_id FROM roles WHERE id=$1`, roleID).Scan(&appID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if _, err := db.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1`, roleID); err != nil {
		return err
	}
	for _, pid := range permIDs {
		var permApp uuid.UUID
		if err := db.QueryRow(ctx, `SELECT application_id FROM permissions WHERE id=$1`, pid).Scan(&permApp); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if permApp != appID {
			return errors.New("rbac: permission and role must belong to the same application")
		}
		if _, err := db.Exec(ctx,
			`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
			roleID, pid); err != nil {
			return err
		}
	}
	return nil
}

// ----- Groups -----

const groupCols = `id, key, display_name, description, is_system, created_at, updated_at`

func scanGroup(row pgx.Row) (*Group, error) {
	var g Group
	err := row.Scan(&g.ID, &g.Key, &g.DisplayName, &g.Description, &g.IsSystem, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &g, err
}

func (Repo) CreateGroup(ctx context.Context, db store.DBTX, g *Group) error {
	_, err := db.Exec(ctx,
		`INSERT INTO groups (id, key, display_name, description) VALUES ($1,$2,$3,$4)`,
		g.ID, g.Key, g.DisplayName, g.Description)
	return err
}

func (Repo) GetGroup(ctx context.Context, db store.DBTX, id uuid.UUID) (*Group, error) {
	return scanGroup(db.QueryRow(ctx, `SELECT `+groupCols+` FROM groups WHERE id=$1`, id))
}

func (Repo) ListGroups(ctx context.Context, db store.DBTX) ([]Group, error) {
	rows, err := db.Query(ctx, `SELECT `+groupCols+` FROM groups ORDER BY display_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func (Repo) UpdateGroup(ctx context.Context, db store.DBTX, id uuid.UUID, displayName, description string) error {
	ct, err := db.Exec(ctx, `UPDATE groups SET display_name=$2, description=$3 WHERE id=$1`, id, displayName, description)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (Repo) DeleteGroup(ctx context.Context, db store.DBTX, id uuid.UUID) error {
	ct, err := db.Exec(ctx, `DELETE FROM groups WHERE id=$1 AND NOT is_system`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
