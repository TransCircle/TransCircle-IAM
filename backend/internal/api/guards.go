package api

import (
	"context"
	"net/http"
	"slices"

	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/rbac"
)

// actorID returns the authenticated caller's user id.
func actorID(r *http.Request) uuid.UUID {
	if p, ok := authctx.From(r.Context()); ok {
		return p.UserID
	}
	return uuid.Nil
}

func (h *Handlers) systemRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return h.Repo.EffectiveRoles(ctx, h.Store.Pool, userID, rbac.SystemAppID)
}

func (h *Handlers) isSuperAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	roles, err := h.systemRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	return slices.Contains(roles, rbac.SuperAdminKey), nil
}

// assertCanManageUser enforces the admin/super-admin relationship rule: a
// super_admin may manage anyone; a plain admin may not modify other admins or
// super-admins (acting on oneself is always allowed).
func (h *Handlers) assertCanManageUser(ctx context.Context, actor, target uuid.UUID) error {
	if actor == target {
		return nil
	}
	actorRoles, err := h.systemRoles(ctx, actor)
	if err != nil {
		return err
	}
	if slices.Contains(actorRoles, rbac.SuperAdminKey) {
		return nil
	}
	targetRoles, err := h.systemRoles(ctx, target)
	if err != nil {
		return err
	}
	if slices.Contains(targetRoles, rbac.SuperAdminKey) || slices.Contains(targetRoles, rbac.AdminKey) {
		return httpx.ErrForbidden.WithDetail("仅超级管理员可管理其他管理员")
	}
	return nil
}

// assertCanGrantRole restricts granting/revoking the admin and super_admin roles
// to super_admins only.
func (h *Handlers) assertCanGrantRole(ctx context.Context, actor, roleID uuid.UUID) error {
	if roleID != rbac.SuperAdminRole && roleID != rbac.AdminRole {
		return nil
	}
	super, err := h.isSuperAdmin(ctx, actor)
	if err != nil {
		return err
	}
	if !super {
		return httpx.ErrForbidden.WithDetail("仅超级管理员可授予/移除管理员角色")
	}
	return nil
}

// assertNotLastSuperAdmin prevents removing the super_admin role from the only
// remaining holder (avoids a lockout).
func (h *Handlers) assertNotLastSuperAdmin(ctx context.Context, roleID uuid.UUID) error {
	if roleID != rbac.SuperAdminRole {
		return nil
	}
	n, err := h.Repo.CountActiveUsersWithRole(ctx, h.Store.Pool, roleID)
	if err != nil {
		return err
	}
	if n <= 1 {
		return httpx.ErrForbidden.WithDetail("不能移除最后一个超级管理员")
	}
	return nil
}

// errSystemObject is returned when a write targets a protected built-in object.
var errSystemObject = httpx.ErrForbidden.WithDetail("内建系统对象不可修改")

// assertNotSystemApp blocks mutations within the built-in system application.
func assertNotSystemApp(appID uuid.UUID) error {
	if appID == rbac.SystemAppID {
		return errSystemObject
	}
	return nil
}

// assertPermissionEditable blocks edits to built-in (system) permissions.
func (h *Handlers) assertPermissionEditable(ctx context.Context, id uuid.UUID) error {
	p, err := h.Repo.GetPermission(ctx, h.Store.Pool, id)
	if err != nil {
		return httpx.ErrNotFound
	}
	if p.IsSystem || p.ApplicationID == rbac.SystemAppID {
		return errSystemObject
	}
	return nil
}

// assertRoleEditable blocks edits to built-in (system) roles such as
// super_admin and admin.
func (h *Handlers) assertRoleEditable(ctx context.Context, id uuid.UUID) error {
	role, err := h.Repo.GetRole(ctx, h.Store.Pool, id)
	if err != nil {
		return httpx.ErrNotFound
	}
	if role.IsSystem || role.ApplicationID == rbac.SystemAppID {
		return errSystemObject
	}
	return nil
}
