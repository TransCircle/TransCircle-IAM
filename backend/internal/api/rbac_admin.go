package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/rbac"
)

// ----- Applications -----

func (h *Handlers) listApplications(w http.ResponseWriter, r *http.Request) error {
	apps, err := h.Repo.ListApplications(r.Context(), h.Store.Pool)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"applications": apps})
	return nil
}

type appReq struct {
	Key         string `json:"key"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	IsActive    bool   `json:"is_active"`
}

func (h *Handlers) createApplication(w http.ResponseWriter, r *http.Request) error {
	var req appReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Key == "" || req.DisplayName == "" {
		return httpx.ErrBadRequest.WithDetail("key 与名称必填")
	}
	app := &rbac.Application{ID: crypto.NewUUIDv7(), Key: req.Key, DisplayName: req.DisplayName, Description: req.Description, IsActive: true}
	ctx := r.Context()
	err := h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.CreateApplication(ctx, tx, app); err != nil {
			return httpx.ErrConflict.WithDetail("应用 key 可能已存在").WithInternal(err)
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.application.create", TargetType: "application", TargetID: app.ID.String(), TargetLabel: app.Key})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusCreated, app)
	return nil
}

func (h *Handlers) updateApplication(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	if err := assertNotSystemApp(id); err != nil {
		return err
	}
	var req appReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.UpdateApplication(ctx, tx, id, req.DisplayName, req.Description, req.IsActive); err != nil {
			return err
		}
		// Toggling is_active changes the effective-permission filter for its users.
		if err := h.Repo.BumpEpoch(ctx, tx); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.application.update", TargetType: "application", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) deleteApplication(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := assertNotSystemApp(id); err != nil {
		return err
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.SoftDeleteApplication(ctx, tx, id); err != nil {
			return err
		}
		// Removing an app drops its permissions from every user's effective set.
		if err := h.Repo.BumpEpoch(ctx, tx); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.application.delete", TargetType: "application", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

// ----- Permissions -----

func (h *Handlers) listPermissions(w http.ResponseWriter, r *http.Request) error {
	appID, err := pathUUID(r, "appID")
	if err != nil {
		return err
	}
	perms, err := h.Repo.ListPermissions(r.Context(), h.Store.Pool, appID)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"permissions": perms})
	return nil
}

type permReq struct {
	Key         string `json:"key"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Notes       string `json:"notes"`
	Category    string `json:"category"`
}

func (h *Handlers) createPermission(w http.ResponseWriter, r *http.Request) error {
	appID, err := pathUUID(r, "appID")
	if err != nil {
		return err
	}
	if err := assertNotSystemApp(appID); err != nil {
		return err
	}
	var req permReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Key == "" || req.DisplayName == "" {
		return httpx.ErrBadRequest.WithDetail("key 与名称必填")
	}
	p := &rbac.Permission{ID: crypto.NewUUIDv7(), ApplicationID: appID, Key: req.Key, DisplayName: req.DisplayName, Description: req.Description, Notes: req.Notes, Category: req.Category}
	ctx := r.Context()
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.CreatePermission(ctx, tx, p); err != nil {
			return httpx.ErrConflict.WithDetail("权限 key 可能已存在").WithInternal(err)
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.permission.create", TargetType: "permission", TargetID: p.ID.String(), TargetLabel: p.Key})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusCreated, p)
	return nil
}

func (h *Handlers) updatePermission(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req permReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	if err := h.assertPermissionEditable(ctx, id); err != nil {
		return err
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.UpdatePermission(ctx, tx, id, req.DisplayName, req.Description, req.Notes, req.Category); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.permission.update", TargetType: "permission", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) deletePermission(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := h.assertPermissionEditable(ctx, id); err != nil {
		return err
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.DeletePermission(ctx, tx, id); err != nil {
			return err
		}
		// Cascade removes the permission from roles/users; invalidate all caches.
		if err := h.Repo.BumpEpoch(ctx, tx); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.permission.delete", TargetType: "permission", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

// ----- Roles -----

func (h *Handlers) listRoles(w http.ResponseWriter, r *http.Request) error {
	appID, err := pathUUID(r, "appID")
	if err != nil {
		return err
	}
	roles, err := h.Repo.ListRoles(r.Context(), h.Store.Pool, appID)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"roles": roles})
	return nil
}

type roleReq struct {
	Key         string `json:"key"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Notes       string `json:"notes"`
}

func (h *Handlers) createRole(w http.ResponseWriter, r *http.Request) error {
	appID, err := pathUUID(r, "appID")
	if err != nil {
		return err
	}
	if err := assertNotSystemApp(appID); err != nil {
		return err
	}
	var req roleReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Key == "" || req.DisplayName == "" {
		return httpx.ErrBadRequest.WithDetail("key 与名称必填")
	}
	role := &rbac.Role{ID: crypto.NewUUIDv7(), ApplicationID: appID, Key: req.Key, DisplayName: req.DisplayName, Description: req.Description, Notes: req.Notes}
	ctx := r.Context()
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.CreateRole(ctx, tx, role); err != nil {
			return httpx.ErrConflict.WithDetail("角色 key 可能已存在").WithInternal(err)
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.role.create", TargetType: "role", TargetID: role.ID.String(), TargetLabel: role.Key})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusCreated, role)
	return nil
}

func (h *Handlers) updateRole(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req roleReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	if err := h.assertRoleEditable(ctx, id); err != nil {
		return err
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.UpdateRole(ctx, tx, id, req.DisplayName, req.Description, req.Notes); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.role.update", TargetType: "role", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) deleteRole(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := h.assertRoleEditable(ctx, id); err != nil {
		return err
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.BumpPermVersionForRole(ctx, tx, id); err != nil {
			return err
		}
		if err := h.Repo.DeleteRole(ctx, tx, id); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.role.delete", TargetType: "role", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) getRolePermissions(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ids, err := h.Repo.RolePermissionIDs(r.Context(), h.Store.Pool, id)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"permission_ids": ids})
	return nil
}

type setRolePermsReq struct {
	PermissionIDs []uuid.UUID `json:"permission_ids"`
}

func (h *Handlers) setRolePermissions(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req setRolePermsReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	if err := h.assertRoleEditable(ctx, id); err != nil {
		return err
	}
	// Replacing a role's permissions is a delete-then-insert that must not
	// interleave with a concurrent edit; run it at SERIALIZABLE with retry.
	err = h.Store.WithSerializableTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.SetRolePermissions(ctx, tx, id, req.PermissionIDs); err != nil {
			switch {
			case errors.Is(err, rbac.ErrCrossAppPermission):
				return httpx.ErrBadRequest.WithDetail("权限与角色必须属于同一应用")
			case errors.Is(err, rbac.ErrNotFound):
				return httpx.ErrNotFound
			default:
				// Propagate raw (incl. pgx 40001) so WithSerializableTx can retry.
				return err
			}
		}
		if err := h.Repo.BumpPermVersionForRole(ctx, tx, id); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.role.set_permissions", TargetType: "role", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

// ----- Groups -----

func (h *Handlers) listGroups(w http.ResponseWriter, r *http.Request) error {
	groups, err := h.Repo.ListGroups(r.Context(), h.Store.Pool)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"groups": groups})
	return nil
}

type groupReq struct {
	Key         string `json:"key"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

func (h *Handlers) createGroup(w http.ResponseWriter, r *http.Request) error {
	var req groupReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Key == "" || req.DisplayName == "" {
		return httpx.ErrBadRequest.WithDetail("key 与名称必填")
	}
	g := &rbac.Group{ID: crypto.NewUUIDv7(), Key: req.Key, DisplayName: req.DisplayName, Description: req.Description}
	ctx := r.Context()
	err := h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.CreateGroup(ctx, tx, g); err != nil {
			return httpx.ErrConflict.WithDetail("身份组 key 可能已存在").WithInternal(err)
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.group.create", TargetType: "group", TargetID: g.ID.String(), TargetLabel: g.Key})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusCreated, g)
	return nil
}

func (h *Handlers) getGroup(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	g, err := h.Repo.GetGroup(ctx, h.Store.Pool, id)
	if err != nil {
		return httpx.ErrNotFound
	}
	members, err := h.Repo.GroupMembers(ctx, h.Store.Pool, id)
	if err != nil {
		return err
	}
	roles, err := h.Repo.GroupRoleIDs(ctx, h.Store.Pool, id)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"group": g, "members": members, "role_ids": roles})
	return nil
}

type groupMembersReq struct {
	UserIDs []uuid.UUID `json:"user_ids"`
}

// addGroupMembers batch-adds users to a group from the group management UI.
func (h *Handlers) addGroupMembers(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req groupMembersReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if len(req.UserIDs) == 0 {
		return httpx.ErrBadRequest.WithDetail("未选择用户")
	}
	ctx := r.Context()
	if _, err := h.Repo.GetGroup(ctx, h.Store.Pool, id); err != nil {
		return httpx.ErrNotFound
	}
	actor := actorID(r)
	// A privileged group's membership is an admin-role grant in disguise.
	if err := h.guardPrivilegedGroupMembership(ctx, actor, id); err != nil {
		return err
	}
	for _, uid := range req.UserIDs {
		if err := h.assertCanManageUser(ctx, actor, uid); err != nil {
			return err
		}
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		for _, uid := range req.UserIDs {
			if err := h.Repo.AddGroupMember(ctx, tx, id, uid); err != nil {
				return err
			}
			// A new member inherits the group's roles → bump their perm version.
			if err := h.Repo.BumpPermVersion(ctx, tx, uid); err != nil {
				return err
			}
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.group.add_members", TargetType: "group", TargetID: id.String(), Metadata: map[string]any{"count": len(req.UserIDs)}})
	})
	if err != nil {
		return mapWriteError(err)
	}
	for _, uid := range req.UserIDs {
		h.afterPermChange(ctx, uid)
	}
	httpx.NoContent(w)
	return nil
}

// removeGroupMember removes a single user from a group.
func (h *Handlers) removeGroupMember(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	userID, err := pathUUID(r, "userID")
	if err != nil {
		return err
	}
	ctx := r.Context()
	actor := actorID(r)
	if err := h.guardPrivilegedGroupMembership(ctx, actor, id); err != nil {
		return err
	}
	if err := h.assertCanManageUser(ctx, actor, userID); err != nil {
		return err
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.RemoveGroupMember(ctx, tx, id, userID); err != nil {
			return err
		}
		if err := h.Repo.BumpPermVersion(ctx, tx, userID); err != nil {
			return err
		}
		// A group may confer super_admin; removing its last member must not zero
		// out the super-admins.
		if err := h.ensureSuperAdminSurvivesTx(ctx, tx); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.group.remove_member", TargetType: "group", TargetID: id.String(), Metadata: map[string]any{"user": userID.String()}})
	})
	if err != nil {
		return err
	}
	h.afterPermChange(ctx, userID)
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) updateGroup(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req groupReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.UpdateGroup(ctx, tx, id, req.DisplayName, req.Description); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.group.update", TargetType: "group", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) deleteGroup(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.BumpPermVersionForGroup(ctx, tx, id); err != nil {
			return err
		}
		if err := h.Repo.DeleteGroup(ctx, tx, id); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.group.delete", TargetType: "group", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) addGroupRole(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req idReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	if err := h.guardRoleGrant(ctx, actorID(r), req.ID); err != nil {
		return err
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.AddGroupRole(ctx, tx, id, req.ID); err != nil {
			return err
		}
		if err := h.Repo.BumpPermVersionForGroup(ctx, tx, id); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.group.add_role", TargetType: "group", TargetID: id.String(), Metadata: map[string]any{"role": req.ID.String()}})
	})
	if err != nil {
		return mapWriteError(err)
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) removeGroupRole(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	roleID, err := pathUUID(r, "roleID")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := h.guardRoleGrant(ctx, actorID(r), roleID); err != nil {
		return err
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.BumpPermVersionForGroup(ctx, tx, id); err != nil {
			return err
		}
		if err := h.Repo.RemoveGroupRole(ctx, tx, id, roleID); err != nil {
			return err
		}
		// Detaching super_admin from a group must not remove the last super-admin.
		if roleID == rbac.SuperAdminRole {
			if err := h.ensureSuperAdminSurvivesTx(ctx, tx); err != nil {
				return err
			}
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.group.remove_role", TargetType: "group", TargetID: id.String(), Metadata: map[string]any{"role": roleID.String()}})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}
