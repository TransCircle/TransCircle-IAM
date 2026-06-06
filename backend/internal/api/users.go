package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authn"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/rbac"
)

func (h *Handlers) listUsers(w http.ResponseWriter, r *http.Request) error {
	limit := queryInt(r, "limit", 20)
	offset := queryInt(r, "offset", 0)
	search := r.URL.Query().Get("search")
	users, total, err := h.Repo.ListUsers(r.Context(), h.Store.Pool, search, limit, offset)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"users": users, "total": total})
	return nil
}

type createUserReq struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

type createUserResp struct {
	User         rbac.User `json:"user"`
	TempPassword string    `json:"temp_password"`
}

func (h *Handlers) createUser(w http.ResponseWriter, r *http.Request) error {
	var req createUserReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Username == "" {
		return httpx.ErrBadRequest.WithDetail("用户名必填")
	}
	ctx := r.Context()
	passwords := authn.NewPasswordService(h.Hasher, 12, 5)
	user := &rbac.User{
		ID: crypto.NewUUIDv7(), Username: req.Username, Email: req.Email, DisplayName: req.DisplayName,
		Status: "active", IsActive: true, ForcePasswordChange: true, MustEnrollMFA: true,
	}
	temp := crypto.RandomToken(9)
	err := h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.CreateUser(ctx, tx, user); err != nil {
			return httpx.ErrConflict.WithDetail("用户名可能已存在").WithInternal(err)
		}
		if err := passwords.SetInitial(ctx, tx, user.ID, temp); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.user.create", TargetType: "user", TargetID: user.ID.String(), TargetLabel: user.Username})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusCreated, createUserResp{User: *user, TempPassword: temp})
	return nil
}

func (h *Handlers) getUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	user, err := h.Repo.GetUser(r.Context(), h.Store.Pool, id)
	if err != nil {
		return httpx.ErrNotFound
	}
	httpx.JSON(w, r, http.StatusOK, user)
	return nil
}

type updateUserReq struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
}

func (h *Handlers) updateUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req updateUserReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Status != "active" && req.Status != "disabled" {
		return httpx.ErrBadRequest.WithDetail("状态非法")
	}
	ctx := r.Context()
	if actorID(r) == id && req.Status == "disabled" {
		return httpx.ErrBadRequest.WithDetail("不能禁用自己的账户")
	}
	if err := h.assertCanManageUser(ctx, actorID(r), id); err != nil {
		return err
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Repo.UpdateUserProfile(ctx, tx, id, req.Email, req.DisplayName, req.Status); err != nil {
			return err
		}
		// Disabling a user revokes their sessions immediately.
		if req.Status == "disabled" {
			if err := h.Sessions.RevokeAllForUser(ctx, tx, id, nil); err != nil {
				return err
			}
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.user.update", TargetType: "user", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) deleteUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if actorID(r) == id {
		return httpx.ErrBadRequest.WithDetail("不能删除自己的账户")
	}
	if err := h.assertCanManageUser(ctx, actorID(r), id); err != nil {
		return err
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Sessions.RevokeAllForUser(ctx, tx, id, nil); err != nil {
			return err
		}
		if err := h.Repo.SoftDeleteUser(ctx, tx, id); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.user.delete", TargetType: "user", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

type resetPwdReq struct {
	Mode     string `json:"mode"`     // "temp" | "manual"
	Password string `json:"password"` // required when mode == "manual"
}

func (h *Handlers) resetPassword(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	actor := actorID(r)
	if actor == id {
		return httpx.ErrBadRequest.WithDetail("请在个人中心修改自己的密码")
	}
	if err := h.assertCanManageUser(ctx, actor, id); err != nil {
		return err
	}
	if err := h.assertNotSuperAdminTarget(ctx, id); err != nil {
		return err
	}
	var req resetPwdReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}

	passwords := authn.NewPasswordService(h.Hasher, 12, 5)
	var temp string
	password := req.Password
	force := true
	if req.Mode == "manual" {
		if len([]rune(password)) < 12 {
			return httpx.ErrBadRequest.WithDetail("密码至少需要 12 个字符")
		}
		force = false // admin chose this password deliberately
	} else {
		password = crypto.RandomToken(9)
		temp = password
	}

	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := passwords.SetByAdmin(ctx, tx, id, password, force); err != nil {
			return err
		}
		if err := h.Sessions.RevokeAllForUser(ctx, tx, id, nil); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{
			Action: "iam.user.reset_password", TargetType: "user", TargetID: id.String(),
			Metadata: map[string]any{"mode": req.Mode},
		})
	})
	if err != nil {
		return err
	}
	out := map[string]string{"status": "ok"}
	if temp != "" {
		out["temp_password"] = temp
	}
	httpx.JSON(w, r, http.StatusOK, out)
	return nil
}

// getUserAssignments returns the user's direct roles, direct permissions, and groups.
func (h *Handlers) getUserAssignments(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	roles, err := h.Repo.UserDirectRoles(ctx, h.Store.Pool, id)
	if err != nil {
		return err
	}
	perms, err := h.Repo.UserDirectPermissions(ctx, h.Store.Pool, id)
	if err != nil {
		return err
	}
	groups, err := h.Repo.UserGroups(ctx, h.Store.Pool, id)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"roles": roles, "permissions": perms, "groups": groups})
	return nil
}

type idReq struct {
	ID uuid.UUID `json:"id"`
}

func (h *Handlers) addUserRole(w http.ResponseWriter, r *http.Request) error {
	return h.mutateAssignment(w, r, "roles", func(ctx context.Context, tx pgx.Tx, userID, target uuid.UUID, by uuid.UUID) error {
		if err := h.Repo.AddUserRole(ctx, tx, userID, target, by); err != nil {
			return err
		}
		return h.Repo.BumpPermVersion(ctx, tx, userID)
	})
}

func (h *Handlers) removeUserRole(w http.ResponseWriter, r *http.Request) error {
	return h.mutateAssignmentPath(w, r, "roleID", func(ctx context.Context, tx pgx.Tx, userID, target uuid.UUID) error {
		if err := h.Repo.RemoveUserRole(ctx, tx, userID, target); err != nil {
			return err
		}
		return h.Repo.BumpPermVersion(ctx, tx, userID)
	})
}

func (h *Handlers) addUserPermission(w http.ResponseWriter, r *http.Request) error {
	return h.mutateAssignment(w, r, "permissions", func(ctx context.Context, tx pgx.Tx, userID, target, by uuid.UUID) error {
		if err := h.Repo.AddUserPermission(ctx, tx, userID, target, by); err != nil {
			return err
		}
		return h.Repo.BumpPermVersion(ctx, tx, userID)
	})
}

func (h *Handlers) removeUserPermission(w http.ResponseWriter, r *http.Request) error {
	return h.mutateAssignmentPath(w, r, "permID", func(ctx context.Context, tx pgx.Tx, userID, target uuid.UUID) error {
		if err := h.Repo.RemoveUserPermission(ctx, tx, userID, target); err != nil {
			return err
		}
		return h.Repo.BumpPermVersion(ctx, tx, userID)
	})
}

func (h *Handlers) addUserToGroup(w http.ResponseWriter, r *http.Request) error {
	return h.mutateAssignment(w, r, "groups", func(ctx context.Context, tx pgx.Tx, userID, target, by uuid.UUID) error {
		if err := h.Repo.AddGroupMember(ctx, tx, target, userID); err != nil {
			return err
		}
		return h.Repo.BumpPermVersion(ctx, tx, userID)
	})
}

func (h *Handlers) removeUserFromGroup(w http.ResponseWriter, r *http.Request) error {
	return h.mutateAssignmentPath(w, r, "groupID", func(ctx context.Context, tx pgx.Tx, userID, target uuid.UUID) error {
		if err := h.Repo.RemoveGroupMember(ctx, tx, target, userID); err != nil {
			return err
		}
		return h.Repo.BumpPermVersion(ctx, tx, userID)
	})
}

func (h *Handlers) mutateAssignment(w http.ResponseWriter, r *http.Request, kind string, fn func(ctx context.Context, tx pgx.Tx, userID, target, by uuid.UUID) error) error {
	userID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req idReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	by := actorID(r)
	ctx := r.Context()
	if err := h.assertCanManageUser(ctx, by, userID); err != nil {
		return err
	}
	if kind == "roles" {
		if err := h.assertCanGrantRole(ctx, by, req.ID); err != nil {
			return err
		}
		if req.ID == rbac.SuperAdminRole || req.ID == rbac.AdminRole {
			if err := h.Guard.CheckStepUp(ctx); err != nil {
				return err
			}
		}
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := fn(ctx, tx, userID, req.ID, by); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.user.grant." + kind, TargetType: "user", TargetID: userID.String(), Metadata: map[string]any{"target": req.ID.String()}})
	})
	if err != nil {
		return err
	}
	h.afterPermChange(ctx, userID)
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) mutateAssignmentPath(w http.ResponseWriter, r *http.Request, param string, fn func(ctx context.Context, tx pgx.Tx, userID, target uuid.UUID) error) error {
	userID, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	target, err := pathUUID(r, param)
	if err != nil {
		return err
	}
	ctx := r.Context()
	actor := actorID(r)
	if err := h.assertCanManageUser(ctx, actor, userID); err != nil {
		return err
	}
	if param == "roleID" {
		if err := h.assertCanGrantRole(ctx, actor, target); err != nil {
			return err
		}
		if err := h.assertNotLastSuperAdmin(ctx, target); err != nil {
			return err
		}
		if target == rbac.SuperAdminRole || target == rbac.AdminRole {
			if err := h.Guard.CheckStepUp(ctx); err != nil {
				return err
			}
		}
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := fn(ctx, tx, userID, target); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.user.revoke." + param, TargetType: "user", TargetID: userID.String(), Metadata: map[string]any{"target": target.String()}})
	})
	if err != nil {
		return err
	}
	h.afterPermChange(ctx, userID)
	httpx.NoContent(w)
	return nil
}

// afterPermChange invalidates the authz cache for a user (post-commit).
func (h *Handlers) afterPermChange(ctx context.Context, userID uuid.UUID) {
	h.Authz.Invalidate(ctx, userID)
}

func (h *Handlers) startImpersonation(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	target, err := h.Repo.GetUser(r.Context(), h.Store.Pool, id)
	if err != nil {
		return httpx.ErrNotFound
	}
	if err := h.assertCanManageUser(r.Context(), actorID(r), id); err != nil {
		return err
	}
	return h.Auth.Impersonate(w, r, target)
}

func (h *Handlers) stopImpersonation(w http.ResponseWriter, r *http.Request) error {
	return h.Auth.StopImpersonation(w, r)
}
