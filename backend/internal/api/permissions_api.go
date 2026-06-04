package api

import (
	"net/http"
	"slices"

	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/httpx"
)

// handlePermissionsAPI is the external machine-facing endpoint that returns a
// user's effective roles + permissions in an application. Access is scoped to the
// token's allowed_app_keys (least privilege, must-fix #15).
//
//	GET /api/v1/permissions?user=<uuid|username>&app=<app_key>
func (h *Handlers) handlePermissionsAPI(w http.ResponseWriter, r *http.Request) error {
	p, ok := authctx.From(r.Context())
	if !ok || !p.IsMachine {
		return httpx.ErrUnauthorized
	}
	// The token must explicitly carry the permissions-read scope.
	if !slices.Contains(p.TokenScopes, "iam.permissions.read") {
		return httpx.ErrForbidden.WithDetail("令牌缺少 iam.permissions.read 作用域")
	}
	ctx := r.Context()
	appKey := r.URL.Query().Get("app")
	if appKey == "" {
		return httpx.ErrBadRequest.WithDetail("缺少 app 参数")
	}
	// Enforce per-token app allowlist.
	if len(p.AllowedApps) > 0 && !slices.Contains(p.AllowedApps, appKey) {
		return httpx.ErrForbidden.WithDetail("令牌无权访问该应用")
	}

	userParam := r.URL.Query().Get("user")
	if userParam == "" {
		return httpx.ErrBadRequest.WithDetail("缺少 user 参数")
	}
	var userID uuid.UUID
	if id, err := uuid.Parse(userParam); err == nil {
		userID = id
	} else {
		u, err := h.Repo.GetUserByUsername(ctx, h.Store.Pool, userParam)
		if err != nil {
			return httpx.ErrNotFound.WithDetail("用户不存在")
		}
		userID = u.ID
	}

	// Resolve the application id from its key.
	apps, err := h.Repo.ListApplications(ctx, h.Store.Pool)
	if err != nil {
		return err
	}
	var appID uuid.UUID
	for _, a := range apps {
		if a.Key == appKey {
			appID = a.ID
			break
		}
	}
	if appID == uuid.Nil {
		return httpx.ErrNotFound.WithDetail("应用不存在")
	}

	ap, err := h.Authz.AppPermissions(ctx, userID, appID, appKey)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, ap)
	return nil
}
