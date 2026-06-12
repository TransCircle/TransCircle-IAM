package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/authn"
	"github.com/transcircle/iam/internal/avatars"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/rbac"
)

// MountAccount registers /me and self-service account endpoints. me is reachable
// mid-onboarding; account endpoints require full onboarding (Gate).
func (h *Handlers) MountAccount(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(h.RequireAuth)
		r.Method("GET", "/api/v1/me", httpx.Handler(h.handleMe))
		// Avatars are served here (RequireAuth but NOT behind the onboarding Gate)
		// so a user's <img> renders even mid-onboarding.
		r.Method("GET", "/api/v1/avatars/{file}", httpx.Handler(h.handleServeAvatar))
		// Step-up: re-verify MFA within the session for sensitive operations.
		r.Method("GET", "/api/v1/auth/step-up/factors", httpx.Handler(h.handleStepUpFactors))
		r.Method("POST", "/api/v1/auth/step-up/totp", httpx.Handler(h.handleStepUpTOTP))
		r.Method("POST", "/api/v1/auth/step-up/webauthn/begin", httpx.Handler(h.handleStepUpWebAuthnBegin))
		r.Method("POST", "/api/v1/auth/step-up/webauthn/finish", httpx.Handler(h.handleStepUpWebAuthnFinish))
	})
	r.Group(func(r chi.Router) {
		r.Use(h.RequireAuth)
		r.Use(h.Gate)
		r.Method("PATCH", "/api/v1/account/profile", httpx.Handler(h.handleUpdateProfile))
		r.Method("POST", "/api/v1/account/avatar", httpx.Handler(h.handleUploadAvatar))
		r.Method("GET", "/api/v1/account/sessions", httpx.Handler(h.handleMySessions))
		r.Method("DELETE", "/api/v1/account/sessions/{id}", httpx.Handler(h.handleRevokeMySession))
		r.Method("POST", "/api/v1/account/sessions/revoke-others", httpx.Handler(h.handleRevokeOtherSessions))
		r.Method("GET", "/api/v1/account/passkeys", httpx.Handler(h.handleListPasskeys))
		// Removing an MFA factor is sensitive: require a fresh step-up so a stolen
		// session cannot strip the account's second factors. (Enrollment/onboarding
		// only adds factors and is not affected.)
		r.With(h.Guard.RequireStepUp()).Method("DELETE", "/api/v1/account/passkeys/{id}", httpx.Handler(h.handleDeletePasskey))
		// Renaming a passkey only changes a display label, so no step-up.
		r.Method("PATCH", "/api/v1/account/passkeys/{id}", httpx.Handler(h.handleRenamePasskey))
		r.With(h.Guard.RequireStepUp()).Method("DELETE", "/api/v1/account/totp", httpx.Handler(h.handleRemoveTOTP))
	})
}

type meResp struct {
	User           meUser   `json:"user"`
	RequiredAction string   `json:"required_action"`
	MFA            any      `json:"mfa"`
	Permissions    []string `json:"permissions"`
	Roles          []string `json:"roles"`          // system-app role keys held by the caller
	IsSuperAdmin   bool     `json:"is_super_admin"` // convenience flag for UI gating
	// True when the email-lock policy is on and the caller is not a
	// super-admin: this caller may not change any email (own or others').
	EmailChangeDisabled bool     `json:"email_change_disabled"`
	Impersonator        *meActor `json:"impersonator"`
}

type meUser struct {
	ID          uuid.UUID `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	Status      string    `json:"status"`
	AvatarURL   string    `json:"avatar_url"`
}

type meActor struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
}

func (h *Handlers) handleMe(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	p, _ := authctx.From(ctx)
	user, err := h.Repo.GetUser(ctx, h.Store.Pool, p.UserID)
	if err != nil {
		return err
	}
	action, err := h.requiredAction(ctx, user)
	if err != nil {
		return err
	}
	mfa, err := h.MFA.Status(ctx, h.Store.Pool, user.ID)
	if err != nil {
		return err
	}
	perms, err := h.Authz.SystemPermissionSet(ctx, user.ID)
	if err != nil {
		return err
	}
	roles, err := h.Repo.EffectiveRoles(ctx, h.Store.Pool, user.ID, rbac.SystemAppID)
	if err != nil {
		return err
	}
	if roles == nil {
		roles = []string{}
	}
	emailLocked, err := h.Repo.EmailChangeRestricted(ctx, h.Store.Pool)
	if err != nil {
		return err
	}
	isSuper := slices.Contains(roles, rbac.SuperAdminKey)
	resp := meResp{
		User:                meUser{ID: user.ID, Username: user.Username, DisplayName: user.DisplayName, Email: user.Email, Status: user.Status, AvatarURL: user.AvatarURL},
		RequiredAction:      action,
		MFA:                 mfa,
		Permissions:         perms,
		Roles:               roles,
		IsSuperAdmin:        isSuper,
		EmailChangeDisabled: emailLocked && !isSuper,
	}
	if p.ImpersonatorID != uuid.Nil {
		resp.Impersonator = &meActor{ID: p.ImpersonatorID, Username: p.ImpersonatorLabel}
	}
	httpx.JSON(w, r, http.StatusOK, resp)
	return nil
}

type updateProfileReq struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// handleUpdateProfile lets a user edit their own email and display name. The
// email is free-form (no SMTP verification); the username is immutable.
func (h *Handlers) handleUpdateProfile(w http.ResponseWriter, r *http.Request) error {
	var req updateProfileReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if len([]rune(req.DisplayName)) > 64 || len(req.Email) > 254 {
		return httpx.ErrBadRequest.WithDetail("显示名或邮箱过长")
	}
	p, _ := authctx.From(r.Context())
	ctx := r.Context()
	err := h.Store.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// Email-lock policy: when enabled, only a super-admin may change an
		// email — everyone else may still edit their display name (email must
		// stay as-is). Checked inside the writing tx under the shared policy
		// lock so a concurrent policy flip cannot race an email change through.
		if err := h.Repo.LockPolicyShared(ctx, tx); err != nil {
			return err
		}
		locked, err := h.Repo.EmailChangeRestricted(ctx, tx)
		if err != nil {
			return err
		}
		if locked {
			u, err := h.Repo.GetUser(ctx, tx, p.UserID)
			if err != nil {
				return err
			}
			if req.Email != u.Email {
				roles, err := h.Repo.EffectiveRoles(ctx, tx, p.UserID, rbac.SystemAppID)
				if err != nil {
					return err
				}
				if !slices.Contains(roles, rbac.SuperAdminKey) {
					return httpx.ErrForbidden.WithDetail("邮箱修改已被管理员锁定，如需变更请联系超级管理员")
				}
			}
		}
		if err := h.Repo.UpdateSelfProfile(ctx, tx, p.UserID, req.Email, req.DisplayName); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "account.profile.update", TargetType: "user", TargetID: p.UserID.String(), TargetLabel: p.Username})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

// handleUploadAvatar stores a self-uploaded avatar (multipart field "avatar").
func (h *Handlers) handleUploadAvatar(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	url, err := avatars.SaveUpload(w, r, h.Cfg.DataDir)
	if err != nil {
		return avatarUploadError(err)
	}
	var old string
	if u, gerr := h.Repo.GetUser(r.Context(), h.Store.Pool, p.UserID); gerr == nil {
		old = u.AvatarURL
	}
	err = h.Store.WithTx(r.Context(), func(ctx context.Context, tx pgx.Tx) error {
		if serr := h.Repo.SetUserAvatar(ctx, tx, p.UserID, url); serr != nil {
			return serr
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "account.avatar.update", TargetType: "user", TargetID: p.UserID.String(), TargetLabel: p.Username})
	})
	if err != nil {
		avatars.Remove(h.Cfg.DataDir, url) // the DB write failed; drop the orphan file
		return err
	}
	if old != "" && old != url {
		avatars.Remove(h.Cfg.DataDir, old)
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"avatar_url": url})
	return nil
}

// avatarUploadError maps an avatars sentinel error to an HTTP problem. Shared
// shape used by both the self (account) and admin (api) avatar handlers.
func avatarUploadError(err error) error {
	switch {
	case errors.Is(err, avatars.ErrTooLarge):
		return httpx.NewError(http.StatusRequestEntityTooLarge, "payload_too_large", "头像不能超过 2MB")
	case errors.Is(err, avatars.ErrUnsupportedType):
		return httpx.NewError(http.StatusUnsupportedMediaType, "unsupported_media_type", "仅支持 PNG/JPEG/WebP 图片")
	case errors.Is(err, avatars.ErrNoFile):
		return httpx.ErrBadRequest.WithDetail("缺少头像文件")
	default:
		return err
	}
}

func (h *Handlers) handleServeAvatar(w http.ResponseWriter, r *http.Request) error {
	if !avatars.ServeFile(w, r, h.Cfg.DataDir, chi.URLParam(r, "file")) {
		return httpx.ErrNotFound
	}
	return nil
}

// handleServeUserAvatar serves a user's CURRENT avatar by user id. This URL is
// stable (the OIDC `picture` claim) and public so OAuth/OIDC clients can fetch
// it without an IAM session. 404 when the user has no avatar so the relying
// party can fall back to its own placeholder.
func (h *Handlers) handleServeUserAvatar(w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		return httpx.ErrNotFound
	}
	u, err := h.Repo.GetUser(r.Context(), h.Store.Pool, id)
	if err != nil {
		return httpx.ErrNotFound
	}
	if !avatars.ServeCurrent(w, r, h.Cfg.DataDir, u.AvatarURL) {
		return httpx.ErrNotFound
	}
	return nil
}

func (h *Handlers) handleMySessions(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	list, err := h.Sessions.ListForUser(r.Context(), p.UserID)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"sessions": list, "current": p.SessionID})
	return nil
}

func (h *Handlers) handleRevokeMySession(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return httpx.ErrBadRequest
	}
	// Ensure the target session belongs to the caller.
	list, err := h.Sessions.ListForUser(r.Context(), p.UserID)
	if err != nil {
		return err
	}
	owned := false
	for _, s := range list {
		if s.ID == id {
			owned = true
			break
		}
	}
	if !owned {
		return httpx.ErrNotFound
	}
	err = h.Store.WithTx(r.Context(), func(ctx context.Context, tx pgx.Tx) error {
		return h.Sessions.Revoke(ctx, tx, id)
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	cur := p.SessionID
	err := h.Store.WithTx(r.Context(), func(ctx context.Context, tx pgx.Tx) error {
		return h.Sessions.RevokeAllForUser(ctx, tx, p.UserID, &cur)
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) handleListPasskeys(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	list, err := h.WebAuthn.ListCredentials(r.Context(), p.UserID)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"passkeys": list})
	return nil
}

func (h *Handlers) handleDeletePasskey(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return httpx.ErrBadRequest
	}
	err = h.Store.WithTx(r.Context(), func(ctx context.Context, tx pgx.Tx) error {
		if derr := h.WebAuthn.DeleteCredential(ctx, tx, p.UserID, id); derr != nil {
			return derr
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "mfa.webauthn.delete", TargetType: "user", TargetID: p.UserID.String(), TargetLabel: p.Username})
	})
	if err != nil {
		if errors.Is(err, authn.ErrCredentialNotFound) {
			return httpx.ErrNotFound.WithDetail("通行密钥不存在")
		}
		return err
	}
	httpx.NoContent(w)
	return nil
}

type renamePasskeyReq struct {
	Name string `json:"name"`
}

// handleRenamePasskey updates a passkey's display name (owner-scoped).
func (h *Handlers) handleRenamePasskey(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return httpx.ErrBadRequest
	}
	var req renamePasskeyReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len([]rune(name)) > 64 {
		return httpx.ErrBadRequest.WithDetail("名称需为 1-64 个字符")
	}
	err = h.Store.WithTx(r.Context(), func(ctx context.Context, tx pgx.Tx) error {
		if rerr := h.WebAuthn.RenameCredential(ctx, tx, p.UserID, id, name); rerr != nil {
			return rerr
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "mfa.webauthn.rename", TargetType: "user", TargetID: p.UserID.String(), TargetLabel: p.Username})
	})
	if err != nil {
		if errors.Is(err, authn.ErrCredentialNotFound) {
			return httpx.ErrNotFound.WithDetail("通行密钥不存在")
		}
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) handleRemoveTOTP(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	err := h.Store.WithTx(r.Context(), func(ctx context.Context, tx pgx.Tx) error {
		if derr := h.TOTP.Remove(ctx, tx, p.UserID); derr != nil {
			return derr
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "mfa.totp.delete", TargetType: "user", TargetID: p.UserID.String(), TargetLabel: p.Username})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}
