package auth

import (
	"context"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/rbac"
)

// MountAccount registers /me and self-service account endpoints. me is reachable
// mid-onboarding; account endpoints require full onboarding (Gate).
func (h *Handlers) MountAccount(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(h.RequireAuth)
		r.Method("GET", "/api/v1/me", httpx.Handler(h.handleMe))
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
		r.Method("GET", "/api/v1/account/sessions", httpx.Handler(h.handleMySessions))
		r.Method("DELETE", "/api/v1/account/sessions/{id}", httpx.Handler(h.handleRevokeMySession))
		r.Method("POST", "/api/v1/account/sessions/revoke-others", httpx.Handler(h.handleRevokeOtherSessions))
		r.Method("GET", "/api/v1/account/passkeys", httpx.Handler(h.handleListPasskeys))
		r.Method("DELETE", "/api/v1/account/passkeys/{id}", httpx.Handler(h.handleDeletePasskey))
		r.Method("DELETE", "/api/v1/account/totp", httpx.Handler(h.handleRemoveTOTP))
	})
}

type meResp struct {
	User           meUser   `json:"user"`
	RequiredAction string   `json:"required_action"`
	MFA            any      `json:"mfa"`
	Permissions    []string `json:"permissions"`
	Roles          []string `json:"roles"`          // system-app role keys held by the caller
	IsSuperAdmin   bool     `json:"is_super_admin"` // convenience flag for UI gating
	Impersonator   *meActor `json:"impersonator"`
}

type meUser struct {
	ID          uuid.UUID `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	Status      string    `json:"status"`
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
	resp := meResp{
		User:           meUser{ID: user.ID, Username: user.Username, DisplayName: user.DisplayName, Email: user.Email, Status: user.Status},
		RequiredAction: action,
		MFA:            mfa,
		Permissions:    perms,
		Roles:          roles,
		IsSuperAdmin:   slices.Contains(roles, rbac.SuperAdminKey),
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
