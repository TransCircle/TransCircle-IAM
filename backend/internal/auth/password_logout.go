package auth

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/authn"
	"github.com/transcircle/iam/internal/httpx"
)

type changePwdReq struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *Handlers) handleChangePassword(w http.ResponseWriter, r *http.Request) error {
	var req changePwdReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	p, _ := authctx.From(r.Context())
	ctx := r.Context()

	if err := h.Password.Verify(ctx, h.Store, p.UserID, req.CurrentPassword); err != nil {
		return httpx.NewError(http.StatusUnauthorized, "invalid_credentials", "当前密码错误")
	}
	err := h.Store.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Password.Change(ctx, tx, p.UserID, req.NewPassword); err != nil {
			if errors.Is(err, authn.ErrPasswordPolicy) {
				return httpx.ErrBadRequest.WithDetail(err.Error())
			}
			return err
		}
		// A password change invalidates every other session (a common reason to
		// change it is suspected compromise); keep only the current one.
		if err := h.Sessions.RevokeAllForUser(ctx, tx, p.UserID, &p.SessionID); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "password.change", TargetType: "user", TargetID: p.UserID.String(), TargetLabel: p.Username})
	})
	if err != nil {
		return err
	}
	user, err := h.Repo.GetUser(ctx, h.Store.Pool, p.UserID)
	if err != nil {
		return err
	}
	action, err := h.requiredAction(ctx, user)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok", "required_action": action})
	return nil
}

func (h *Handlers) handleLogout(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	if p, ok := authctx.From(ctx); ok {
		_ = h.Store.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
			if err := h.Sessions.Revoke(ctx, tx, p.SessionID); err != nil {
				return err
			}
			return h.Audit.Write(ctx, tx, audit.Event{Action: "logout", TargetType: "user", TargetID: p.UserID.String(), TargetLabel: p.Username})
		})
	}
	h.Cookies.Clear(w, h.Cfg.SessionCookie)
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}
