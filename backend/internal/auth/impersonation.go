package auth

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/authz"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/rbac"
	"github.com/transcircle/iam/internal/sessions"
)

func returnKey(impSession uuid.UUID) string { return "impersonate:return:" + impSession.String() }

// Impersonate starts an admin login-as session for target. The caller must have
// already passed the iam.users.impersonate guard. Enforces the non-escalation
// rule (must-fix #6): the target's effective permissions must be a subset of the
// admin's, unless the admin holds iam.users.impersonate.elevated. Never nestable.
func (h *Handlers) Impersonate(w http.ResponseWriter, r *http.Request, target *rbac.User) error {
	ctx := r.Context()
	admin, _ := authctx.From(ctx)

	if admin.Impersonating() {
		return httpx.ErrForbidden.WithDetail("不可在代登会话中再次代登")
	}
	if target.ID == admin.UserID {
		return httpx.ErrBadRequest.WithDetail("不能代登自己")
	}

	elevated, err := h.Authz.HasSystem(ctx, admin.UserID, authz.PermUsersImpersonateElevated)
	if err != nil {
		return err
	}
	if !elevated {
		allowed, err := h.permissionsSubset(ctx, target.ID, admin.UserID)
		if err != nil {
			return err
		}
		if !allowed {
			h.Audit.Log(ctx, audit.Event{
				Action: "impersonate.denied", Result: audit.ResultDenied,
				TargetType: "user", TargetID: target.ID.String(), TargetLabel: target.Username,
				Metadata: map[string]any{"reason": "would_escalate"},
			})
			return httpx.ErrForbidden.WithDetail("不能代登权限高于自身的用户")
		}
	}

	adminSession := admin.SessionID
	var sess *sessions.Session
	sess, err = h.establishSession(ctx, target, httpx.ClientIP(ctx), httpx.UserAgent(ctx), []string{"impersonation"}, 2, true, true, &admin.UserID)
	if err != nil {
		return err
	}
	// Remember the admin's original session so they can return.
	_ = h.Store.Redis.Set(ctx, returnKey(sess.ID), adminSession.String(), h.Cfg.SessionAbsoluteTTL).Err()
	h.setSessionCookie(w, sess.ID)
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok", "impersonating": target.Username})
	return nil
}

// permissionsSubset reports whether subject's effective permissions are a subset
// of reference's.
func (h *Handlers) permissionsSubset(ctx context.Context, subject, reference uuid.UUID) (bool, error) {
	sub, err := h.Authz.AllPermissions(ctx, subject)
	if err != nil {
		return false, err
	}
	ref, err := h.Authz.AllPermissions(ctx, reference)
	if err != nil {
		return false, err
	}
	refSet := map[string]bool{}
	for app, perms := range ref {
		for _, p := range perms {
			refSet[app+"|"+p] = true
		}
	}
	for app, perms := range sub {
		for _, p := range perms {
			if !refSet[app+"|"+p] {
				return false, nil
			}
		}
	}
	return true, nil
}

// StopImpersonation ends the current login-as session and restores the admin's
// original session if still valid.
func (h *Handlers) StopImpersonation(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	p, ok := authctx.From(ctx)
	if !ok || !p.Impersonating() {
		return httpx.ErrBadRequest.WithDetail("当前不是代登会话")
	}
	adminSessionStr, _ := h.Store.Redis.GetDel(ctx, returnKey(p.SessionID)).Result()

	err := h.Store.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Sessions.Revoke(ctx, tx, p.SessionID); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{
			Action: "impersonate.stop", TargetType: "user", TargetID: p.UserID.String(), TargetLabel: p.Username,
		})
	})
	if err != nil {
		return err
	}

	// Restore admin session cookie if it is still valid.
	if adminSessionStr != "" {
		if adminID, perr := uuid.Parse(adminSessionStr); perr == nil {
			if _, rerr := h.Sessions.Resolve(ctx, adminID); rerr == nil {
				h.setSessionCookie(w, adminID)
				httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "restored"})
				return nil
			}
		}
	}
	h.Cookies.Clear(w, h.Cfg.SessionCookie)
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "logged_out"})
	return nil
}
