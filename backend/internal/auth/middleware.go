package auth

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/rbac"
)

type userCtxKey struct{}

// UserFrom returns the fully-loaded user attached by SessionMiddleware.
func UserFrom(ctx context.Context) (*rbac.User, bool) {
	u, ok := ctx.Value(userCtxKey{}).(*rbac.User)
	return u, ok
}

// SessionMiddleware resolves the session cookie into a principal + loaded user.
// It never rejects; downstream guards enforce authentication.
func (h *Handlers) SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := h.Cookies.Get(r, h.Cfg.SessionCookie)
		if raw == "" {
			next.ServeHTTP(w, r)
			return
		}
		sid, err := uuid.Parse(raw)
		if err != nil {
			h.Cookies.Clear(w, h.Cfg.SessionCookie)
			next.ServeHTTP(w, r)
			return
		}
		sess, err := h.Sessions.Resolve(r.Context(), sid)
		if err != nil {
			h.Cookies.Clear(w, h.Cfg.SessionCookie)
			next.ServeHTTP(w, r)
			return
		}
		user, err := h.Repo.GetUser(r.Context(), h.Store.Pool, sess.UserID)
		if err != nil || !user.IsActive {
			h.Cookies.Clear(w, h.Cfg.SessionCookie)
			next.ServeHTTP(w, r)
			return
		}
		p := &authctx.Principal{
			UserID:       user.ID,
			SessionID:    sess.ID,
			Username:     user.Username,
			AAL:          sess.AAL,
			MFASatisfied: sess.MFASatisfied,
			AuthAt:       sess.CreatedAt,
			AMR:          sess.AMR,
		}
		if sess.MFAAt != nil {
			p.MFAAt = *sess.MFAAt
		}
		if sess.ImpersonatorID != nil {
			p.ImpersonatorID = *sess.ImpersonatorID
			if imp, ierr := h.Repo.GetUser(r.Context(), h.Store.Pool, *sess.ImpersonatorID); ierr == nil {
				p.ImpersonatorLabel = imp.Username
			}
		}
		ctx := authctx.With(r.Context(), p)
		ctx = context.WithValue(ctx, userCtxKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAuth rejects unauthenticated requests.
func (h *Handlers) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authctx.From(r.Context()); !ok {
			httpx.Error(w, r, httpx.ErrUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Gate enforces onboarding completion (password change + MFA enrollment) before
// allowing access to business/admin endpoints. Onboarding endpoints and /me are
// mounted outside this gate.
func (h *Handlers) Gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFrom(r.Context())
		if !ok {
			httpx.Error(w, r, httpx.ErrUnauthorized)
			return
		}
		action, err := h.requiredAction(r.Context(), user)
		if err != nil {
			httpx.Error(w, r, httpx.ErrInternal.WithInternal(err))
			return
		}
		if action != "none" {
			e := httpx.NewError(http.StatusForbidden, "onboarding_required", "请先完成账户初始化")
			e.Fields = map[string]any{"required_action": action}
			httpx.Error(w, r, e)
			return
		}
		next.ServeHTTP(w, r)
	})
}
