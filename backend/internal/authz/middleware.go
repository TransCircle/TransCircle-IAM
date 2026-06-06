package authz

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/httpx"
)

// Guard builds permission-checking middleware bound to the authz service.
type Guard struct {
	svc      *Service
	stepUpFn func() time.Duration
}

// NewGuard creates a guard. stepUpWindow is how recently MFA must have occurred
// for step-up-protected routes.
func NewGuard(svc *Service, stepUpWindow time.Duration) *Guard {
	return &Guard{svc: svc, stepUpFn: func() time.Duration { return stepUpWindow }}
}

// RequirePermission denies the request unless the user holds the system permission.
// The guard fails closed: any resolution error results in denial, never allow.
func (g *Guard) RequirePermission(permKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := authctx.From(r.Context())
			if !ok || p.UserID == uuid.Nil {
				httpx.Error(w, r, httpx.ErrUnauthorized)
				return
			}
			if p.IsMachine {
				// Machine tokens cannot access admin endpoints.
				httpx.Error(w, r, httpx.ErrForbidden.WithDetail("机器令牌不可访问管理接口"))
				return
			}
			allowed, err := g.svc.HasSystem(r.Context(), p.UserID, permKey)
			if err != nil {
				httpx.Error(w, r, httpx.ErrForbidden.WithDetail("权限校验失败").WithInternal(err))
				return
			}
			if !allowed {
				httpx.Error(w, r, httpx.ErrForbidden.WithDetail("缺少权限: "+permKey))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ErrStepUpRequired is the canonical "re-verify MFA" error (HTTP 403,
// code "step_up_required") that the frontend interceptor watches for.
func ErrStepUpRequired() *httpx.AppError {
	return httpx.NewError(http.StatusForbidden, "step_up_required", "需要重新进行多因素验证")
}

// CheckStepUp returns ErrStepUpRequired unless the principal's MFA was satisfied
// within the step-up window. Use this for conditional, in-handler step-up (e.g.
// only when granting a privileged role).
func (g *Guard) CheckStepUp(ctx context.Context) error {
	p, ok := authctx.From(ctx)
	if !ok || p.UserID == uuid.Nil {
		return httpx.ErrUnauthorized
	}
	if p.MFAAt.IsZero() || time.Since(p.MFAAt) > g.stepUpFn() {
		return ErrStepUpRequired()
	}
	return nil
}

// RequireStepUp denies the request unless MFA was satisfied within the step-up
// window (for sensitive operations such as secret rotation or impersonation).
func (g *Guard) RequireStepUp() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := g.CheckStepUp(r.Context()); err != nil {
				httpx.Error(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
