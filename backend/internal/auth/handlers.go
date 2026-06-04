// Package auth implements the login state machine, onboarding gates, session and
// MFA HTTP endpoints, self-service account management, and admin impersonation.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authn"
	"github.com/transcircle/iam/internal/authz"
	"github.com/transcircle/iam/internal/config"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/rbac"
	"github.com/transcircle/iam/internal/sessions"
	"github.com/transcircle/iam/internal/store"
)

// Handlers bundles every dependency the auth endpoints need.
type Handlers struct {
	Cfg      *config.Config
	Store    *store.Store
	Cookies  httpx.Cookies
	Sessions *sessions.Manager
	Password *authn.PasswordService
	TOTP     *authn.TOTPService
	Recovery *authn.RecoveryService
	WebAuthn *authn.WebAuthnService
	Lockout  *authn.Lockout
	MFA      authn.MFA
	Audit    *audit.Writer
	Authz    *authz.Service
	Repo     rbac.Repo
}

// Mount registers the auth + self-service routes. protected wraps routes that
// require an authenticated, fully-onboarded session.
func (h *Handlers) Mount(r chi.Router) {
	r.Route("/api/v1/auth", func(r chi.Router) {
		// Public (pre-session) endpoints.
		r.Method("POST", "/login", httpx.Handler(h.handleLogin))
		r.Method("POST", "/mfa/totp", httpx.Handler(h.handleLoginTOTP))
		r.Method("POST", "/mfa/recovery", httpx.Handler(h.handleLoginRecovery))
		r.Method("POST", "/webauthn/login/begin", httpx.Handler(h.handleWebAuthnLoginBegin))
		r.Method("POST", "/webauthn/login/finish", httpx.Handler(h.handleWebAuthnLoginFinish))
		r.Method("POST", "/logout", httpx.Handler(h.handleLogout))

		// Authenticated (may be mid-onboarding) endpoints.
		r.Group(func(r chi.Router) {
			r.Use(h.RequireAuth)
			r.Method("POST", "/password/change", httpx.Handler(h.handleChangePassword))
			r.Method("POST", "/mfa/totp/enroll/begin", httpx.Handler(h.handleTOTPEnrollBegin))
			r.Method("POST", "/mfa/totp/enroll/finish", httpx.Handler(h.handleTOTPEnrollFinish))
			r.Method("POST", "/webauthn/register/begin", httpx.Handler(h.handleWebAuthnRegisterBegin))
			r.Method("POST", "/webauthn/register/finish", httpx.Handler(h.handleWebAuthnRegisterFinish))
			r.Method("POST", "/recovery/generate", httpx.Handler(h.handleGenerateRecovery))
		})
	})
	h.MountAccount(r)
}

// ----- login ticket (pre-auth state in Redis) -----

type loginTicket struct {
	UserID      uuid.UUID `json:"user_id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
}

func ticketKey(t string) string { return "auth:login:" + t }

func (h *Handlers) storeTicket(ctx context.Context, lt loginTicket) (string, error) {
	t := crypto.RandomToken(18)
	raw, _ := json.Marshal(lt)
	if err := h.Store.Redis.Set(ctx, ticketKey(t), raw, h.Cfg.LoginTicketTTL).Err(); err != nil {
		return "", err
	}
	return t, nil
}

func (h *Handlers) takeTicket(ctx context.Context, t string) (*loginTicket, error) {
	raw, err := h.Store.Redis.GetDel(ctx, ticketKey(t)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, httpx.ErrUnauthorized.WithDetail("登录会话已过期，请重新登录")
	}
	if err != nil {
		return nil, err
	}
	var lt loginTicket
	if err := json.Unmarshal(raw, &lt); err != nil {
		return nil, err
	}
	return &lt, nil
}

// ----- session establishment -----

func (h *Handlers) establishSession(ctx context.Context, user *rbac.User, ip, ua string, amr []string, aal int, mfaSatisfied bool, impersonator *uuid.UUID) (*sessions.Session, error) {
	var sess *sessions.Session
	err := h.Store.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		s, err := h.Sessions.Create(ctx, tx, sessions.CreateParams{
			UserID:         user.ID,
			IP:             ip,
			UserAgent:      ua,
			AMR:            amr,
			AAL:            aal,
			MFASatisfied:   mfaSatisfied,
			ImpersonatorID: impersonator,
		})
		if err != nil {
			return err
		}
		sess = s
		action := "login.success"
		meta := map[string]any{"amr": amr, "aal": aal}
		if impersonator != nil {
			action = "impersonate.start"
			meta["impersonator"] = impersonator.String()
		}
		return h.Audit.Write(ctx, tx, audit.Event{
			Action: action, Result: audit.ResultSuccess,
			TargetType: "user", TargetID: user.ID.String(), TargetLabel: user.Username,
			Metadata: meta,
		})
	})
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (h *Handlers) setSessionCookie(w http.ResponseWriter, sessionID uuid.UUID) {
	h.Cookies.Set(w, h.Cfg.SessionCookie, sessionID.String(), int(h.Cfg.SessionAbsoluteTTL/time.Second))
}

// requiredAction computes the onboarding action the user must complete next.
func (h *Handlers) requiredAction(ctx context.Context, user *rbac.User) (string, error) {
	if user.ForcePasswordChange {
		return "change_password", nil
	}
	if user.MustEnrollMFA {
		st, err := h.MFA.Status(ctx, h.Store.Pool, user.ID)
		if err != nil {
			return "", err
		}
		if !st.HasAny() {
			return "enroll_mfa", nil
		}
	}
	return "none", nil
}
