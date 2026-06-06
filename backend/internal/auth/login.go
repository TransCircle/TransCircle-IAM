package auth

import (
	"errors"
	"net/http"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/rbac"
)

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResp struct {
	Status         string   `json:"status"` // ok | mfa_required
	Ticket         string   `json:"ticket,omitempty"`
	Methods        []string `json:"methods,omitempty"`
	RequiredAction string   `json:"required_action,omitempty"`
}

// handleLogin verifies credentials and either establishes a session (no MFA
// factor yet) or returns an MFA challenge ticket.
func (h *Handlers) handleLogin(w http.ResponseWriter, r *http.Request) error {
	var req loginReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	ip := httpx.ClientIP(ctx)

	if locked, _ := h.Lockout.Locked(ctx, "ip:"+ip, "user:"+req.Username); locked {
		h.Audit.Log(ctx, audit.Event{Action: "login.locked", Result: audit.ResultDenied, ActorLabel: req.Username})
		return httpx.NewError(http.StatusTooManyRequests, "locked", "尝试过于频繁，账户暂时锁定，请稍后再试")
	}

	user, err := h.Repo.GetUserByUsername(ctx, h.Store.Pool, req.Username)
	if errors.Is(err, rbac.ErrNotFound) {
		// Burn time to equalize timing and avoid user enumeration.
		h.Password.BurnTime(ctx, req.Password)
		h.recordLoginFailure(r, req.Username)
		return invalidCreds()
	}
	if err != nil {
		return err
	}
	if !user.IsActive {
		h.Password.BurnTime(ctx, req.Password)
		h.recordLoginFailure(r, req.Username)
		return invalidCreds()
	}

	if verr := h.Password.Verify(ctx, h.Store, user.ID, req.Password); verr != nil {
		h.recordLoginFailure(r, req.Username)
		return invalidCreds()
	}

	h.Lockout.Reset(ctx, "ip:"+ip, "user:"+req.Username)

	// Does the user have a usable MFA factor?
	st, err := h.MFA.Status(ctx, h.Store.Pool, user.ID)
	if err != nil {
		return err
	}
	if st.HasAny() {
		ticket, err := h.storeTicket(ctx, loginTicket{UserID: user.ID, Username: user.Username, DisplayName: user.DisplayName})
		if err != nil {
			return err
		}
		methods := []string{}
		if st.Passkeys > 0 {
			methods = append(methods, "webauthn")
		}
		if st.TOTP {
			methods = append(methods, "totp")
		}
		if st.RecoveryCodes > 0 {
			methods = append(methods, "recovery")
		}
		httpx.JSON(w, r, http.StatusOK, loginResp{Status: "mfa_required", Ticket: ticket, Methods: methods})
		return nil
	}

	// No MFA factor yet: establish a session; the gate will force enrollment.
	sess, err := h.establishSession(ctx, user, ip, httpx.UserAgent(ctx), []string{"pwd"}, 1, false, false, nil)
	if err != nil {
		return err
	}
	h.setSessionCookie(w, sess.ID)
	action, err := h.requiredAction(ctx, user)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, loginResp{Status: "ok", RequiredAction: action})
	return nil
}

func (h *Handlers) recordLoginFailure(r *http.Request, username string) {
	ctx := r.Context()
	h.Lockout.RecordFailure(ctx, "ip:"+httpx.ClientIP(ctx), "user:"+username)
	h.Audit.Log(ctx, audit.Event{Action: "login.failure", Result: audit.ResultFailure, ActorLabel: username})
}

func invalidCreds() error {
	return httpx.NewError(http.StatusUnauthorized, "invalid_credentials", "用户名或密码错误")
}
