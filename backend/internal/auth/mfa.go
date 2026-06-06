package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/authn"
	"github.com/transcircle/iam/internal/httpx"
)

func (h *Handlers) peekTicket(ctx context.Context, t string) (*loginTicket, error) {
	raw, err := h.Store.Redis.Get(ctx, ticketKey(t)).Bytes()
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

// completeMFALogin establishes a session after a successful second factor.
func (h *Handlers) completeMFALogin(w http.ResponseWriter, r *http.Request, lt *loginTicket, factor string) error {
	ctx := r.Context()
	user, err := h.Repo.GetUser(ctx, h.Store.Pool, lt.UserID)
	if err != nil {
		return err
	}
	// Recovery codes authenticate the session but must NOT satisfy step-up.
	sess, err := h.establishSession(ctx, user, httpx.ClientIP(ctx), httpx.UserAgent(ctx), []string{"pwd", factor}, 2, true, factor != "recovery", nil)
	if err != nil {
		return err
	}
	h.Store.Redis.Del(ctx, ticketKey(lt.Username)) // best-effort cleanup
	h.setSessionCookie(w, sess.ID)
	action, err := h.requiredAction(ctx, user)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, loginResp{Status: "ok", RequiredAction: action})
	return nil
}

type mfaCodeReq struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

func (h *Handlers) handleLoginTOTP(w http.ResponseWriter, r *http.Request) error {
	var req mfaCodeReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	lt, err := h.takeTicket(ctx, req.Ticket)
	if err != nil {
		return err
	}
	ok, err := h.TOTP.Verify(ctx, h.Store, lt.UserID, req.Code)
	if err != nil {
		return err
	}
	if !ok {
		h.Audit.Log(ctx, audit.Event{Action: "login.mfa_failure", Result: audit.ResultFailure, ActorLabel: lt.Username, Metadata: map[string]any{"factor": "totp"}})
		return httpx.NewError(http.StatusUnauthorized, "invalid_code", "验证码错误")
	}
	return h.completeMFALogin(w, r, lt, "otp")
}

func (h *Handlers) handleLoginRecovery(w http.ResponseWriter, r *http.Request) error {
	var req mfaCodeReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	lt, err := h.takeTicket(ctx, req.Ticket)
	if err != nil {
		return err
	}
	used, err := h.Recovery.Consume(ctx, h.Store, lt.UserID, req.Code)
	if err != nil {
		return err
	}
	if !used {
		h.Audit.Log(ctx, audit.Event{Action: "login.mfa_failure", Result: audit.ResultFailure, ActorLabel: lt.Username, Metadata: map[string]any{"factor": "recovery"}})
		return httpx.NewError(http.StatusUnauthorized, "invalid_code", "恢复码无效或已被使用")
	}
	return h.completeMFALogin(w, r, lt, "recovery")
}

func (h *Handlers) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Ticket string `json:"ticket"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	lt, err := h.peekTicket(ctx, req.Ticket)
	if err != nil {
		return err
	}
	opts, waTicket, err := h.WebAuthn.BeginLogin(ctx, authn.UserInfo{ID: lt.UserID, Username: lt.Username, DisplayName: lt.DisplayName})
	if err != nil {
		return httpx.ErrBadRequest.WithDetail(err.Error())
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"options": opts.Response, "wa_ticket": waTicket})
	return nil
}

func (h *Handlers) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	loginT := r.URL.Query().Get("lt")
	waT := r.URL.Query().Get("wt")
	lt, err := h.takeTicket(ctx, loginT)
	if err != nil {
		return err
	}
	if err := h.WebAuthn.FinishLogin(ctx, authn.UserInfo{ID: lt.UserID, Username: lt.Username, DisplayName: lt.DisplayName}, waT, r); err != nil {
		h.Audit.Log(ctx, audit.Event{Action: "login.mfa_failure", Result: audit.ResultFailure, ActorLabel: lt.Username, Metadata: map[string]any{"factor": "webauthn"}})
		return httpx.NewError(http.StatusUnauthorized, "invalid_assertion", "通行密钥验证失败")
	}
	return h.completeMFALogin(w, r, lt, "webauthn")
}

// ----- Enrollment (authenticated, during or after onboarding) -----

func (h *Handlers) handleTOTPEnrollBegin(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	ctx := r.Context()
	var url string
	err := h.Store.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		u, err := h.TOTP.BeginEnroll(ctx, tx, p.UserID, p.Username)
		url = u
		return err
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"otpauth_url": url})
	return nil
}

func (h *Handlers) handleTOTPEnrollFinish(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Code string `json:"code"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	p, _ := authctx.From(r.Context())
	ctx := r.Context()
	err := h.Store.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.TOTP.ConfirmEnroll(ctx, tx, p.UserID, req.Code); err != nil {
			return httpx.ErrBadRequest.WithDetail(err.Error())
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET must_enroll_mfa=false WHERE id=$1`, p.UserID); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "mfa.totp.enroll", TargetType: "user", TargetID: p.UserID.String(), TargetLabel: p.Username})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

func (h *Handlers) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	ctx := r.Context()
	opts, waTicket, err := h.WebAuthn.BeginRegistration(ctx, authn.UserInfo{ID: p.UserID, Username: p.Username, DisplayName: p.Username})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"options": opts.Response, "wa_ticket": waTicket})
	return nil
}

func (h *Handlers) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	ctx := r.Context()
	waT := r.URL.Query().Get("wt")
	name := r.URL.Query().Get("name")
	err := h.Store.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.WebAuthn.FinishRegistration(ctx, tx, authn.UserInfo{ID: p.UserID, Username: p.Username, DisplayName: p.Username}, waT, name, r); err != nil {
			return httpx.ErrBadRequest.WithDetail(err.Error())
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET must_enroll_mfa=false WHERE id=$1`, p.UserID); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "mfa.webauthn.register", TargetType: "user", TargetID: p.UserID.String(), TargetLabel: p.Username})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

func (h *Handlers) handleGenerateRecovery(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	ctx := r.Context()
	var codes []string
	err := h.Store.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		c, err := h.Recovery.Generate(ctx, tx, p.UserID, 10)
		if err != nil {
			return err
		}
		codes = c
		return h.Audit.Write(ctx, tx, audit.Event{Action: "mfa.recovery.generate", TargetType: "user", TargetID: p.UserID.String(), TargetLabel: p.Username})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"codes": codes})
	return nil
}
