package auth

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/authn"
	"github.com/transcircle/iam/internal/httpx"
)

// Step-up re-verifies MFA inside an already-authenticated session and refreshes
// the session's mfa_satisfied_at, so RequireStepUp-guarded operations can be
// performed again without logging out. Recovery codes are intentionally excluded.

func (h *Handlers) handleStepUpFactors(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	st, err := h.MFA.Status(r.Context(), h.Store.Pool, p.UserID)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"totp": st.TOTP, "passkeys": st.Passkeys})
	return nil
}

func (h *Handlers) handleStepUpTOTP(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Code string `json:"code"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	p, _ := authctx.From(ctx)
	// Step-up runs inside an authenticated session, so without its own lockout
	// a stolen-but-stale session could brute-force TOTP to unlock every
	// step-up-gated action. Same counter family as the login second factor.
	if locked, _ := h.Lockout.Locked(ctx, mfaLockKeys(ctx, p.UserID)...); locked {
		h.Audit.Log(ctx, audit.Event{Action: "auth.stepup_locked", Result: audit.ResultDenied, ActorLabel: p.Username})
		return mfaLockedErr()
	}
	ok, err := h.TOTP.Verify(ctx, h.Store, p.UserID, req.Code)
	if err != nil {
		return err
	}
	if !ok {
		h.Lockout.RecordFailure(ctx, mfaLockKeys(ctx, p.UserID)...)
		h.Audit.Log(ctx, audit.Event{Action: "auth.stepup_failure", Result: audit.ResultFailure, ActorLabel: p.Username, Metadata: map[string]any{"factor": "totp"}})
		return httpx.NewError(http.StatusUnauthorized, "invalid_code", "验证码错误")
	}
	h.Lockout.Reset(ctx, mfaLockKeys(ctx, p.UserID)...)
	return h.completeStepUp(w, r, p, "otp")
}

func (h *Handlers) handleStepUpWebAuthnBegin(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	p, _ := authctx.From(ctx)
	opts, ticket, err := h.WebAuthn.BeginLogin(ctx, authn.UserInfo{ID: p.UserID, Username: p.Username, DisplayName: p.Username})
	if err != nil {
		return httpx.ErrBadRequest.WithDetail(err.Error())
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"options": opts.Response, "wa_ticket": ticket})
	return nil
}

func (h *Handlers) handleStepUpWebAuthnFinish(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	p, _ := authctx.From(ctx)
	waT := r.URL.Query().Get("wt")
	if err := h.WebAuthn.FinishLogin(ctx, authn.UserInfo{ID: p.UserID, Username: p.Username, DisplayName: p.Username}, waT, r); err != nil {
		return httpx.NewError(http.StatusUnauthorized, "invalid_assertion", "通行密钥验证失败")
	}
	return h.completeStepUp(w, r, p, "webauthn")
}

// completeStepUp refreshes the session's MFA freshness, audits it, and responds.
func (h *Handlers) completeStepUp(w http.ResponseWriter, r *http.Request, p *authctx.Principal, factor string) error {
	ctx := r.Context()
	err := h.Store.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Sessions.MarkMFASatisfied(ctx, tx, p.SessionID, factor, 2); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{
			Action: "auth.stepup", TargetType: "user", TargetID: p.UserID.String(), TargetLabel: p.Username,
			Metadata: map[string]any{"factor": factor},
		})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}
