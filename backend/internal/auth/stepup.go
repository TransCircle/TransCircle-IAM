package auth

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/authn"
	"github.com/transcircle/iam/internal/httpx"
)

// Step-up re-verifies MFA inside an already-authenticated session and refreshes
// the session's mfa_satisfied_at, so RequireStepUp-guarded operations can be
// performed again without logging out. Recovery codes are intentionally excluded.

// stepUpIdentity returns the user whose credentials must satisfy a step-up.
//
// In an impersonation session the verifying party is the ADMIN behind the
// session, never the user being impersonated: a sensitive operation performed
// while acting as someone else is the admin's own responsibility and must be
// authorized with the admin's own second factor (and rate-limited under the
// admin's lockout family). Outside impersonation it is simply the session user.
func stepUpIdentity(p *authctx.Principal) (uuid.UUID, string) {
	if p.Impersonating() {
		return p.ImpersonatorID, p.ImpersonatorLabel
	}
	return p.UserID, p.Username
}

func (h *Handlers) handleStepUpFactors(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	vid, _ := stepUpIdentity(p)
	st, err := h.MFA.Status(r.Context(), h.Store.Pool, vid)
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
	vid, vname := stepUpIdentity(p)
	// Step-up runs inside an authenticated session, so without its own lockout
	// a stolen-but-stale session could brute-force TOTP to unlock every
	// step-up-gated action. Same counter family as the login second factor.
	if locked, _ := h.Lockout.Locked(ctx, mfaLockKeys(ctx, vid)...); locked {
		h.Audit.Log(ctx, audit.Event{Action: "auth.stepup_locked", Result: audit.ResultDenied, ActorLabel: vname})
		return mfaLockedErr()
	}
	ok, err := h.TOTP.Verify(ctx, h.Store, vid, req.Code)
	if err != nil {
		return err
	}
	if !ok {
		h.Lockout.RecordFailure(ctx, mfaLockKeys(ctx, vid)...)
		h.Audit.Log(ctx, audit.Event{Action: "auth.stepup_failure", Result: audit.ResultFailure, ActorLabel: vname, Metadata: map[string]any{"factor": "totp"}})
		return httpx.NewError(http.StatusUnauthorized, "invalid_code", "验证码错误")
	}
	h.Lockout.Reset(ctx, mfaLockKeys(ctx, vid)...)
	return h.completeStepUp(w, r, p, "otp")
}

func (h *Handlers) handleStepUpWebAuthnBegin(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	p, _ := authctx.From(ctx)
	vid, vname := stepUpIdentity(p)
	opts, ticket, err := h.WebAuthn.BeginLogin(ctx, authn.UserInfo{ID: vid, Username: vname, DisplayName: vname})
	if err != nil {
		return httpx.ErrBadRequest.WithDetail(err.Error())
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"options": opts.Response, "wa_ticket": ticket})
	return nil
}

func (h *Handlers) handleStepUpWebAuthnFinish(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	p, _ := authctx.From(ctx)
	vid, vname := stepUpIdentity(p)
	waT := r.URL.Query().Get("wt")
	if err := h.WebAuthn.FinishLogin(ctx, authn.UserInfo{ID: vid, Username: vname, DisplayName: vname}, waT, r); err != nil {
		return httpx.NewError(http.StatusUnauthorized, "invalid_assertion", "通行密钥验证失败")
	}
	return h.completeStepUp(w, r, p, "webauthn")
}

// completeStepUp refreshes the session's MFA freshness, audits it, and responds.
func (h *Handlers) completeStepUp(w http.ResponseWriter, r *http.Request, p *authctx.Principal, factor string) error {
	ctx := r.Context()
	vid, vname := stepUpIdentity(p)
	err := h.Store.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Sessions.MarkMFASatisfied(ctx, tx, p.SessionID, factor, 2); err != nil {
			return err
		}
		meta := map[string]any{"factor": factor}
		if p.Impersonating() {
			// Record that the admin (not the impersonated user) cleared the step-up.
			meta["verified_by"] = vname
		}
		return h.Audit.Write(ctx, tx, audit.Event{
			Action: "auth.stepup", TargetType: "user", TargetID: vid.String(), TargetLabel: vname,
			Metadata: meta,
		})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}
