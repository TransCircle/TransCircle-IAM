package auth

import (
	"net/http"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/authn"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/mfaverify"
)

// These endpoints back the hosted page at /verify/{id}: an end user, logged into
// the IAM, completes a TOTP or passkey check that an application requested via
// the machine API. They verify the CURRENT session user's own factors. The app
// reads the result back through the machine endpoint.

// loadVerification fetches the record and enforces the optional user pin: when
// the app pinned a specific user, the logged-in session must belong to them.
func (h *Handlers) loadVerification(r *http.Request, p *authctx.Principal) (*mfaverify.Record, error) {
	id := chi.URLParam(r, "id")
	rec, err := mfaverify.Get(r.Context(), h.Store.Redis, id)
	if err != nil {
		return nil, httpx.ErrNotFound.WithDetail("验证请求不存在或已过期")
	}
	return rec, nil
}

func (h *Handlers) verificationMismatch(rec *mfaverify.Record, p *authctx.Principal) bool {
	return rec.RequireUserID != "" && rec.RequireUserID != p.UserID.String()
}

func factorAllowed(rec *mfaverify.Record, factor string) bool {
	return len(rec.AllowedFactors) == 0 || slices.Contains(rec.AllowedFactors, factor)
}

// handleVerifyInfo describes a verification request to the hosted page.
func (h *Handlers) handleVerifyInfo(w http.ResponseWriter, r *http.Request) error {
	p, _ := authctx.From(r.Context())
	rec, err := h.loadVerification(r, p)
	if err != nil {
		return err
	}
	st, err := h.MFA.Status(r.Context(), h.Store.Pool, p.UserID)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"status":          rec.Status,
		"requested_by":    rec.RequestedBy,
		"allowed_factors": rec.AllowedFactors,
		"require_label":   rec.RequireUserLabel,
		"mismatch":        h.verificationMismatch(rec, p),
		"has_redirect":    rec.RedirectURI != "",
		"current_user":    p.Username,
		"factors":         map[string]any{"totp": st.TOTP, "passkeys": st.Passkeys},
	})
	return nil
}

// markVerified stamps the record as completed by the current user, single-use
// and atomically, then audits it. A verification can be claimed exactly once: a
// later attempt by a different user never overwrites the authoritative result.
func (h *Handlers) markVerified(w http.ResponseWriter, r *http.Request, rec *mfaverify.Record, p *authctx.Principal, factor string) error {
	ctx := r.Context()
	now := time.Now()
	rec.Status = mfaverify.StatusVerified
	rec.UserID = p.UserID.String()
	rec.Username = p.Username
	rec.Factor = factor
	rec.VerifiedAt = &now
	res, err := mfaverify.Complete(ctx, h.Store.Redis, rec)
	if err != nil {
		return err
	}
	switch res {
	case mfaverify.CompleteExpired:
		return httpx.ErrNotFound.WithDetail("验证请求不存在或已过期")
	case mfaverify.CompleteAlready:
		// Single-use. Treat a repeat by the SAME user as idempotent success;
		// otherwise refuse so we never override the recorded result.
		if existing, gerr := mfaverify.Get(ctx, h.Store.Redis, rec.ID); gerr == nil && existing.UserID == p.UserID.String() {
			httpx.JSON(w, r, http.StatusOK, map[string]any{"status": "verified", "redirect_uri": existing.RedirectURI})
			return nil
		}
		return httpx.NewError(http.StatusConflict, "already_verified", "该验证请求已被完成")
	}
	h.Audit.Log(ctx, audit.Event{
		Action: "mfa.verify.success", Result: audit.ResultSuccess,
		TargetType: "mfa_verification", TargetID: rec.ID, TargetLabel: rec.RequestedBy,
		Metadata: map[string]any{"factor": factor},
	})
	httpx.JSON(w, r, http.StatusOK, map[string]any{"status": "verified", "redirect_uri": rec.RedirectURI})
	return nil
}

func (h *Handlers) handleVerifyTOTP(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Code string `json:"code"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	p, _ := authctx.From(ctx)
	rec, err := h.loadVerification(r, p)
	if err != nil {
		return err
	}
	if h.verificationMismatch(rec, p) {
		return httpx.ErrForbidden.WithDetail("当前登录账号与请求验证的账号不一致，请切换账号后重试")
	}
	if !factorAllowed(rec, "totp") {
		return httpx.ErrForbidden.WithDetail("该验证请求不接受动态口令")
	}
	// Same anti-brute-force lockout family as login/step-up.
	if locked, _ := h.Lockout.Locked(ctx, mfaLockKeys(ctx, p.UserID)...); locked {
		return mfaLockedErr()
	}
	ok, err := h.TOTP.Verify(ctx, h.Store, p.UserID, req.Code)
	if err != nil {
		return err
	}
	if !ok {
		h.Lockout.RecordFailure(ctx, mfaLockKeys(ctx, p.UserID)...)
		return httpx.NewError(http.StatusUnauthorized, "invalid_code", "验证码错误")
	}
	h.Lockout.Reset(ctx, mfaLockKeys(ctx, p.UserID)...)
	return h.markVerified(w, r, rec, p, "totp")
}

func (h *Handlers) handleVerifyWebAuthnBegin(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	p, _ := authctx.From(ctx)
	rec, err := h.loadVerification(r, p)
	if err != nil {
		return err
	}
	if h.verificationMismatch(rec, p) {
		return httpx.ErrForbidden.WithDetail("当前登录账号与请求验证的账号不一致，请切换账号后重试")
	}
	if !factorAllowed(rec, "passkey") {
		return httpx.ErrForbidden.WithDetail("该验证请求不接受通行密钥")
	}
	opts, ticket, err := h.WebAuthn.BeginLogin(ctx, authn.UserInfo{ID: p.UserID, Username: p.Username, DisplayName: p.Username})
	if err != nil {
		return httpx.ErrBadRequest.WithDetail(err.Error())
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"options": opts.Response, "wa_ticket": ticket})
	return nil
}

func (h *Handlers) handleVerifyWebAuthnFinish(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	p, _ := authctx.From(ctx)
	rec, err := h.loadVerification(r, p)
	if err != nil {
		return err
	}
	if h.verificationMismatch(rec, p) {
		return httpx.ErrForbidden.WithDetail("当前登录账号与请求验证的账号不一致，请切换账号后重试")
	}
	if !factorAllowed(rec, "passkey") {
		return httpx.ErrForbidden.WithDetail("该验证请求不接受通行密钥")
	}
	waT := r.URL.Query().Get("wt")
	if err := h.WebAuthn.FinishLogin(ctx, authn.UserInfo{ID: p.UserID, Username: p.Username, DisplayName: p.Username}, waT, r); err != nil {
		return httpx.NewError(http.StatusUnauthorized, "invalid_assertion", "通行密钥验证失败")
	}
	return h.markVerified(w, r, rec, p, "passkey")
}
