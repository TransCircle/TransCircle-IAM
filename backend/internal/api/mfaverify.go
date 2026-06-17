package api

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/mfaverify"
)

const (
	mfaVerifyDefaultTTL = 10 * time.Minute
	mfaVerifyMinTTL     = 60 * time.Second
	mfaVerifyMaxTTL     = 30 * time.Minute
)

// requireMFAVerifyScope guards the standalone verification endpoints: the
// machine principal must carry the iam.mfa.verify scope.
func requireMFAVerifyScope(p *authctx.Principal) error {
	if p == nil || !p.IsMachine {
		return httpx.ErrUnauthorized
	}
	if !slices.Contains(p.TokenScopes, ScopeMFAVerify) {
		return httpx.ErrForbidden.WithDetail("令牌缺少 " + ScopeMFAVerify + " 作用域")
	}
	return nil
}

type createMFAVerifyReq struct {
	// User optionally pins the verification to a specific IAM user (username or
	// UUID). Omit to let any logged-in user complete it.
	User string `json:"user"`
	// RedirectURI optionally sends the browser back to the app after success.
	RedirectURI string `json:"redirect_uri"`
	// Factors optionally limits which factors are accepted ("totp","passkey").
	Factors []string `json:"factors"`
	// TTLSeconds optionally sets the lifetime (clamped to [60, 1800]).
	TTLSeconds int `json:"ttl_seconds"`
}

// createMFAVerification (machine) starts a verification request and returns the
// hosted URL the app should send the user to. POST /api/v1/mfa-verifications
func (h *Handlers) createMFAVerification(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	p, _ := authctx.From(ctx)
	if err := requireMFAVerifyScope(p); err != nil {
		return err
	}
	var req createMFAVerifyReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.RedirectURI != "" {
		if len(req.RedirectURI) > 2048 {
			return httpx.ErrBadRequest.WithDetail("redirect_uri 过长")
		}
		u, perr := url.Parse(req.RedirectURI)
		if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Fragment != "" || u.User != nil {
			return httpx.ErrBadRequest.WithDetail("redirect_uri 必须是合法的 http(s) 绝对地址，且不含片段或用户名信息")
		}
	}
	// Validate the optional factor allowlist.
	var factors []string
	for _, f := range req.Factors {
		f = strings.ToLower(strings.TrimSpace(f))
		if f != "totp" && f != "passkey" {
			return httpx.ErrBadRequest.WithDetail("factors 仅支持 totp 与 passkey")
		}
		if !slices.Contains(factors, f) {
			factors = append(factors, f)
		}
	}

	// Resolve the optional pinned user so the result is unambiguous.
	var requireID, requireLabel string
	if u := strings.TrimSpace(req.User); u != "" {
		requireLabel = u
		var userID uuid.UUID
		if id, perr := uuid.Parse(u); perr == nil {
			userID = id
		} else {
			usr, uerr := h.Repo.GetUserByUsername(ctx, h.Store.Pool, u)
			if uerr != nil {
				return httpx.ErrNotFound.WithDetail("用户不存在")
			}
			userID = usr.ID
		}
		usr, gerr := h.Repo.GetUser(ctx, h.Store.Pool, userID)
		if gerr != nil {
			return httpx.ErrNotFound.WithDetail("用户不存在")
		}
		requireID = usr.ID.String()
		requireLabel = usr.Username
	}

	ttl := mfaVerifyDefaultTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
		if ttl < mfaVerifyMinTTL {
			ttl = mfaVerifyMinTTL
		}
		if ttl > mfaVerifyMaxTTL {
			ttl = mfaVerifyMaxTTL
		}
	}

	now := time.Now()
	rec := mfaverify.Record{
		ID:               crypto.RandomToken(18),
		RequestedBy:      p.TokenName,
		CreatedByTokenID: p.TokenID.String(),
		RequireUserID:    requireID,
		RequireUserLabel: requireLabel,
		RedirectURI:      req.RedirectURI,
		AllowedFactors:   factors,
		Status:           mfaverify.StatusPending,
		CreatedAt:        now,
		ExpiresAt:        now.Add(ttl),
	}
	if err := mfaverify.Create(ctx, h.Store.Redis, rec, ttl); err != nil {
		return err
	}
	h.Audit.Log(ctx, audit.Event{
		Action: "mfa.verify.request", Result: audit.ResultSuccess,
		TargetType: "mfa_verification", TargetID: rec.ID, TargetLabel: requireLabel,
	})
	httpx.JSON(w, r, http.StatusCreated, map[string]any{
		"id":         rec.ID,
		"verify_url": strings.TrimRight(h.Cfg.Issuer, "/") + "/verify/" + rec.ID,
		"status":     rec.Status,
		"expires_at": rec.ExpiresAt,
	})
	return nil
}

// getMFAVerification (machine) returns the authoritative result of a request.
// GET /api/v1/mfa-verifications/{id}
func (h *Handlers) getMFAVerification(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	p, _ := authctx.From(ctx)
	if err := requireMFAVerifyScope(p); err != nil {
		return err
	}
	id := chi.URLParam(r, "id")
	rec, err := mfaverify.Get(ctx, h.Store.Redis, id)
	if err != nil {
		return httpx.ErrNotFound.WithDetail("验证请求不存在或已过期")
	}
	// Only the API token that created the request may read its result back. 404
	// (not 403) so a different token cannot probe for the existence of an id.
	if rec.CreatedByTokenID != "" && rec.CreatedByTokenID != p.TokenID.String() {
		return httpx.ErrNotFound.WithDetail("验证请求不存在或已过期")
	}
	out := map[string]any{
		"id":          rec.ID,
		"status":      rec.Status,
		"expires_at":  rec.ExpiresAt,
		"verified_at": rec.VerifiedAt,
	}
	if rec.Status == mfaverify.StatusVerified {
		out["user_id"] = rec.UserID
		out["username"] = rec.Username
		out["factor"] = rec.Factor
	}
	httpx.JSON(w, r, http.StatusOK, out)
	return nil
}
