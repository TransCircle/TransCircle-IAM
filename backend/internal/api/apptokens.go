package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/httpx"
)

type apiTokenInfo struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Prefix         string     `json:"prefix"`
	Scopes         []string   `json:"scopes"`
	AllowedAppKeys []string   `json:"allowed_app_keys"`
	ExpiresAt      *time.Time `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Token scope catalog — the source of truth the admin UI renders as a checklist
// instead of a free-text field. Only scopes actually enforced by the API belong
// here (iam.permissions.read gates the permissions API; iam.mfa.verify gates the
// standalone two-factor verification API).
const ScopeMFAVerify = "iam.mfa.verify"

type tokenScope struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

var tokenScopeCatalog = []tokenScope{
	{Key: "iam.permissions.read", Label: "查询用户权限", Description: "调用 GET /api/v1/permissions 查询某用户在某应用下的角色、权限与身份组"},
	{Key: ScopeMFAVerify, Label: "发起两步验证", Description: "调用两步验证接口生成验证链接，引导用户完成 TOTP / 通行密钥验证，并回查验证结果"},
}

// validateTokenScopes enforces the simplified contract: a token carries at least
// one scope, and every scope must come from the known catalog (no free-form
// strings that could silently become effective when a future endpoint checks them).
func validateTokenScopes(scopes []string) error {
	if len(scopes) == 0 {
		return httpx.ErrBadRequest.WithDetail("请至少选择一个作用域")
	}
	for _, s := range scopes {
		known := false
		for _, c := range tokenScopeCatalog {
			if c.Key == s {
				known = true
				break
			}
		}
		if !known {
			return httpx.ErrBadRequest.WithDetail("未知作用域：" + s)
		}
	}
	return nil
}

// apiTokenMeta returns everything the create/edit token form needs to render
// pickers instead of free-text fields: the enforced scope catalog, the list of
// applications (key + name) the token can be limited to, and whether the caller
// may mint an unrestricted (all-applications) token.
func (h *Handlers) apiTokenMeta(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	apps, err := h.Repo.ListApplications(ctx, h.Store.Pool)
	if err != nil {
		return err
	}
	type appOpt struct {
		Key         string `json:"key"`
		DisplayName string `json:"display_name"`
	}
	appOpts := []appOpt{}
	for _, a := range apps {
		appOpts = append(appOpts, appOpt{Key: a.Key, DisplayName: a.DisplayName})
	}
	super, err := h.isSuperAdmin(ctx, actorID(r))
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"scopes":         tokenScopeCatalog,
		"applications":   appOpts,
		"can_unrestrict": super,
	})
	return nil
}

func (h *Handlers) listAPITokens(w http.ResponseWriter, r *http.Request) error {
	rows, err := h.Store.Pool.Query(r.Context(),
		`SELECT id, name, prefix, scopes, allowed_app_keys, expires_at, revoked_at, last_used_at, created_at
		   FROM api_tokens ORDER BY created_at DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []apiTokenInfo{}
	for rows.Next() {
		var t apiTokenInfo
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.Scopes, &t.AllowedAppKeys, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedAt); err != nil {
			return err
		}
		out = append(out, t)
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"tokens": out})
	return nil
}

type createTokenReq struct {
	Name           string   `json:"name"`
	Scopes         []string `json:"scopes"`
	AllowedAppKeys []string `json:"allowed_app_keys"`
	ExpiresInDays  int      `json:"expires_in_days"`
}

func (h *Handlers) createAPIToken(w http.ResponseWriter, r *http.Request) error {
	var req createTokenReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Name == "" {
		return httpx.ErrBadRequest.WithDetail("名称必填")
	}
	if err := validateTokenScopes(req.Scopes); err != nil {
		return err
	}
	if req.ExpiresInDays < 0 {
		return httpx.ErrBadRequest.WithDetail("有效期天数不能为负(0 表示永不过期)")
	}
	ctx0 := r.Context()
	// An empty allowed_app_keys means "all applications" — only a super-admin may
	// mint such a broad token (least privilege).
	if len(req.AllowedAppKeys) == 0 {
		super, err := h.isSuperAdmin(ctx0, actorID(r))
		if err != nil {
			return err
		}
		if !super {
			return httpx.ErrBadRequest.WithDetail("请指定该令牌可访问的应用 key(仅超级管理员可创建不限应用的令牌)")
		}
	}
	prefix := crypto.RandomToken(6)
	secret := crypto.RandomToken(24)
	full := "tcp_" + prefix + "_" + secret
	hash, err := h.Hasher.Hash(r.Context(), secret)
	if err != nil {
		return err
	}
	id := crypto.NewUUIDv7()
	var expires *time.Time
	if req.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresInDays)
		expires = &t
	}
	by := uuid.Nil
	if p, ok := authctx.From(r.Context()); ok {
		by = p.UserID
	}
	ctx := r.Context()
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO api_tokens (id, name, token_hash, prefix, scopes, allowed_app_keys, created_by, expires_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			id, req.Name, hash, prefix, orEmpty(req.Scopes), orEmpty(req.AllowedAppKeys), by, expires)
		if err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.apptoken.create", TargetType: "api_token", TargetID: id.String(), TargetLabel: req.Name})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusCreated, map[string]any{"id": id, "token": full})
	return nil
}

type updateTokenReq struct {
	Name           string   `json:"name"`
	Scopes         []string `json:"scopes"`
	AllowedAppKeys []string `json:"allowed_app_keys"`
	// nil = keep the current expiry untouched; 0 = never expire; >0 = re-anchor
	// to now + N days. Pointer so an edit that doesn't touch the field can't
	// silently extend a token's life.
	ExpiresInDays *int `json:"expires_in_days"`
}

// updateAPIToken edits a token's non-secret config (name, scopes, app allowlist,
// expiry). The secret and prefix are immutable; scope/allowlist changes take
// effect immediately on the next token use.
func (h *Handlers) updateAPIToken(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	var req updateTokenReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.Name == "" {
		return httpx.ErrBadRequest.WithDetail("名称必填")
	}
	if err := validateTokenScopes(req.Scopes); err != nil {
		return err
	}
	if req.ExpiresInDays != nil && *req.ExpiresInDays < 0 {
		return httpx.ErrBadRequest.WithDetail("有效期天数不能为负(0 表示永不过期)")
	}
	ctx := r.Context()
	// An empty allowed_app_keys means "all applications" — only a super-admin may
	// hold such a broad token (least privilege, mirrors createAPIToken).
	if len(req.AllowedAppKeys) == 0 {
		super, err := h.isSuperAdmin(ctx, actorID(r))
		if err != nil {
			return err
		}
		if !super {
			return httpx.ErrBadRequest.WithDetail("请指定该令牌可访问的应用 key(仅超级管理员可创建不限应用的令牌)")
		}
	}
	setExpiry := req.ExpiresInDays != nil
	var expires *time.Time
	if setExpiry && *req.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, *req.ExpiresInDays)
		expires = &t
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`UPDATE api_tokens SET name=$2, scopes=$3, allowed_app_keys=$4,
			        expires_at = CASE WHEN $6::boolean THEN $5 ELSE expires_at END
			   WHERE id=$1 AND revoked_at IS NULL`,
			id, req.Name, orEmpty(req.Scopes), orEmpty(req.AllowedAppKeys), expires, setExpiry)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return httpx.ErrNotFound.WithDetail("令牌不存在或已吊销")
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.apptoken.update", TargetType: "api_token", TargetID: id.String(), TargetLabel: req.Name})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) revokeAPIToken(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE api_tokens SET revoked_at=now() WHERE id=$1`, id); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.apptoken.revoke", TargetType: "api_token", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

// machineAuth authenticates a Bearer api_token and sets a machine principal.
func (h *Handlers) machineAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		// tcp_<prefix>_<secret>
		if !strings.HasPrefix(raw, "tcp_") {
			httpx.Error(w, r, httpx.ErrUnauthorized.WithDetail("缺少有效的机器令牌"))
			return
		}
		parts := strings.SplitN(strings.TrimPrefix(raw, "tcp_"), "_", 2)
		if len(parts) != 2 {
			httpx.Error(w, r, httpx.ErrUnauthorized)
			return
		}
		prefix, secret := parts[0], parts[1]
		var (
			id           uuid.UUID
			name, hash   string
			scopes, apps []string
			revokedAt    *time.Time
			expiresAt    *time.Time
		)
		err := h.Store.Pool.QueryRow(r.Context(),
			`SELECT id, name, token_hash, scopes, allowed_app_keys, revoked_at, expires_at FROM api_tokens WHERE prefix=$1`, prefix).
			Scan(&id, &name, &hash, &scopes, &apps, &revokedAt, &expiresAt)
		if err != nil {
			httpx.Error(w, r, httpx.ErrUnauthorized)
			return
		}
		if revokedAt != nil || (expiresAt != nil && time.Now().After(*expiresAt)) {
			httpx.Error(w, r, httpx.ErrUnauthorized.WithDetail("令牌已失效"))
			return
		}
		if _, verr := h.Hasher.Verify(r.Context(), secret, hash); verr != nil {
			httpx.Error(w, r, httpx.ErrUnauthorized)
			return
		}
		_, _ = h.Store.Pool.Exec(r.Context(), `UPDATE api_tokens SET last_used_at=now() WHERE id=$1`, id)
		p := &authctx.Principal{IsMachine: true, TokenID: id, TokenName: name, TokenScopes: scopes, AllowedApps: apps}
		next.ServeHTTP(w, r.WithContext(authctx.With(r.Context(), p)))
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}
