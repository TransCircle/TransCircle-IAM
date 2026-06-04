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

func (h *Handlers) listAPITokens(w http.ResponseWriter, r *http.Request) error {
	rows, err := h.Store.Pool.Query(r.Context(),
		`SELECT id, name, prefix, scopes, allowed_app_keys, expires_at, revoked_at, last_used_at, created_at
		   FROM api_tokens ORDER BY created_at DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var out []apiTokenInfo
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
			id, req.Name, hash, prefix, req.Scopes, req.AllowedAppKeys, by, expires)
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
		p := &authctx.Principal{IsMachine: true, TokenName: name, TokenScopes: scopes, AllowedApps: apps}
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
