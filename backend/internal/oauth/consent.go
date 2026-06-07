package oauth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/httpx"
)

// registerConsentAPI mounts the session-authenticated, CSRF-protected consent
// endpoints used by the frontend consent page.
func (p *Provider) registerConsentAPI(r chi.Router) {
	r.Method("GET", "/api/v1/oauth/consent-info", httpx.Handler(p.handleConsentInfo))
	r.Method("POST", "/api/v1/oauth/consent", httpx.Handler(p.handleConsentApprove))
}

func (p *Provider) currentMappingVersion(ctx context.Context) (int64, error) {
	var v int64
	err := p.store.Pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(mapping_version), 1) FROM oauth_scope_permission_map`).Scan(&v)
	return v, err
}

// consentSatisfied reports whether consent can be skipped (trusted client) or a
// current grant already covers the requested scopes (must-fix #9: a grant is
// stale once the scope→permission mapping version advances).
func (p *Provider) consentSatisfied(ctx context.Context, userID interface{ String() string }, client *Client, scopes []string) (bool, error) {
	if client.SkipConsent {
		return true, nil
	}
	var granted []string
	var mappingVersion int64
	err := p.store.Pool.QueryRow(ctx,
		`SELECT granted_scopes, mapping_version FROM oauth_consent_grants WHERE user_id=$1 AND client_id=$2`,
		userID.String(), client.ClientID).Scan(&granted, &mappingVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	current, err := p.currentMappingVersion(ctx)
	if err != nil {
		return false, err
	}
	if mappingVersion < current {
		return false, nil
	}
	for _, sc := range scopes {
		if !slices.Contains(granted, sc) {
			return false, nil
		}
	}
	return true, nil
}

type consentScope struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

func (p *Provider) handleConsentInfo(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	if _, ok := authctx.From(ctx); !ok {
		return httpx.ErrUnauthorized
	}
	clientID := r.URL.Query().Get("client_id")
	client, err := p.clients.Get(ctx, p.store.Pool, clientID)
	if err != nil {
		return httpx.ErrNotFound.WithDetail("应用不存在")
	}
	requested := splitScopes(r.URL.Query().Get("scope"))
	var out []consentScope
	for _, sc := range requested {
		var cs consentScope
		cs.Name = sc
		_ = p.store.Pool.QueryRow(ctx,
			`SELECT display_name, description FROM oauth_scopes WHERE name=$1`, sc).Scan(&cs.DisplayName, &cs.Description)
		if cs.DisplayName == "" {
			cs.DisplayName = sc
		}
		out = append(out, cs)
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"client_name": client.ClientName,
		"scopes":      out,
	})
	return nil
}

type consentReq struct {
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	Approve  bool     `json:"approve"`
}

func (p *Provider) handleConsentApprove(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	principal, ok := authctx.From(ctx)
	if !ok {
		return httpx.ErrUnauthorized
	}
	var req consentReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if !req.Approve {
		return httpx.NewError(http.StatusOK, "denied", "已拒绝授权")
	}
	current, err := p.currentMappingVersion(ctx)
	if err != nil {
		return err
	}
	err = p.store.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO oauth_consent_grants (id, user_id, client_id, granted_scopes, mapping_version)
			 VALUES ($1,$2,$3,$4,$5)
			 ON CONFLICT (user_id, client_id) DO UPDATE
			   SET granted_scopes=EXCLUDED.granted_scopes, mapping_version=EXCLUDED.mapping_version`,
			crypto.NewUUIDv7(), principal.UserID, req.ClientID, orEmpty(req.Scopes), current)
		if err != nil {
			return err
		}
		return p.audit.Write(ctx, tx, audit.Event{
			Action: "oauth.consent", TargetType: "client", TargetID: req.ClientID,
			Metadata: map[string]any{"scopes": req.Scopes},
		})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

func splitScopes(s string) []string {
	return strings.Fields(s)
}
