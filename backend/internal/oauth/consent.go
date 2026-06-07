package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

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

// consentTicket is a one-time, short-lived proof that the user just approved a
// specific client + scope set on the consent page. For a non-trusted client it
// is the ONLY thing that lets an authorization proceed, and it is consumed on
// use — so every authorization re-prompts, even when the same client was
// approved moments ago. Persistent grants intentionally do NOT skip the prompt.
type consentTicket struct {
	UserID   string   `json:"user_id"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

const consentTicketTTL = 5 * time.Minute

func consentTicketKey(token string) string { return "oauth:consent:once:" + token }

// mintConsentTicket stores a single-use ticket and returns its opaque token.
func (p *Provider) mintConsentTicket(ctx context.Context, userID, clientID string, scopes []string) (string, error) {
	token := crypto.RandomToken(24)
	raw, err := json.Marshal(consentTicket{UserID: userID, ClientID: clientID, Scopes: orEmpty(scopes)})
	if err != nil {
		return "", err
	}
	if err := p.store.Redis.Set(ctx, consentTicketKey(token), raw, consentTicketTTL).Err(); err != nil {
		return "", err
	}
	return token, nil
}

// consumeConsentTicket atomically redeems a one-time consent ticket (GetDel). It
// returns true only when the ticket exists, belongs to this user + client, and
// covers every requested scope. Any miss (absent, expired, mismatched, or a
// Redis error) returns false, which fails safe by re-prompting for consent.
func (p *Provider) consumeConsentTicket(ctx context.Context, token, userID, clientID string, scopes []string) bool {
	if token == "" {
		return false
	}
	raw, err := p.store.Redis.GetDel(ctx, consentTicketKey(token)).Bytes()
	if err != nil {
		return false
	}
	var t consentTicket
	if err := json.Unmarshal(raw, &t); err != nil {
		return false
	}
	if t.UserID != userID || t.ClientID != clientID {
		return false
	}
	for _, sc := range scopes {
		if !slices.Contains(t.Scopes, sc) {
			return false
		}
	}
	return true
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
	out := []consentScope{}
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
	// Record the consent decision (history of the user's latest approval per
	// client). This row is a record only — it does NOT gate future prompts; the
	// one-time ticket minted below is what actually authorizes this single flow.
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
	// Mint the single-use ticket that lets exactly this authorization proceed.
	token, err := p.mintConsentTicket(ctx, principal.UserID.String(), req.ClientID, req.Scopes)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok", "consent_token": token})
	return nil
}

func splitScopes(s string) []string {
	return strings.Fields(s)
}
