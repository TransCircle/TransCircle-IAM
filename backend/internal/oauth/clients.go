// Package oauth implements the OAuth2 / OIDC provider on top of ory/fosite:
// client management, a Redis/Postgres-backed storage adapter, the provider
// endpoints, the consent flow, and per-application permission claims.
package oauth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/keys"
	"github.com/transcircle/iam/internal/store"
)

// ErrNotFound is returned when a client does not exist.
var ErrNotFound = errors.New("oauth: client not found")

// Client is an OAuth/OIDC client (relying party or M2M app).
type Client struct {
	ID                      uuid.UUID  `json:"id"`
	ClientID                string     `json:"client_id"`
	ClientName              string     `json:"client_name"`
	AppID                   *uuid.UUID `json:"app_id"`
	Public                  bool       `json:"public"`
	TokenEndpointAuthMethod string     `json:"token_endpoint_auth_method"`
	RedirectURIs            []string   `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string   `json:"post_logout_redirect_uris"`
	GrantTypes              []string   `json:"grant_types"`
	ResponseTypes           []string   `json:"response_types"`
	AllowedScopes           []string   `json:"allowed_scopes"`
	AllowedAppKeys          []string   `json:"allowed_app_keys"`
	Audience                []string   `json:"audience"`
	PKCERequired            bool       `json:"pkce_required"`
	SkipConsent             bool       `json:"skip_consent"`
	Active                  bool       `json:"active"`
	// Login access control. Empty across all three = unrestricted; otherwise a
	// user must match at least one rule to complete authorization (see migration
	// 0014). LoginRequiredPerms holds permission keys (resolved in the bound app).
	LoginAllowedUserIDs   []uuid.UUID `json:"login_allowed_user_ids"`
	LoginAllowedGroupKeys []string    `json:"login_allowed_group_keys"`
	LoginRequiredPerms    []string    `json:"login_required_perms"`
	CreatedAt             time.Time   `json:"created_at"`
	UpdatedAt             time.Time   `json:"updated_at"`
	// HasSecret indicates a confidential client has a stored hash.
	HasSecret bool `json:"has_secret"`
}

// LoginRestricted reports whether the client limits which users may log in.
func (c *Client) LoginRestricted() bool {
	return len(c.LoginAllowedUserIDs) > 0 || len(c.LoginAllowedGroupKeys) > 0 || len(c.LoginRequiredPerms) > 0
}

// ClientService manages OAuth clients with secret hashing + one-time reveal.
type ClientService struct {
	st     *store.Store
	hasher *crypto.Hasher
	ks     *keys.KeyStore
}

// NewClientService builds the service.
func NewClientService(st *store.Store, hasher *crypto.Hasher, ks *keys.KeyStore) *ClientService {
	return &ClientService{st: st, hasher: hasher, ks: ks}
}

const clientCols = `id, client_id, client_name, app_id, public, token_endpoint_auth_method,
	redirect_uris, post_logout_redirect_uris, grant_types, response_types, allowed_scopes,
	allowed_app_keys, audience, pkce_required, skip_consent, active,
	login_allowed_user_ids, login_allowed_group_keys, login_required_perms,
	created_at, updated_at,
	(secret_hash IS NOT NULL) AS has_secret`

func scanClient(row pgx.Row) (*Client, error) {
	var c Client
	err := row.Scan(&c.ID, &c.ClientID, &c.ClientName, &c.AppID, &c.Public, &c.TokenEndpointAuthMethod,
		&c.RedirectURIs, &c.PostLogoutRedirectURIs, &c.GrantTypes, &c.ResponseTypes, &c.AllowedScopes,
		&c.AllowedAppKeys, &c.Audience, &c.PKCERequired, &c.SkipConsent, &c.Active,
		&c.LoginAllowedUserIDs, &c.LoginAllowedGroupKeys, &c.LoginRequiredPerms,
		&c.CreatedAt, &c.UpdatedAt,
		&c.HasSecret)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &c, err
}

// Get returns a client by its client_id.
func (s *ClientService) Get(ctx context.Context, db store.DBTX, clientID string) (*Client, error) {
	return scanClient(db.QueryRow(ctx, `SELECT `+clientCols+` FROM oauth_clients WHERE client_id=$1`, clientID))
}

// List returns all clients.
func (s *ClientService) List(ctx context.Context) ([]Client, error) {
	rows, err := s.st.Pool.Query(ctx, `SELECT `+clientCols+` FROM oauth_clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Client{}
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// CreateParams describes a new or edited client. PKCERequired and Active default
// to true at creation; on update they carry the caller's chosen values.
type CreateParams struct {
	ClientName             string
	AppID                  *uuid.UUID
	Public                 bool
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	GrantTypes             []string
	ResponseTypes          []string
	AllowedScopes          []string
	AllowedAppKeys         []string
	Audience               []string
	SkipConsent            bool
	PKCERequired           bool
	Active                 bool
	LoginAllowedUserIDs    []uuid.UUID
	LoginAllowedGroupKeys  []string
	LoginRequiredPerms     []string
}

// Create inserts a client and returns it plus the generated secret (shown once
// for confidential clients).
func (s *ClientService) Create(ctx context.Context, db store.DBTX, p CreateParams) (*Client, string, error) {
	id := crypto.NewUUIDv7()
	clientID := "tc_" + crypto.RandomToken(12)
	c := &Client{
		ID: id, ClientID: clientID, ClientName: p.ClientName, AppID: p.AppID, Public: p.Public,
		RedirectURIs: orEmpty(p.RedirectURIs), PostLogoutRedirectURIs: orEmpty(p.PostLogoutRedirectURIs),
		GrantTypes:     defaultIfEmpty(p.GrantTypes, []string{"authorization_code", "refresh_token"}),
		ResponseTypes:  defaultIfEmpty(p.ResponseTypes, []string{"code"}),
		AllowedScopes:  defaultIfEmpty(p.AllowedScopes, []string{"openid", "profile", "email"}),
		AllowedAppKeys: orEmpty(p.AllowedAppKeys), Audience: orEmpty(p.Audience),
		SkipConsent: p.SkipConsent, PKCERequired: p.PKCERequired, Active: p.Active,
		LoginAllowedUserIDs:   orEmptyUUID(p.LoginAllowedUserIDs),
		LoginAllowedGroupKeys: orEmpty(p.LoginAllowedGroupKeys),
		LoginRequiredPerms:    orEmpty(p.LoginRequiredPerms),
	}
	authMethod := "client_secret_basic"
	var secretPlain, secretHash string
	var secretEnc, secretNonce []byte
	var dekVer *int
	if p.Public {
		authMethod = "none"
	} else {
		secretPlain = crypto.RandomToken(24)
		h, err := s.hasher.Hash(ctx, secretPlain)
		if err != nil {
			return nil, "", err
		}
		secretHash = h
		enc, nonce, ver, err := s.ks.EncryptSecret([]byte(secretPlain), "client:"+clientID)
		if err != nil {
			return nil, "", err
		}
		secretEnc, secretNonce, dekVer = enc, nonce, &ver
	}
	c.TokenEndpointAuthMethod = authMethod

	_, err := db.Exec(ctx,
		`INSERT INTO oauth_clients
		   (id, client_id, client_name, secret_hash, client_secret_enc, client_secret_nonce, client_secret_dek_version,
		    app_id, public, token_endpoint_auth_method, redirect_uris, post_logout_redirect_uris,
		    grant_types, response_types, allowed_scopes, allowed_app_keys, audience, skip_consent, pkce_required, active,
		    login_allowed_user_ids, login_allowed_group_keys, login_required_perms)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
		id, clientID, p.ClientName, nullStr(secretHash), secretEnc, secretNonce, dekVer,
		p.AppID, p.Public, authMethod, c.RedirectURIs, c.PostLogoutRedirectURIs,
		c.GrantTypes, c.ResponseTypes, c.AllowedScopes, c.AllowedAppKeys, c.Audience, p.SkipConsent, c.PKCERequired, c.Active,
		c.LoginAllowedUserIDs, c.LoginAllowedGroupKeys, c.LoginRequiredPerms)
	if err != nil {
		return nil, "", err
	}
	c.HasSecret = secretHash != ""
	return c, secretPlain, nil
}

// Update edits a client's non-secret configuration.
func (s *ClientService) Update(ctx context.Context, db store.DBTX, clientID string, p CreateParams) error {
	ct, err := db.Exec(ctx,
		`UPDATE oauth_clients SET client_name=$2, redirect_uris=$3, post_logout_redirect_uris=$4,
		    grant_types=$5, response_types=$6, allowed_scopes=$7, allowed_app_keys=$8, audience=$9,
		    skip_consent=$10, pkce_required=$11, active=$12, app_id=$13,
		    login_allowed_user_ids=$14, login_allowed_group_keys=$15, login_required_perms=$16
		  WHERE client_id=$1`,
		clientID, p.ClientName, orEmpty(p.RedirectURIs), orEmpty(p.PostLogoutRedirectURIs),
		defaultIfEmpty(p.GrantTypes, []string{"authorization_code", "refresh_token"}),
		defaultIfEmpty(p.ResponseTypes, []string{"code"}),
		defaultIfEmpty(p.AllowedScopes, []string{"openid", "profile", "email"}),
		orEmpty(p.AllowedAppKeys), orEmpty(p.Audience), p.SkipConsent, p.PKCERequired, p.Active, p.AppID,
		orEmptyUUID(p.LoginAllowedUserIDs), orEmpty(p.LoginAllowedGroupKeys), orEmpty(p.LoginRequiredPerms))
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a client.
func (s *ClientService) Delete(ctx context.Context, db store.DBTX, clientID string) error {
	ct, err := db.Exec(ctx, `DELETE FROM oauth_clients WHERE client_id=$1`, clientID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RotateSecret generates a new secret, hashes it, and stores the previous hash
// with a short grace window. Returns the new secret (shown once).
func (s *ClientService) RotateSecret(ctx context.Context, db store.DBTX, clientID string) (string, error) {
	var prevHash *string
	if err := db.QueryRow(ctx, `SELECT secret_hash FROM oauth_clients WHERE client_id=$1`, clientID).Scan(&prevHash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	newSecret := crypto.RandomToken(24)
	hash, err := s.hasher.Hash(ctx, newSecret)
	if err != nil {
		return "", err
	}
	grace := time.Now().Add(24 * time.Hour)
	_, err = db.Exec(ctx,
		`UPDATE oauth_clients
		    SET secret_hash=$2, secret_prev_hash=$3, secret_prev_expires_at=$4,
		        client_secret_enc=NULL, client_secret_nonce=NULL, client_secret_dek_version=NULL
		  WHERE client_id=$1`,
		clientID, hash, prevHash, grace)
	return newSecret, err
}

// RevealSecret returns the stored plaintext secret exactly once, then nulls it
// (one-time reveal-on-create, must-fix #10).
func (s *ClientService) RevealSecret(ctx context.Context, db store.DBTX, clientID string) (string, error) {
	var enc, nonce []byte
	var ver *int
	err := db.QueryRow(ctx,
		`SELECT client_secret_enc, client_secret_nonce, client_secret_dek_version FROM oauth_clients WHERE client_id=$1`, clientID).
		Scan(&enc, &nonce, &ver)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if enc == nil || ver == nil {
		return "", errors.New("oauth: 密钥已不可再次查看，请轮换")
	}
	pt, err := s.ks.DecryptSecret(enc, nonce, *ver, "client:"+clientID)
	if err != nil {
		return "", err
	}
	// Burn the stored ciphertext so it can be revealed only once. If this fails
	// the caller's transaction rolls back and no secret is returned.
	if _, err := db.Exec(ctx,
		`UPDATE oauth_clients SET client_secret_enc=NULL, client_secret_nonce=NULL, client_secret_dek_version=NULL WHERE client_id=$1`, clientID); err != nil {
		return "", err
	}
	return string(pt), nil
}

// secretHashes returns the client's current secret hash plus any previous hash
// still inside its rotation grace window, so fosite accepts both during rotation.
func (s *ClientService) secretHashes(ctx context.Context, clientID string) (current string, rotated []string, err error) {
	var h, prev *string
	var prevExp *time.Time
	err = s.st.Pool.QueryRow(ctx,
		`SELECT secret_hash, secret_prev_hash, secret_prev_expires_at FROM oauth_clients WHERE client_id=$1`, clientID).
		Scan(&h, &prev, &prevExp)
	if err != nil {
		return "", nil, err
	}
	if h == nil {
		return "", nil, errors.New("oauth: client has no secret")
	}
	current = *h
	if prev != nil && prevExp != nil && time.Now().Before(*prevExp) {
		rotated = []string{*prev}
	}
	return current, rotated, nil
}

func defaultIfEmpty(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

// orEmpty coalesces a nil slice to an empty one so NOT NULL text[] columns are
// never sent a SQL NULL (pgx encodes a nil slice as NULL).
func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// orEmptyUUID coalesces a nil slice to an empty one so NOT NULL uuid[] columns
// are never sent a SQL NULL.
func orEmptyUUID(v []uuid.UUID) []uuid.UUID {
	if v == nil {
		return []uuid.UUID{}
	}
	return v
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
