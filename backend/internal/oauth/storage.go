package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ory/fosite"
	"github.com/redis/go-redis/v9"

	"github.com/transcircle/iam/internal/logging"
	"github.com/transcircle/iam/internal/store"
)

// storage implements the fosite storage interfaces. Ephemeral artifacts (codes,
// access/refresh sessions, PKCE, OIDC handoff) live in Redis with TTL; refresh
// rotation lineage lives in Postgres for reuse detection + family revoke.
type storage struct {
	st      *store.Store
	clients *ClientService
	cfg     storageConfig
}

type storageConfig struct {
	accessTTL  time.Duration
	refreshTTL time.Duration
	codeTTL    time.Duration
}

func newStorage(st *store.Store, clients *ClientService, cfg storageConfig) *storage {
	return &storage{st: st, clients: clients, cfg: cfg}
}

// ----- serialization -----

type storedRequest struct {
	ID                string          `json:"id"`
	RequestedAt       time.Time       `json:"requested_at"`
	ClientID          string          `json:"client_id"`
	RequestedScope    []string        `json:"requested_scope"`
	GrantedScope      []string        `json:"granted_scope"`
	RequestedAudience []string        `json:"requested_audience"`
	GrantedAudience   []string        `json:"granted_audience"`
	Form              url.Values      `json:"form"`
	Session           json.RawMessage `json:"session"`
	Active            bool            `json:"active"`
}

func toStored(req fosite.Requester) (storedRequest, error) {
	sessionJSON, err := json.Marshal(req.GetSession())
	if err != nil {
		return storedRequest{}, err
	}
	return storedRequest{
		ID:                req.GetID(),
		RequestedAt:       req.GetRequestedAt(),
		ClientID:          req.GetClient().GetID(),
		RequestedScope:    req.GetRequestedScopes(),
		GrantedScope:      req.GetGrantedScopes(),
		RequestedAudience: req.GetRequestedAudience(),
		GrantedAudience:   req.GetGrantedAudience(),
		Form:              req.GetRequestForm(),
		Session:           sessionJSON,
		Active:            true,
	}, nil
}

func (s *storage) fromStored(ctx context.Context, sr storedRequest, session fosite.Session) (fosite.Requester, error) {
	client, err := s.GetClient(ctx, sr.ClientID)
	if err != nil {
		return nil, err
	}
	if len(sr.Session) > 0 && session != nil {
		if err := json.Unmarshal(sr.Session, session); err != nil {
			return nil, err
		}
	}
	req := &fosite.Request{
		ID:                sr.ID,
		RequestedAt:       sr.RequestedAt,
		Client:            client,
		RequestedScope:    sr.RequestedScope,
		GrantedScope:      sr.GrantedScope,
		RequestedAudience: sr.RequestedAudience,
		GrantedAudience:   sr.GrantedAudience,
		Form:              sr.Form,
		Session:           session,
	}
	return req, nil
}

func (s *storage) put(ctx context.Context, key string, req fosite.Requester, ttl time.Duration) error {
	sr, err := toStored(req)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(sr)
	if err != nil {
		return err
	}
	return s.st.Redis.Set(ctx, key, raw, ttl).Err()
}

func (s *storage) get(ctx context.Context, key string, session fosite.Session) (fosite.Requester, *storedRequest, error) {
	raw, err := s.st.Redis.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	var sr storedRequest
	if err := json.Unmarshal(raw, &sr); err != nil {
		return nil, nil, err
	}
	req, err := s.fromStored(ctx, sr, session)
	if err != nil {
		return nil, nil, err
	}
	return req, &sr, nil
}

// ----- ClientManager -----

func (s *storage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	c, err := s.clients.Get(ctx, s.st.Pool, id)
	if err != nil {
		// fosite reports every GetClient failure to the RP as the same opaque
		// "The requested OAuth 2.0 Client does not exist." With debug messages off
		// in prod, a genuinely missing client is indistinguishable from a real
		// lookup failure (DB connectivity, a scan/type error). Split the two so the
		// operator can actually tell them apart from the logs.
		if errors.Is(err, ErrNotFound) {
			logging.From(ctx).Warn("oauth: client lookup found no such client", "client_id", id)
			return nil, fosite.ErrNotFound
		}
		logging.From(ctx).Error("oauth: client lookup failed", "client_id", id, "err", err)
		return nil, fosite.ErrServerError.WithWrap(err).WithDebug(err.Error())
	}
	if !c.Active {
		// The client exists but is disabled. This is a common reason an operator
		// sees "client does not exist" for a client they know is configured.
		logging.From(ctx).Warn("oauth: client is inactive; rejecting request", "client_id", id)
		return nil, fosite.ErrInvalidClient.WithHint("The OAuth 2.0 Client is disabled.")
	}
	return s.toFositeClient(ctx, c), nil
}

func (s *storage) toFositeClient(ctx context.Context, c *Client) fosite.Client {
	var secret []byte
	var rotated [][]byte
	if c.HasSecret {
		if cur, prev, err := s.clients.secretHashes(ctx, c.ClientID); err == nil {
			secret = []byte(cur)
			for _, h := range prev {
				rotated = append(rotated, []byte(h))
			}
		}
	}
	return &fosite.DefaultClient{
		ID:             c.ClientID,
		Secret:         secret,
		RotatedSecrets: rotated,
		RedirectURIs:   c.RedirectURIs,
		GrantTypes:     c.GrantTypes,
		ResponseTypes:  c.ResponseTypes,
		Scopes:         c.AllowedScopes,
		Audience:       c.Audience,
		Public:         c.Public,
	}
}

func (s *storage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	exists, err := s.st.Redis.Exists(ctx, "oauth:jti:"+jti).Result()
	if err != nil {
		return err
	}
	if exists == 1 {
		return fosite.ErrJTIKnown
	}
	return nil
}

func (s *storage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return s.st.Redis.Set(ctx, "oauth:jti:"+jti, "1", time.Until(exp)).Err()
}

// ----- AuthorizeCodeStorage -----

func (s *storage) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	return s.put(ctx, "oauth:code:"+code, req, s.cfg.codeTTL)
}

func (s *storage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	req, sr, err := s.get(ctx, "oauth:code:"+code, session)
	if err != nil {
		return nil, err
	}
	if !sr.Active {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}
	// Single-use: atomically claim the code (SET NX) so two concurrent token
	// requests can never both consume the same authorization code. fosite calls
	// this once per exchange; a reused/raced code returns the requester plus
	// ErrInvalidatedAuthorizeCode so fosite revokes any tokens already minted.
	ok, serr := s.st.Redis.SetNX(ctx, "oauth:code:used:"+code, "1", s.cfg.codeTTL).Result()
	if serr != nil {
		return nil, serr
	}
	if !ok {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}
	return req, nil
}

func (s *storage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	raw, err := s.st.Redis.Get(ctx, "oauth:code:"+code).Bytes()
	if errors.Is(err, redis.Nil) {
		return fosite.ErrNotFound
	}
	if err != nil {
		return err
	}
	var sr storedRequest
	if err := json.Unmarshal(raw, &sr); err != nil {
		return err
	}
	sr.Active = false
	out, _ := json.Marshal(sr)
	return s.st.Redis.Set(ctx, "oauth:code:"+code, out, s.cfg.codeTTL).Err()
}

// ----- AccessTokenStorage -----

func (s *storage) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	return s.put(ctx, "oauth:at:"+signature, req, s.cfg.accessTTL)
}

func (s *storage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	req, _, err := s.get(ctx, "oauth:at:"+signature, session)
	return req, err
}

func (s *storage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.st.Redis.Del(ctx, "oauth:at:"+signature).Err()
}

// ----- RefreshTokenStorage + reuse detection -----

func (s *storage) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, req fosite.Requester) error {
	// Record durable lineage FIRST so a refresh token never exists in Redis
	// without its chain row (which reuse detection + family revoke depend on).
	family := req.GetID()
	var userID *uuid.UUID
	if sub := req.GetSession().GetSubject(); sub != "" {
		if id, err := uuid.Parse(sub); err == nil {
			userID = &id
		}
	}
	// user_id is a NOT NULL FK; a refresh token without a resolvable user subject
	// must never persist a lineage row (would trip 23502). Fail closed instead.
	if userID == nil {
		return errors.New("oauth: refresh token session missing a valid user subject")
	}
	if _, err := s.st.Pool.Exec(ctx,
		`INSERT INTO oauth_refresh_chains (jti, family_id, user_id, client_id)
		 VALUES ($1, $2, $3, $4) ON CONFLICT (jti) DO NOTHING`,
		signature, familyUUID(family), userID, req.GetClient().GetID()); err != nil {
		return err
	}
	if err := s.put(ctx, "oauth:rt:"+signature, req, s.cfg.refreshTTL); err != nil {
		// Roll back the lineage so we don't leave an orphan chain row.
		_, _ = s.st.Pool.Exec(ctx, `DELETE FROM oauth_refresh_chains WHERE jti=$1`, signature)
		return err
	}
	return nil
}

func (s *storage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	// Reuse detection: a revoked (already-rotated) token being presented again
	// means a leak — revoke the whole family (must-fix #1). A missing chain row is
	// an anomaly and is treated as inactive (fail-closed). We also re-check the
	// owning user's status: deactivating or deleting a user must immediately stop
	// their connected apps from minting new tokens off an outstanding refresh
	// token, which the cookie-session revoke alone does not cover.
	var revoked, userActive bool
	var family uuid.UUID
	var userDeleted *time.Time
	err := s.st.Pool.QueryRow(ctx,
		`SELECT c.revoked, c.family_id, COALESCE(u.is_active, false), u.deleted_at
		   FROM oauth_refresh_chains c
		   LEFT JOIN users u ON u.id = c.user_id
		  WHERE c.jti=$1`, signature).Scan(&revoked, &family, &userActive, &userDeleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fosite.ErrInactiveToken
	}
	if err != nil {
		return nil, err
	}
	if revoked {
		// An already-rotated refresh token presented again is the canonical signal
		// of token theft. Log it for the SOC before revoking the whole family.
		logging.From(ctx).Warn("oauth: refresh token reuse detected; revoking token family", "family_id", family.String())
		s.revokeFamily(ctx, family)
		return nil, fosite.ErrInactiveToken
	}
	if !userActive || userDeleted != nil {
		s.revokeFamily(ctx, family)
		return nil, fosite.ErrInactiveToken
	}
	req, _, gerr := s.get(ctx, "oauth:rt:"+signature, session)
	return req, gerr
}

func (s *storage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.st.Redis.Del(ctx, "oauth:rt:"+signature).Err()
}

func (s *storage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	// Atomically claim the rotation: the conditional UPDATE only affects a row
	// whose revoked flag is still false, so exactly one of two concurrent refresh
	// exchanges wins. The loser updates zero rows and is rejected, so a single
	// refresh token can never be exchanged twice. A genuine later reuse (the token
	// presented after it was rotated) is still caught in GetRefreshTokenSession,
	// which revokes the whole family. We deliberately do NOT family-revoke here, so
	// a benign concurrent double-submit can't nuke the winner's fresh token.
	ct, err := s.st.Pool.Exec(ctx,
		`UPDATE oauth_refresh_chains SET revoked=true, used_at=now() WHERE jti=$1 AND revoked=false`, refreshTokenSignature)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fosite.ErrInactiveToken
	}
	return s.st.Redis.Del(ctx, "oauth:rt:"+refreshTokenSignature).Err()
}

// ----- TokenRevocationStorage -----

func (s *storage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	s.revokeFamily(ctx, familyUUID(requestID))
	return nil
}

func (s *storage) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	return s.RevokeRefreshToken(ctx, requestID)
}

func (s *storage) RevokeAccessToken(ctx context.Context, requestID string) error {
	// Access tokens are JWTs keyed by signature; we cannot enumerate by requestID
	// in Redis, so rely on short TTL + family refresh revoke. No-op is acceptable.
	return nil
}

func (s *storage) revokeFamily(ctx context.Context, family uuid.UUID) {
	rows, err := s.st.Pool.Query(ctx,
		`UPDATE oauth_refresh_chains SET revoked=true WHERE family_id=$1 RETURNING jti`, family)
	if err != nil {
		return
	}
	defer rows.Close()
	var jtis []string
	for rows.Next() {
		var j string
		if rows.Scan(&j) == nil {
			jtis = append(jtis, j)
		}
	}
	for _, j := range jtis {
		_ = s.st.Redis.Del(ctx, "oauth:rt:"+j).Err()
	}
}

// ----- PKCERequestStorage -----

func (s *storage) CreatePKCERequestSession(ctx context.Context, signature string, req fosite.Requester) error {
	return s.put(ctx, "oauth:pkce:"+signature, req, s.cfg.codeTTL)
}

func (s *storage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	req, _, err := s.get(ctx, "oauth:pkce:"+signature, session)
	return req, err
}

func (s *storage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.st.Redis.Del(ctx, "oauth:pkce:"+signature).Err()
}

// ----- OpenIDConnectRequestStorage -----

func (s *storage) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) error {
	return s.put(ctx, "oauth:oidc:"+authorizeCode, req, s.cfg.codeTTL)
}

func (s *storage) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) (fosite.Requester, error) {
	out, _, err := s.get(ctx, "oauth:oidc:"+authorizeCode, req.GetSession())
	if errors.Is(err, fosite.ErrNotFound) {
		return nil, fosite.ErrNotFound
	}
	return out, err
}

func (s *storage) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return s.st.Redis.Del(ctx, "oauth:oidc:"+authorizeCode).Err()
}

// familyUUID maps a fosite request ID to a deterministic UUID for the chain table.
func familyUUID(requestID string) uuid.UUID {
	if id, err := uuid.Parse(requestID); err == nil {
		return id
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(requestID))
}
