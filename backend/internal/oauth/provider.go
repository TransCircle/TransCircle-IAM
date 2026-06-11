package oauth

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/authz"
	"github.com/transcircle/iam/internal/config"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/keys"
	"github.com/transcircle/iam/internal/rbac"
	"github.com/transcircle/iam/internal/store"
)

// argonHasher adapts our argon2id hasher to fosite.Hasher for client secrets
// (resolves the bcrypt-vs-argon2id conflict in favor of argon2id).
type argonHasher struct{ h *crypto.Hasher }

func (a argonHasher) Hash(ctx context.Context, data []byte) ([]byte, error) {
	s, err := a.h.Hash(ctx, string(data))
	return []byte(s), err
}

func (a argonHasher) Compare(ctx context.Context, hash, data []byte) error {
	_, err := a.h.Verify(ctx, string(data), string(hash))
	return err
}

// Provider is the OAuth2/OIDC provider plus its HTTP dependencies.
type Provider struct {
	oauth2  fosite.OAuth2Provider
	storage *storage
	ks      *keys.KeyStore
	cfg     *config.Config
	clients *ClientService
	authz   *authz.Service
	repo    rbac.Repo
	audit   *audit.Writer
	cookies httpx.Cookies
	store   *store.Store
}

// Deps are the provider construction dependencies.
type Deps struct {
	Cfg     *config.Config
	Store   *store.Store
	Keys    *keys.KeyStore
	Hasher  *crypto.Hasher
	Clients *ClientService
	Authz   *authz.Service
	Audit   *audit.Writer
	Cookies httpx.Cookies
}

// NewProvider builds the fosite provider. The HMAC global secret is loaded from
// the DB so signatures stay stable across restarts/replicas.
func NewProvider(ctx context.Context, d Deps) (*Provider, error) {
	globalSecret, err := d.Keys.LoadNamedSecret(ctx, d.Store, "oauth.hmac_secret")
	if err != nil {
		return nil, err
	}

	fc := &fosite.Config{
		AccessTokenLifespan:            d.Cfg.AccessTokenTTL,
		RefreshTokenLifespan:           d.Cfg.RefreshTokenTTL,
		AuthorizeCodeLifespan:          10 * time.Minute,
		IDTokenLifespan:                d.Cfg.IDTokenTTL,
		IDTokenIssuer:                  d.Cfg.Issuer,
		AccessTokenIssuer:              d.Cfg.Issuer,
		GlobalSecret:                   globalSecret,
		EnforcePKCE:                    true,
		EnablePKCEPlainChallengeMethod: false,
		ScopeStrategy:                  fosite.ExactScopeStrategy,
		AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
		ClientSecretsHasher:            argonHasher{h: d.Hasher},
		SendDebugMessagesToClients:     !d.Cfg.IsProd(),
	}

	st := newStorage(d.Store, d.Clients, d.Keys, storageConfig{
		accessTTL:  d.Cfg.AccessTokenTTL,
		refreshTTL: d.Cfg.RefreshTokenTTL,
		codeTTL:    10 * time.Minute,
	})

	keyGetter := func(ctx context.Context) (interface{}, error) {
		return d.Keys.ActiveSigningKey().Private, nil
	}
	hmac := compose.NewOAuth2HMACStrategy(fc)
	strategy := &compose.CommonStrategy{
		CoreStrategy:               compose.NewOAuth2JWTStrategy(keyGetter, hmac, fc),
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, fc),
		Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
	}

	provider := compose.Compose(fc, st, strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
		compose.OAuth2StatelessJWTIntrospectionFactory,
	)

	return &Provider{
		oauth2:  provider,
		storage: st,
		ks:      d.Keys,
		cfg:     d.Cfg,
		clients: d.Clients,
		authz:   d.Authz,
		audit:   d.Audit,
		cookies: d.Cookies,
		store:   d.Store,
	}, nil
}
