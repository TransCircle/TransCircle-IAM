package oauth

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/ory/fosite"

	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/httpx"
)

// Mount registers the OAuth2/OIDC protocol endpoints + discovery + JWKS.
func (p *Provider) Mount(r chi.Router) {
	r.Get("/.well-known/openid-configuration", p.handleDiscovery)
	r.Get("/.well-known/jwks.json", p.handleJWKS)
	r.Get("/jwks.json", p.handleJWKS) // back-compat alias

	r.Get("/oauth2/auth", p.handleAuthorize)
	r.Post("/oauth2/auth", p.handleAuthorize)
	r.Post("/oauth2/token", p.handleToken)
	r.Get("/oauth2/userinfo", p.handleUserinfo)
	r.Post("/oauth2/userinfo", p.handleUserinfo)
	r.Post("/oauth2/introspect", p.handleIntrospect)
	r.Post("/oauth2/revoke", p.handleRevoke)

	p.registerConsentAPI(r)
}

func (p *Provider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	iss := p.cfg.Issuer
	doc := map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oauth2/auth",
		"token_endpoint":                        iss + "/oauth2/token",
		"userinfo_endpoint":                     iss + "/oauth2/userinfo",
		"jwks_uri":                              iss + "/.well-known/jwks.json",
		"introspection_endpoint":                iss + "/oauth2/introspect",
		"revocation_endpoint":                   iss + "/oauth2/revoke",
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access", "tc.permissions"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported":                      []string{"sub", "name", "preferred_username", "email", "tc_app", "tc_roles", "tc_perm_version"},
	}
	httpx.JSON(w, r, http.StatusOK, doc)
}

func (p *Provider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, r, http.StatusOK, p.ks.JWKS())
}

func (p *Provider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ar, err := p.oauth2.NewAuthorizeRequest(ctx, r)
	if err != nil {
		p.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	principal, ok := authctx.From(ctx)
	if !ok {
		p.redirectToLogin(w, r)
		return
	}
	user, err := p.repo.GetUser(ctx, p.store.Pool, principal.UserID)
	if err != nil {
		p.redirectToLogin(w, r)
		return
	}
	if user.ForcePasswordChange || user.MustEnrollMFA {
		// Onboarding incomplete: send the user through login/onboarding first.
		p.redirectToLogin(w, r)
		return
	}

	client, err := p.clients.Get(ctx, p.store.Pool, ar.GetClient().GetID())
	if err != nil {
		p.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrInvalidClient)
		return
	}
	scopes := []string(ar.GetRequestedScopes())

	// Trusted clients skip the prompt entirely. Every other client must be
	// re-approved on each authorization: the consent page mints a one-time
	// ticket when the user approves, which is consumed here for exactly this
	// request. A fresh authorization carries no ticket, so it always prompts
	// again — consent is never silently remembered.
	if !client.SkipConsent {
		token := r.URL.Query().Get("consent_token")
		if !p.consumeConsentTicket(ctx, token, user.ID.String(), client.ClientID, scopes) {
			p.redirectToConsent(w, r, client, scopes)
			return
		}
	}
	p.finishAuthorize(w, r, ar, client)
}

func (p *Provider) finishAuthorize(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester, client *Client) {
	ctx := r.Context()
	principal, _ := authctx.From(ctx)
	user, err := p.repo.GetUser(ctx, p.store.Pool, principal.UserID)
	if err != nil {
		p.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}
	for _, sc := range ar.GetRequestedScopes() {
		if slices.Contains(client.AllowedScopes, sc) {
			ar.GrantScope(sc)
		}
	}
	for _, aud := range ar.GetRequestedAudience() {
		ar.GrantAudience(aud)
	}

	sess := NewSession(user.ID.String(), p.ks.ActiveSigningKey().KID, p.cfg.Issuer)
	if err := p.enrich(ctx, sess, user, client.ClientID, []string(ar.GetGrantedScopes())); err != nil {
		p.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}
	resp, err := p.oauth2.NewAuthorizeResponse(ctx, ar, sess)
	if err != nil {
		p.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}
	p.oauth2.WriteAuthorizeResponse(ctx, w, ar, resp)
}

func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := NewSession("", p.ks.ActiveSigningKey().KID, p.cfg.Issuer)
	ar, err := p.oauth2.NewAccessRequest(ctx, r, sess)
	if err != nil {
		p.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}
	// For client_credentials, enrich the access token with the client's app claims.
	if ar.GetGrantTypes().ExactOne("client_credentials") {
		ar.GrantAudience(p.cfg.Issuer)
		for _, sc := range ar.GetRequestedScopes() {
			ar.GrantScope(sc)
		}
	}
	resp, err := p.oauth2.NewAccessResponse(ctx, ar)
	if err != nil {
		p.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}
	p.oauth2.WriteAccessResponse(ctx, w, ar, resp)
}

func (p *Provider) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := fosite.AccessTokenFromRequest(r)
	if token == "" {
		httpx.Error(w, r, httpx.ErrUnauthorized.WithDetail("缺少访问令牌"))
		return
	}
	sess := NewSession("", p.ks.ActiveSigningKey().KID, p.cfg.Issuer)
	_, ar, err := p.oauth2.IntrospectToken(ctx, token, fosite.AccessToken, sess)
	if err != nil {
		httpx.Error(w, r, httpx.ErrUnauthorized.WithDetail("访问令牌无效"))
		return
	}
	subject := ar.GetSession().GetSubject()
	out := map[string]any{"sub": subject}
	granted := []string(ar.GetGrantedScopes())

	if uid, perr := uuidFromString(subject); perr == nil {
		if user, uerr := p.repo.GetUser(ctx, p.store.Pool, uid); uerr == nil {
			if slices.Contains(granted, "profile") {
				out["name"] = user.DisplayName
				out["preferred_username"] = user.Username
			}
			if slices.Contains(granted, "email") {
				out["email"] = user.Email
			}
			if slices.Contains(granted, "tc.permissions") {
				ac, aerr := p.computeAppClaims(ctx, subject, ar.GetClient().GetID())
				if aerr == nil && ac.App != "" {
					out["tc_app"] = ac.App
					out["tc_roles"] = ac.Roles
					out["tc_permissions"] = ac.Permissions
					out["tc_perm_version"] = ac.PermVersion
				}
			}
		}
	}
	httpx.JSON(w, r, http.StatusOK, out)
}

func (p *Provider) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := NewSession("", p.ks.ActiveSigningKey().KID, p.cfg.Issuer)
	ir, err := p.oauth2.NewIntrospectionRequest(ctx, r, sess)
	if err != nil {
		p.oauth2.WriteIntrospectionError(ctx, w, err)
		return
	}
	p.oauth2.WriteIntrospectionResponse(ctx, w, ir)
}

func (p *Provider) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := p.oauth2.NewRevocationRequest(ctx, r)
	p.oauth2.WriteRevocationResponse(ctx, w, err)
}

func (p *Provider) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	ret := url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, p.cfg.Issuer+"/login?return="+ret, http.StatusFound)
}

func (p *Provider) redirectToConsent(w http.ResponseWriter, r *http.Request, client *Client, scopes []string) {
	ret := url.QueryEscape(r.URL.RequestURI())
	q := url.Values{}
	q.Set("client_id", client.ClientID)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("return", ret)
	http.Redirect(w, r, p.cfg.Issuer+"/consent?"+q.Encode(), http.StatusFound)
}
