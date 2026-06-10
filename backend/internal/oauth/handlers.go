package oauth

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ory/fosite"

	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/avatars"
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
		"claims_supported":                      []string{"sub", "name", "preferred_username", "picture", "email", "tc_app", "tc_roles", "tc_permissions", "tc_groups", "tc_perm_version"},
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

	// prompt=none means the RP wants silent auth: never render UI; on any required
	// interaction return the corresponding OIDC error on the redirect_uri instead.
	promptNone := slices.Contains(strings.Fields(ar.GetRequestForm().Get("prompt")), "none")

	principal, ok := authctx.From(ctx)
	if !ok {
		if promptNone {
			p.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrLoginRequired)
			return
		}
		p.redirectToLogin(w, r)
		return
	}
	user, err := p.repo.GetUser(ctx, p.store.Pool, principal.UserID)
	if err != nil {
		if promptNone {
			p.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrLoginRequired)
			return
		}
		p.redirectToLogin(w, r)
		return
	}
	if user.ForcePasswordChange || user.MustEnrollMFA {
		// Onboarding incomplete: send the user through login/onboarding first.
		if promptNone {
			p.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrLoginRequired)
			return
		}
		p.redirectToLogin(w, r)
		return
	}
	if principal.Impersonating() {
		// An admin acting as this user must not be able to grant a third-party
		// app durable access (refresh tokens + recorded consent) on the victim's
		// behalf. Refuse to complete the authorization in an impersonation session.
		p.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrAccessDenied.WithHint("不支持在模拟登录会话中完成 OAuth 授权"))
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
		approved, denied := p.consumeConsentTicket(ctx, token, user.ID.String(), client.ClientID, scopes)
		if denied {
			// The user explicitly refused: complete the flow per spec so the
			// relying party receives error=access_denied on its redirect_uri.
			p.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrAccessDenied)
			return
		}
		if !approved {
			if promptNone {
				p.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrConsentRequired)
				return
			}
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
	p.setAuthContext(sess, principal)
	resp, err := p.oauth2.NewAuthorizeResponse(ctx, ar, sess)
	if err != nil {
		p.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}
	p.oauth2.WriteAuthorizeResponse(ctx, w, ar, resp)
}

// setAuthContext stamps the OIDC auth_time/rat/acr/amr onto the ID token from the
// IAM session. Without auth_time fosite rejects any request carrying max_age or a
// prompt with server_error, and RPs cannot see that (or how strongly) the user
// authenticated.
func (p *Provider) setAuthContext(sess *Session, principal *authctx.Principal) {
	if principal == nil || sess.DefaultSession == nil || sess.DefaultSession.Claims == nil {
		return
	}
	claims := sess.DefaultSession.Claims
	authTime := principal.AuthAt
	if authTime.IsZero() {
		authTime = time.Now()
	}
	claims.AuthTime = authTime
	claims.RequestedAt = time.Now()
	amr := principal.AMR
	if len(amr) == 0 {
		amr = []string{"pwd"}
	}
	claims.AuthenticationMethodsReferences = amr
	if principal.AAL >= 2 {
		claims.AuthenticationContextClassReference = "urn:transcircle:iam:aal2"
	} else {
		claims.AuthenticationContextClassReference = "urn:transcircle:iam:aal1"
	}
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
	// On refresh, re-resolve the user's current identity + authorization so a
	// rotated token never carries stale roles/permissions/profile. Best-effort:
	// the owning user's active status is already enforced in the storage layer.
	if ar.GetGrantTypes().ExactOne("refresh_token") {
		if s, ok := ar.GetSession().(*Session); ok {
			if uid, perr := uuidFromString(s.GetSubject()); perr == nil {
				if user, uerr := p.repo.GetUser(ctx, p.store.Pool, uid); uerr == nil {
					_ = p.enrich(ctx, s, user, ar.GetClient().GetID(), []string(ar.GetGrantedScopes()))
				}
			}
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
				if user.AvatarURL != "" {
					out["picture"] = avatars.UserURL(p.cfg.Issuer, user.ID.String())
				}
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
					out["tc_groups"] = ac.Groups
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
