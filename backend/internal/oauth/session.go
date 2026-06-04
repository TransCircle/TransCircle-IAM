package oauth

import (
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// Compile-time checks that our session satisfies the fosite session contracts.
var (
	_ fosite.Session             = (*Session)(nil)
	_ oauth2.JWTSessionContainer = (*Session)(nil)
	_ openid.Session             = (*Session)(nil)
)

// Session is our fosite session. It embeds the OIDC default session and also
// implements oauth2.JWTSessionContainer so JWT access tokens carry our claims +
// the signing-key `kid` header (needed for JWKS rotation).
type Session struct {
	*openid.DefaultSession
	JWTClaims *jwt.JWTClaims `json:"jwt_claims"`
	JWTHeader *jwt.Headers   `json:"jwt_header"`
	// Extra carries our custom access-token claims (tc_app, tc_roles, tc_perm_version).
	Extra map[string]any `json:"extra"`
}

// NewSession builds a fresh session for a subject.
func NewSession(subject, kid, issuer string) *Session {
	headers := &jwt.Headers{Extra: map[string]any{"kid": kid}}
	return &Session{
		DefaultSession: &openid.DefaultSession{
			Claims:    &jwt.IDTokenClaims{Subject: subject, Issuer: issuer},
			Headers:   headers,
			Subject:   subject,
			ExpiresAt: map[fosite.TokenType]time.Time{},
		},
		JWTClaims: &jwt.JWTClaims{Subject: subject, Issuer: issuer, Extra: map[string]any{}},
		JWTHeader: &jwt.Headers{Extra: map[string]any{"kid": kid}},
		Extra:     map[string]any{},
	}
}

// GetJWTClaims implements oauth2.JWTSessionContainer (access-token claims).
func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.JWTClaims == nil {
		s.JWTClaims = &jwt.JWTClaims{Extra: map[string]any{}}
	}
	// Merge custom claims into the access token.
	for k, v := range s.Extra {
		s.JWTClaims.Extra[k] = v
	}
	return s.JWTClaims
}

// GetJWTHeader implements oauth2.JWTSessionContainer.
func (s *Session) GetJWTHeader() *jwt.Headers {
	if s.JWTHeader == nil {
		s.JWTHeader = jwt.NewHeaders()
	}
	return s.JWTHeader
}

// Clone deep-copies the session (required by fosite).
func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	clone := &Session{Extra: map[string]any{}}
	if s.DefaultSession != nil {
		clone.DefaultSession = s.DefaultSession.Clone().(*openid.DefaultSession)
	}
	if s.JWTClaims != nil {
		c := *s.JWTClaims
		clone.JWTClaims = &c
	}
	if s.JWTHeader != nil {
		h := *s.JWTHeader
		clone.JWTHeader = &h
	}
	for k, v := range s.Extra {
		clone.Extra[k] = v
	}
	return clone
}
