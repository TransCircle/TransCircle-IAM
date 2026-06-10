// Package authctx carries the authenticated principal through the request
// context. It is dependency-free so both the auth and authz packages can import
// it without a cycle.
package authctx

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Principal is the authenticated caller for a request: either a user session or
// a machine token.
type Principal struct {
	UserID       uuid.UUID
	SessionID    uuid.UUID
	Username     string
	AAL          int
	MFASatisfied bool
	MFAAt        time.Time
	// AuthAt is when the underlying session was established (the OIDC auth_time);
	// AMR is the authentication-methods list recorded at login (e.g. pwd, otp).
	AuthAt time.Time
	AMR    []string
	// ImpersonatorID is set when an admin is acting as this user.
	ImpersonatorID    uuid.UUID
	ImpersonatorLabel string

	// Machine token fields (mutually exclusive with a user session).
	IsMachine   bool
	TokenName   string
	TokenScopes []string
	AllowedApps []string
}

// Impersonating reports whether this principal is an admin login-as session.
func (p *Principal) Impersonating() bool { return p.ImpersonatorID != uuid.Nil }

type ctxKey struct{}

// With stores the principal in ctx.
func With(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// From returns the principal, if any.
func From(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}
