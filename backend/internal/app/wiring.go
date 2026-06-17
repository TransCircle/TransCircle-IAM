package app

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/transcircle/iam/internal/api"
	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/auth"
	"github.com/transcircle/iam/internal/authn"
	"github.com/transcircle/iam/internal/authz"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/keys"
	"github.com/transcircle/iam/internal/oauth"
	"github.com/transcircle/iam/internal/rbac"
	"github.com/transcircle/iam/internal/server"
	"github.com/transcircle/iam/internal/sessions"
)

// buildDeps instantiates every subsystem and returns the server dependencies.
func buildDeps(ctx context.Context, rt *runtime, log *slog.Logger) (server.Deps, error) {
	cfg := rt.cfg
	st := rt.st

	ks, err := keys.Load(ctx, st, cfg)
	if err != nil {
		return server.Deps{}, err
	}
	// Propagate signing-key rotations across replicas (must-fix: multi-replica
	// JWKS/kid consistency). Stops when the serve context is cancelled.
	ks.StartAutoReload(ctx, st, cfg, 60*time.Second)

	hasher := crypto.NewHasher(cfg.Argon2Memory, cfg.Argon2Iterations, cfg.Argon2Parallelism, cfg.Argon2MaxConcurrent)
	repo := rbac.Repo{}
	authzSvc := authz.New(st)
	guard := authz.NewGuard(authzSvc, cfg.StepUpWindow)
	auditWriter := audit.NewWriter(st)
	sessMgr := sessions.NewManager(st, cfg.SessionIdleTTL, cfg.SessionAbsoluteTTL)

	// Fail closed if the seeded permission catalog drifted from the code.
	if err := authzSvc.VerifyCatalog(ctx); err != nil {
		return server.Deps{}, err
	}

	cookies := httpx.Cookies{Secure: cfg.CookieSecure, SameSite: cookieSameSite(cfg.CookieSameSite), Domain: cfg.CookieDomain}

	authHandlers := &auth.Handlers{
		Cfg:      cfg,
		Store:    st,
		Cookies:  cookies,
		Sessions: sessMgr,
		Password: authn.NewPasswordService(hasher, 12, 5),
		TOTP:     authn.NewTOTPService(ks, "TransCircle"),
		Recovery: authn.NewRecoveryService(hasher),
		WebAuthn: authn.NewWebAuthnService(st, cfg.Issuer),
		Lockout:  authn.NewLockout(st.Redis, cfg.LockoutThreshold, cfg.LockoutWindow, cfg.LockoutDuration),
		MFA:      authn.MFA{},
		Audit:    auditWriter,
		Authz:    authzSvc,
		Guard:    guard,
		Repo:     repo,
	}

	clients := oauth.NewClientService(st, hasher, ks)
	oauthProvider, err := oauth.NewProvider(ctx, oauth.Deps{
		Cfg: cfg, Store: st, Keys: ks, Hasher: hasher, Clients: clients,
		Authz: authzSvc, Audit: auditWriter, Cookies: cookies,
	})
	if err != nil {
		return server.Deps{}, err
	}

	apiHandlers := &api.Handlers{
		Cfg: cfg, Store: st, Repo: repo, Authz: authzSvc, Guard: guard, Audit: auditWriter,
		Sessions: sessMgr, Clients: clients, Keys: ks, Hasher: hasher, Auth: authHandlers,
	}

	csrf := httpx.CSRF(cookies, cfg.CSRFCookie, oauthCSRFExempt)

	return server.Deps{
		Cfg:   cfg,
		Store: st,
		Log:   log,
		GlobalMiddleware: []func(http.Handler) http.Handler{
			authHandlers.SessionMiddleware,
			csrf,
		},
		Mounters: []server.RouteMounter{authHandlers, oauthProvider, apiHandlers},
	}, nil
}

// oauthCSRFExempt exempts the non-cookie-authenticated machine endpoints
// (Bearer/Basic authed) from CSRF. The consent POST is NOT exempt (cookie-authed).
// The machine permissions API is GET-only and Bearer-authed, so it never reaches
// the CSRF check; the standalone MFA-verification machine API has an unsafe POST,
// so it must be exempted here (it is authenticated solely by an api_token Bearer,
// never by the session cookie, so CSRF gives it no protection anyway).
func oauthCSRFExempt(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/oauth2/token"),
		strings.HasPrefix(p, "/oauth2/introspect"),
		strings.HasPrefix(p, "/oauth2/revoke"),
		strings.HasPrefix(p, "/oauth2/userinfo"),
		strings.HasPrefix(p, "/api/v1/mfa-verifications"):
		return true
	}
	return false
}

func cookieSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
