// Package config loads all runtime configuration from environment variables.
// Everything has a sane default so the system boots zero-config in dev; only
// secrets that must survive restarts are persisted in the DB (see internal/crypto).
package config

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is the fully-resolved runtime configuration.
type Config struct {
	// Env is "dev" or "prod". Controls cookie Secure flag default and error verbosity.
	Env string `env:"IAM_ENV" envDefault:"dev"`

	// Issuer is the public base URL of this IAM (no trailing slash). Used as the
	// OIDC issuer, WebAuthn origin default, and absolute-URL base.
	Issuer string `env:"IAM_ISSUER" envDefault:"http://localhost:8080"`

	HTTPListen    string `env:"IAM_HTTP_LISTEN" envDefault:":8080"`
	MetricsListen string `env:"IAM_METRICS_LISTEN" envDefault:"127.0.0.1:9090"`

	// DatabaseURL is a libpq/pgx connection string.
	DatabaseURL string `env:"IAM_DATABASE_URL" envDefault:"postgres://iam:iam@localhost:5432/iam?sslmode=disable"`

	RedisURL string `env:"IAM_REDIS_URL" envDefault:"redis://localhost:6379/0"`

	// Cookies.
	CookieSecure   bool   `env:"IAM_COOKIE_SECURE"`
	CookieDomain   string `env:"IAM_COOKIE_DOMAIN"`
	SessionCookie  string `env:"IAM_SESSION_COOKIE" envDefault:"__Host-tc_session"`
	CSRFCookie     string `env:"IAM_CSRF_COOKIE" envDefault:"__Host-tc_csrf"`
	CookieSameSite string `env:"IAM_COOKIE_SAMESITE" envDefault:"lax"`

	// Session lifetimes (must-fix #16): idle + absolute, single source of truth.
	SessionIdleTTL     time.Duration `env:"IAM_SESSION_IDLE_TTL" envDefault:"12h"`
	SessionAbsoluteTTL time.Duration `env:"IAM_SESSION_ABSOLUTE_TTL" envDefault:"168h"`
	// LoginTicketTTL bounds the pre-auth login flow.
	LoginTicketTTL time.Duration `env:"IAM_LOGIN_TICKET_TTL" envDefault:"5m"`
	// StepUpWindow: how recently MFA must have been satisfied for sensitive ops.
	StepUpWindow time.Duration `env:"IAM_STEPUP_WINDOW" envDefault:"5m"`

	// Argon2id parameters (PHC encoded, can be tuned up safely).
	Argon2Memory      uint32 `env:"IAM_ARGON2_MEMORY_KIB" envDefault:"65536"`
	Argon2Iterations  uint32 `env:"IAM_ARGON2_ITERATIONS" envDefault:"3"`
	Argon2Parallelism uint8  `env:"IAM_ARGON2_PARALLELISM" envDefault:"2"`
	// Argon2MaxConcurrent caps simultaneous in-flight password hashes (DoS guard, must-fix #11).
	Argon2MaxConcurrent int `env:"IAM_ARGON2_MAX_CONCURRENT" envDefault:"8"`

	// Lockout policy.
	LockoutThreshold int           `env:"IAM_LOCKOUT_THRESHOLD" envDefault:"8"`
	LockoutWindow    time.Duration `env:"IAM_LOCKOUT_WINDOW" envDefault:"15m"`
	LockoutDuration  time.Duration `env:"IAM_LOCKOUT_DURATION" envDefault:"15m"`

	// KEK (optional hardening, must-fix: default off). When enabled the DEK is
	// wrapped by a key supplied via env/secret instead of stored bare.
	KEKEnabled bool   `env:"IAM_KEK_ENABLED"`
	KEK        string `env:"IAM_KEK"`      // base64-std 32 bytes
	KEKFile    string `env:"IAM_KEK_FILE"` // alternative: read base64 from file (docker secret)

	// TrustedProxies: CIDRs whose X-Forwarded-* headers are honored.
	TrustedProxiesRaw string `env:"IAM_TRUSTED_PROXIES" envDefault:""`
	TrustedProxies    []netip.Prefix
	// TrustAllProxies honors X-Forwarded-* from any peer (use only when the app
	// is never reachable except through your trusted reverse proxy).
	TrustAllProxies bool `env:"IAM_TRUST_ALL_PROXIES"`

	// CORSOrigins: allowed browser origins for the SPA (comma separated).
	CORSOriginsRaw string `env:"IAM_CORS_ORIGINS" envDefault:""`
	CORSOrigins    []string

	// Bootstrap.
	BootstrapAdminUsername string `env:"IAM_BOOTSTRAP_ADMIN_USERNAME" envDefault:"admin"`
	BootstrapAdminEmail    string `env:"IAM_BOOTSTRAP_ADMIN_EMAIL" envDefault:"admin@transcircle.internal"`
	// BootstrapOutFile: where the first-admin credentials + recovery codes are written (0600).
	BootstrapOutFile string `env:"IAM_BOOTSTRAP_OUT_FILE" envDefault:"/var/lib/iam/bootstrap.json"`

	// OAuth token lifetimes (defaults; per-client overrides exist).
	AccessTokenTTL  time.Duration `env:"IAM_ACCESS_TOKEN_TTL" envDefault:"15m"`
	RefreshTokenTTL time.Duration `env:"IAM_REFRESH_TOKEN_TTL" envDefault:"720h"`
	IDTokenTTL      time.Duration `env:"IAM_ID_TOKEN_TTL" envDefault:"15m"`

	// MigrateOnBoot lets `serve` apply migrations itself (dev). Prod uses the
	// one-shot migrate service instead.
	MigrateOnBoot bool `env:"IAM_MIGRATE_ON_BOOT" envDefault:"true"`
}

// Load parses configuration from the environment and derives computed fields.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse env: %w", err)
	}
	if cfg.Env == "prod" {
		// In prod default cookies to Secure unless explicitly overridden by env presence.
		cfg.CookieSecure = true
	}

	if cfg.TrustAllProxies {
		// Trust X-Forwarded-* from any peer (IPv4 + IPv6 catch-all).
		cfg.TrustedProxies = []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}
	}
	for _, raw := range splitList(cfg.TrustedProxiesRaw) {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			// Allow a bare IP too.
			addr, aerr := netip.ParseAddr(raw)
			if aerr != nil {
				return nil, fmt.Errorf("invalid trusted proxy %q: %w", raw, err)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, p)
	}
	cfg.CORSOrigins = splitList(cfg.CORSOriginsRaw)
	if len(cfg.CORSOrigins) == 0 {
		cfg.CORSOrigins = []string{cfg.Issuer}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.SessionAbsoluteTTL < c.SessionIdleTTL {
		return fmt.Errorf("session absolute TTL (%s) must be >= idle TTL (%s)", c.SessionAbsoluteTTL, c.SessionIdleTTL)
	}
	if c.Argon2MaxConcurrent < 1 {
		return fmt.Errorf("argon2 max concurrent must be >= 1")
	}
	switch strings.ToLower(c.CookieSameSite) {
	case "lax", "strict", "none":
	default:
		return fmt.Errorf("invalid cookie samesite %q", c.CookieSameSite)
	}
	return nil
}

// IsProd reports whether the system runs in production mode.
func (c *Config) IsProd() bool { return c.Env == "prod" }

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
