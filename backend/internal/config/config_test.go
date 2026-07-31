package config

import (
	"net/netip"
	"testing"
)

func TestTrustAllProxies(t *testing.T) {
	t.Setenv("IAM_TRUST_ALL_PROXIES", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Any peer must be trusted under trust-all.
	for _, ip := range []string{"203.0.113.7", "10.1.2.3", "::1"} {
		addr := netip.MustParseAddr(ip)
		trusted := false
		for _, p := range cfg.TrustedProxies {
			if p.Contains(addr) {
				trusted = true
				break
			}
		}
		if !trusted {
			t.Fatalf("expected %s to be trusted under trust-all", ip)
		}
	}
}

func TestProductionRejectsHTTPIssuer(t *testing.T) {
	t.Setenv("IAM_ENV", "prod")
	t.Setenv("IAM_ISSUER", "http://iam.example")
	t.Setenv("IAM_DATABASE_URL", "postgres://iam:strong-password@db:5432/iam?sslmode=require")
	t.Setenv("IAM_REDIS_URL", "redis://:strong-password@redis:6379/0")
	if _, err := Load(); err == nil {
		t.Fatal("expected production HTTP issuer to be rejected")
	}
}

func TestProductionRejectsTrustAll(t *testing.T) {
	t.Setenv("IAM_ENV", "prod")
	t.Setenv("IAM_ISSUER", "https://iam.example")
	t.Setenv("IAM_DATABASE_URL", "postgres://iam:strong-password@db:5432/iam?sslmode=require")
	t.Setenv("IAM_REDIS_URL", "redis://:strong-password@redis:6379/0")
	t.Setenv("IAM_TRUST_ALL_PROXIES", "true")
	if _, err := Load(); err == nil {
		t.Fatal("expected trust-all proxies to be rejected in production")
	}
}

func TestDefaultNoTrust(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Fatalf("expected no trusted proxies by default, got %d", len(cfg.TrustedProxies))
	}
}
