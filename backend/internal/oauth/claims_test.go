package oauth

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/config"
	"github.com/transcircle/iam/internal/rbac"
)

// TestEnrichStampsClientIDOnAccessToken guards the UserInfo regression: the
// access token MUST carry a client_id claim. UserInfo recovers the OAuth client
// (and thus the bound application) from the access token via stateless JWT
// introspection, but fosite's JWT access-token strategy does not emit client_id
// on its own. Without this claim, introspection yields an empty client id,
// computeAppClaims finds no app, and UserInfo silently drops every tc_* claim.
// Passing only the openid scope keeps enrich off the DB-backed claim paths.
func TestEnrichStampsClientIDOnAccessToken(t *testing.T) {
	p := &Provider{cfg: &config.Config{Issuer: "https://iam.example.org"}}
	sess := NewSession("", "test-kid", p.cfg.Issuer)
	user := &rbac.User{ID: uuid.New(), Username: "zhangsan", DisplayName: "张三"}

	if err := p.enrich(context.Background(), sess, user, "tc_clientid", []string{"openid"}); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if got, _ := sess.Extra["client_id"].(string); got != "tc_clientid" {
		t.Fatalf("access token must carry client_id for stateless-introspection UserInfo; got %q", got)
	}
}

func TestPermFingerprint(t *testing.T) {
	base := permFingerprint([]string{"editor"}, []string{"doc.read", "doc.write"}, []string{"eng"})

	// Order-independent within each category.
	if got := permFingerprint([]string{"editor"}, []string{"doc.write", "doc.read"}, []string{"eng"}); got != base {
		t.Fatalf("fingerprint must be order-independent: %s vs %s", base, got)
	}

	// INTEGRATION.md §5: a change in ANY category must change the fingerprint, so
	// §4's "refresh cached tc_roles when tc_perm_version changes" advice holds.
	if permFingerprint([]string{"editor", "viewer"}, []string{"doc.read", "doc.write"}, []string{"eng"}) == base {
		t.Fatal("adding a role must change the fingerprint")
	}
	if permFingerprint([]string{"editor"}, []string{"doc.read"}, []string{"eng"}) == base {
		t.Fatal("changing permissions must change the fingerprint")
	}
	if permFingerprint([]string{"editor"}, []string{"doc.read", "doc.write"}, []string{"eng", "all-staff"}) == base {
		t.Fatal("joining a group must change the fingerprint")
	}

	// Categories must not collide: the same key in a different category differs.
	if permFingerprint([]string{"x"}, nil, nil) == permFingerprint(nil, []string{"x"}, nil) {
		t.Fatal("a role and a permission with the same key must not collide")
	}

	// Empty across all categories hashes to the sentinel.
	if permFingerprint(nil, nil, nil) != "0" {
		t.Fatal("empty authorization surface should fingerprint to 0")
	}
}

func TestSplitScopes(t *testing.T) {
	got := splitScopes("openid profile  tc.permissions")
	if len(got) != 3 || got[2] != "tc.permissions" {
		t.Fatalf("unexpected: %#v", got)
	}
}
