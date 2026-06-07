package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/rbac"
)

func uuidFromString(s string) (uuid.UUID, error) { return uuid.Parse(s) }

// appClaims is the per-application authorization snapshot injected into tokens.
type appClaims struct {
	App         string   `json:"tc_app"`
	Roles       []string `json:"tc_roles"`
	PermVersion string   `json:"tc_perm_version"`
	Permissions []string `json:"-"` // full set delivered via userinfo / REST, not the ID token
	Groups      []string `json:"-"` // identity-group keys delivered via userinfo / REST
}

// computeAppClaims resolves the requesting client's app context for the user.
// Returns zero value if the client is not bound to an application.
func (p *Provider) computeAppClaims(ctx context.Context, userID, clientID string) (appClaims, error) {
	client, err := p.clients.Get(ctx, p.store.Pool, clientID)
	if err != nil || client.AppID == nil {
		return appClaims{}, nil
	}
	uid, err := uuidFromString(userID)
	if err != nil {
		return appClaims{}, nil
	}
	app, err := p.repo.GetApplication(ctx, p.store.Pool, *client.AppID)
	if err != nil {
		return appClaims{}, nil
	}
	ap, err := p.authz.AppPermissions(ctx, uid, app.ID, app.Key)
	if err != nil {
		return appClaims{}, err
	}
	return appClaims{
		App:         ap.AppKey,
		Roles:       ap.Roles,
		PermVersion: permHash(ap.Permissions),
		Permissions: ap.Permissions,
		Groups:      ap.Groups,
	}, nil
}

// permHash is a short stable digest so RPs can detect permission changes without
// the full set in the ID token (must-fix #4).
func permHash(perms []string) string {
	if len(perms) == 0 {
		return "0"
	}
	sorted := slices.Clone(perms)
	slices.Sort(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, ",")))
	return hex.EncodeToString(sum[:])[:12]
}

// enrich populates the OIDC + access-token claims for a session given the granted
// scopes. The full permission set goes only into the access token's tc_permissions
// when the tc.permissions scope is granted; the ID token carries roles + version.
func (p *Provider) enrich(ctx context.Context, sess *Session, user *rbac.User, clientID string, scopes []string) error {
	sess.Subject = user.ID.String()
	sess.DefaultSession.Subject = user.ID.String()
	sess.DefaultSession.Claims.Subject = user.ID.String()
	sess.DefaultSession.Claims.Issuer = p.cfg.Issuer

	idExtra := sess.DefaultSession.Claims.Extra
	if idExtra == nil {
		idExtra = map[string]any{}
		sess.DefaultSession.Claims.Extra = idExtra
	}
	if slices.Contains(scopes, "profile") {
		idExtra["name"] = user.DisplayName
		idExtra["preferred_username"] = user.Username
		sess.DefaultSession.Username = user.Username
	}
	if slices.Contains(scopes, "email") {
		idExtra["email"] = user.Email
	}

	if slices.Contains(scopes, "tc.permissions") {
		ac, err := p.computeAppClaims(ctx, user.ID.String(), clientID)
		if err != nil {
			return err
		}
		idExtra["tc_app"] = ac.App
		idExtra["tc_roles"] = ac.Roles
		idExtra["tc_perm_version"] = ac.PermVersion
		// The access token carries only app/roles/version — never the full
		// permission set (must-fix #4: keep tokens small; full set via UserInfo/REST).
		sess.Extra["tc_app"] = ac.App
		sess.Extra["tc_roles"] = ac.Roles
		sess.Extra["tc_perm_version"] = ac.PermVersion
	}
	return nil
}
