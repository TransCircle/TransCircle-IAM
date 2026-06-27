package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/avatars"
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
		PermVersion: permFingerprint(ap.Roles, ap.Permissions, ap.Groups),
		Permissions: ap.Permissions,
		Groups:      ap.Groups,
	}, nil
}

// permFingerprint is a short stable digest of the user's full per-app
// authorization surface so RPs can detect changes without the complete sets in
// the token (must-fix #4). It covers roles, permissions AND identity groups
// because the integration contract (INTEGRATION.md §5) promises tc_perm_version
// changes on ANY role/permission/group change, and §4 tells RPs to refresh their
// cached tc_roles when it does — both of which break if the digest hashed
// permissions alone (e.g. granting a role whose permissions the user already
// holds would leave a permissions-only hash unchanged). Each category is sorted
// and joined under its own separator so a key moving between categories can
// never collide. Groups are global, so an unrelated group change bumps every
// app's version — that only over-refreshes, which is safe.
func permFingerprint(roles, perms, groups []string) string {
	if len(roles) == 0 && len(perms) == 0 && len(groups) == 0 {
		return "0"
	}
	r, p, g := slices.Clone(roles), slices.Clone(perms), slices.Clone(groups)
	slices.Sort(r)
	slices.Sort(p)
	slices.Sort(g)
	sum := sha256.Sum256([]byte(strings.Join(r, ",") + "|" + strings.Join(p, ",") + "|" + strings.Join(g, ",")))
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

	// Stamp the client_id onto the access token. fosite's JWT access-token
	// strategy does not emit client_id on its own, and UserInfo resolves the
	// per-application tc_* claims via STATELESS JWT introspection — which can only
	// recover the client (and thus the bound application) from a client_id claim.
	// Without this the introspected client id is empty, computeAppClaims looks up
	// an unknown client, and UserInfo silently drops tc_app/tc_roles/
	// tc_permissions/tc_groups/tc_perm_version even though the ID token (built here
	// with the real client id) carries them. Access-token only — the ID token
	// already identifies the client via aud.
	sess.Extra["client_id"] = clientID

	idExtra := sess.DefaultSession.Claims.Extra
	if idExtra == nil {
		idExtra = map[string]any{}
		sess.DefaultSession.Claims.Extra = idExtra
	}
	if slices.Contains(scopes, "profile") {
		idExtra["name"] = user.DisplayName
		idExtra["preferred_username"] = user.Username
		sess.DefaultSession.Username = user.Username
		// `picture` is the durable per-user avatar URL (resolves to the current
		// avatar, survives changes). Omitted when the user has no avatar so RPs
		// don't receive a 404ing link.
		if user.AvatarURL != "" {
			idExtra["picture"] = avatars.UserURL(p.cfg.Issuer, user.ID.String())
		}
	}
	if slices.Contains(scopes, "email") {
		idExtra["email"] = user.Email
	}

	if slices.Contains(scopes, "tc.permissions") {
		ac, err := p.computeAppClaims(ctx, user.ID.String(), clientID)
		if err != nil {
			return err
		}
		// Only emit tc_* when the client is actually bound to an application.
		// computeAppClaims returns a zero value (App == "") for an unbound client;
		// UserInfo already skips the whole block in that case (handleUserinfo), so
		// guard here too — otherwise the token would carry tc_app:"" / tc_roles:null
		// while UserInfo omits them, an inconsistent shape for the same session.
		if ac.App != "" {
			idExtra["tc_app"] = ac.App
			idExtra["tc_roles"] = ac.Roles
			idExtra["tc_perm_version"] = ac.PermVersion
			// The access token carries only app/roles/version — never the full
			// permission set (must-fix #4: keep tokens small; full set via UserInfo/REST).
			sess.Extra["tc_app"] = ac.App
			sess.Extra["tc_roles"] = ac.Roles
			sess.Extra["tc_perm_version"] = ac.PermVersion
		}
	}
	return nil
}
