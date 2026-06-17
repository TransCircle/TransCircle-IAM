// Package api implements the protected REST surface: the admin console endpoints
// (guarded per iam.* permission, atomic, audited) and the external machine-facing
// permissions API.
package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/auth"
	"github.com/transcircle/iam/internal/authz"
	"github.com/transcircle/iam/internal/config"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/keys"
	"github.com/transcircle/iam/internal/oauth"
	"github.com/transcircle/iam/internal/rbac"
	"github.com/transcircle/iam/internal/sessions"
	"github.com/transcircle/iam/internal/store"
)

// Handlers serves the admin + machine REST API.
type Handlers struct {
	Cfg      *config.Config
	Store    *store.Store
	Repo     rbac.Repo
	Authz    *authz.Service
	Guard    *authz.Guard
	Audit    *audit.Writer
	Sessions *sessions.Manager
	Clients  *oauth.ClientService
	Keys     *keys.KeyStore
	Hasher   *crypto.Hasher
	Auth     *auth.Handlers
}

// Mount registers all REST routes.
func (h *Handlers) Mount(r chi.Router) {
	// External machine-to-machine permissions API (Bearer api_token).
	r.Group(func(r chi.Router) {
		r.Use(h.machineAuth)
		r.Method("GET", "/api/v1/permissions", httpx.Handler(h.handlePermissionsAPI))
	})

	// Admin API: authenticated + onboarded + per-permission guarded.
	r.Group(func(r chi.Router) {
		r.Use(h.Auth.RequireAuth)
		r.Use(h.Auth.Gate)

		// Users
		r.Method("GET", "/api/v1/admin/users", h.guard(authz.PermUsersRead, h.listUsers))
		r.Method("POST", "/api/v1/admin/users", h.guard(authz.PermUsersWrite, h.createUser))
		r.Method("GET", "/api/v1/admin/users/{id}", h.guard(authz.PermUsersRead, h.getUser))
		r.Method("PATCH", "/api/v1/admin/users/{id}", h.guard(authz.PermUsersWrite, h.updateUser))
		r.Method("DELETE", "/api/v1/admin/users/{id}", h.guardStepUp(authz.PermUsersDelete, h.deleteUser))
		r.Method("POST", "/api/v1/admin/users/{id}/reset-password", h.guardStepUp(authz.PermUsersWrite, h.resetPassword))
		r.Method("POST", "/api/v1/admin/users/{id}/avatar", h.guard(authz.PermUsersWrite, h.uploadUserAvatar))
		r.Method("GET", "/api/v1/admin/users/{id}/assignments", h.guard(authz.PermUsersRead, h.getUserAssignments))
		r.Method("POST", "/api/v1/admin/users/{id}/roles", h.guard(authz.PermUsersWrite, h.addUserRole))
		r.Method("DELETE", "/api/v1/admin/users/{id}/roles/{roleID}", h.guard(authz.PermUsersWrite, h.removeUserRole))
		r.Method("POST", "/api/v1/admin/users/{id}/permissions", h.guard(authz.PermUsersWrite, h.addUserPermission))
		r.Method("DELETE", "/api/v1/admin/users/{id}/permissions/{permID}", h.guard(authz.PermUsersWrite, h.removeUserPermission))
		r.Method("POST", "/api/v1/admin/users/{id}/groups", h.guard(authz.PermUsersWrite, h.addUserToGroup))
		r.Method("DELETE", "/api/v1/admin/users/{id}/groups/{groupID}", h.guard(authz.PermUsersWrite, h.removeUserFromGroup))
		r.Method("POST", "/api/v1/admin/users/{id}/impersonate", h.guardStepUp(authz.PermUsersImpersonate, h.startImpersonation))
		r.Method("POST", "/api/v1/admin/impersonation/stop", httpx.Handler(h.stopImpersonation))

		// Applications
		r.Method("GET", "/api/v1/admin/applications", h.guard(authz.PermAppsRead, h.listApplications))
		r.Method("POST", "/api/v1/admin/applications", h.guard(authz.PermAppsWrite, h.createApplication))
		r.Method("PATCH", "/api/v1/admin/applications/{id}", h.guard(authz.PermAppsWrite, h.updateApplication))
		r.Method("DELETE", "/api/v1/admin/applications/{id}", h.guardStepUp(authz.PermAppsDelete, h.deleteApplication))

		// Permissions
		r.Method("GET", "/api/v1/admin/applications/{appID}/permissions", h.guard(authz.PermPermsRead, h.listPermissions))
		r.Method("POST", "/api/v1/admin/applications/{appID}/permissions", h.guard(authz.PermPermsWrite, h.createPermission))
		r.Method("PATCH", "/api/v1/admin/permissions/{id}", h.guard(authz.PermPermsWrite, h.updatePermission))
		r.Method("DELETE", "/api/v1/admin/permissions/{id}", h.guard(authz.PermPermsDelete, h.deletePermission))

		// Roles
		r.Method("GET", "/api/v1/admin/applications/{appID}/roles", h.guard(authz.PermRolesRead, h.listRoles))
		r.Method("POST", "/api/v1/admin/applications/{appID}/roles", h.guard(authz.PermRolesWrite, h.createRole))
		r.Method("PATCH", "/api/v1/admin/roles/{id}", h.guard(authz.PermRolesWrite, h.updateRole))
		r.Method("DELETE", "/api/v1/admin/roles/{id}", h.guard(authz.PermRolesDelete, h.deleteRole))
		r.Method("GET", "/api/v1/admin/roles/{id}/permissions", h.guard(authz.PermRolesRead, h.getRolePermissions))
		r.Method("PUT", "/api/v1/admin/roles/{id}/permissions", h.guard(authz.PermRolesWrite, h.setRolePermissions))

		// Groups
		r.Method("GET", "/api/v1/admin/groups", h.guard(authz.PermGroupsRead, h.listGroups))
		r.Method("POST", "/api/v1/admin/groups", h.guard(authz.PermGroupsWrite, h.createGroup))
		r.Method("PATCH", "/api/v1/admin/groups/{id}", h.guard(authz.PermGroupsWrite, h.updateGroup))
		r.Method("DELETE", "/api/v1/admin/groups/{id}", h.guard(authz.PermGroupsDelete, h.deleteGroup))
		r.Method("GET", "/api/v1/admin/groups/{id}", h.guard(authz.PermGroupsRead, h.getGroup))
		r.Method("POST", "/api/v1/admin/groups/{id}/members", h.guard(authz.PermGroupsWrite, h.addGroupMembers))
		r.Method("DELETE", "/api/v1/admin/groups/{id}/members/{userID}", h.guard(authz.PermGroupsWrite, h.removeGroupMember))
		r.Method("POST", "/api/v1/admin/groups/{id}/roles", h.guard(authz.PermGroupsWrite, h.addGroupRole))
		r.Method("DELETE", "/api/v1/admin/groups/{id}/roles/{roleID}", h.guard(authz.PermGroupsWrite, h.removeGroupRole))

		// OAuth clients
		r.Method("GET", "/api/v1/admin/clients", h.guard(authz.PermClientsRead, h.listClients))
		r.Method("GET", "/api/v1/admin/clients/{clientID}", h.guard(authz.PermClientsRead, h.getClient))
		r.Method("POST", "/api/v1/admin/clients", h.guard(authz.PermClientsWrite, h.createClient))
		r.Method("PATCH", "/api/v1/admin/clients/{clientID}", h.guard(authz.PermClientsWrite, h.updateClient))
		r.Method("DELETE", "/api/v1/admin/clients/{clientID}", h.guardStepUp(authz.PermClientsDelete, h.deleteClient))
		r.Method("POST", "/api/v1/admin/clients/{clientID}/rotate-secret", h.guardStepUp(authz.PermClientsRotateSecret, h.rotateClientSecret))
		r.Method("POST", "/api/v1/admin/clients/{clientID}/secret/reveal", h.guardStepUp(authz.PermClientsRotateSecret, h.revealClientSecret))

		// Sessions (admin)
		r.Method("GET", "/api/v1/admin/users/{id}/sessions", h.guard(authz.PermSessionsRead, h.listUserSessions))
		r.Method("DELETE", "/api/v1/admin/sessions/{sid}", h.guard(authz.PermSessionsRevoke, h.revokeSession))
		r.Method("POST", "/api/v1/admin/users/{id}/sessions/revoke-all", h.guard(authz.PermSessionsRevoke, h.revokeAllUserSessions))

		// Audit
		r.Method("GET", "/api/v1/admin/audit", h.guard(authz.PermAuditRead, h.listAudit))

		// Settings
		r.Method("GET", "/api/v1/admin/settings/webauthn", h.guard(authz.PermSettingsRead, h.getWebAuthnRP))
		r.Method("PUT", "/api/v1/admin/settings/webauthn", h.guardStepUp(authz.PermSettingsWrite, h.updateWebAuthnRP))
		r.Method("GET", "/api/v1/admin/settings/policy", h.guard(authz.PermSettingsRead, h.getPolicy))
		r.Method("PUT", "/api/v1/admin/settings/policy", h.guardStepUp(authz.PermSettingsWrite, h.updatePolicy))

		// Security (keys)
		r.Method("GET", "/api/v1/admin/security/keys", h.guard(authz.PermSecurityRead, h.listKeys))
		r.Method("POST", "/api/v1/admin/security/keys/rotate", h.guardStepUp(authz.PermSecurityRotate, h.rotateSigningKey))

		// API tokens
		r.Method("GET", "/api/v1/admin/api-tokens/meta", h.guard(authz.PermAPITokensRead, h.apiTokenMeta))
		r.Method("GET", "/api/v1/admin/api-tokens", h.guard(authz.PermAPITokensRead, h.listAPITokens))
		r.Method("POST", "/api/v1/admin/api-tokens", h.guardStepUp(authz.PermAPITokensWrite, h.createAPIToken))
		r.Method("PATCH", "/api/v1/admin/api-tokens/{id}", h.guardStepUp(authz.PermAPITokensWrite, h.updateAPIToken))
		r.Method("DELETE", "/api/v1/admin/api-tokens/{id}", h.guardStepUp(authz.PermAPITokensDelete, h.revokeAPIToken))

		// Dashboard stats
		r.Method("GET", "/api/v1/admin/stats", h.guard(authz.PermUsersRead, h.dashboardStats))
	})
}

// guard chains a permission check before the handler.
func (h *Handlers) guard(perm string, fn httpx.Handler) http.Handler {
	return h.Guard.RequirePermission(perm)(fn)
}

// guardStepUp additionally requires recent MFA (sensitive operations).
func (h *Handlers) guardStepUp(perm string, fn httpx.Handler) http.Handler {
	return h.Guard.RequirePermission(perm)(h.Guard.RequireStepUp()(fn))
}

// tx runs fn in a transaction (atomicity helper).
func (h *Handlers) tx(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx) error) error {
	return h.Store.WithTx(ctx, fn)
}

// orEmpty coalesces a nil slice to an empty one so NOT NULL text[] columns are
// never sent a SQL NULL (pgx encodes a nil slice as NULL; an explicitly-listed
// column bypasses the table's DEFAULT '{}').
func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
