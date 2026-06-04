package authz

// Permission catalog — the Go mirror of the system permission keys seeded in
// migration 0004. This is the single source consumed by guards; a startup
// self-check (VerifyCatalog) asserts every key below exists in the DB so the
// seed, these constants, and the frontend list cannot silently drift (must-fix #5).
const (
	PermUsersRead                = "iam.users.read"
	PermUsersWrite               = "iam.users.write"
	PermUsersDelete              = "iam.users.delete"
	PermUsersImpersonate         = "iam.users.impersonate"
	PermUsersImpersonateElevated = "iam.users.impersonate.elevated"
	PermGroupsRead               = "iam.groups.read"
	PermGroupsWrite              = "iam.groups.write"
	PermGroupsDelete             = "iam.groups.delete"
	PermRolesRead                = "iam.roles.read"
	PermRolesWrite               = "iam.roles.write"
	PermRolesDelete              = "iam.roles.delete"
	PermPermsRead                = "iam.permissions.read"
	PermPermsWrite               = "iam.permissions.write"
	PermPermsDelete              = "iam.permissions.delete"
	PermAppsRead                 = "iam.applications.read"
	PermAppsWrite                = "iam.applications.write"
	PermAppsDelete               = "iam.applications.delete"
	PermClientsRead              = "iam.clients.read"
	PermClientsWrite             = "iam.clients.write"
	PermClientsDelete            = "iam.clients.delete"
	PermClientsRotateSecret      = "iam.clients.rotate_secret"
	PermSessionsRead             = "iam.sessions.read"
	PermSessionsRevoke           = "iam.sessions.revoke"
	PermAuditRead                = "iam.audit.read"
	PermSecurityRead             = "iam.security.read"
	PermSecurityRotate           = "iam.security.rotate"
	PermSettingsRead             = "iam.settings.read"
	PermSettingsWrite            = "iam.settings.write"
	PermAPITokensRead            = "iam.apptokens.read"
	PermAPITokensWrite           = "iam.apptokens.write"
	PermAPITokensDelete          = "iam.apptokens.delete"
)

// Catalog is the authoritative list of system permission keys.
var Catalog = []string{
	PermUsersRead, PermUsersWrite, PermUsersDelete, PermUsersImpersonate, PermUsersImpersonateElevated,
	PermGroupsRead, PermGroupsWrite, PermGroupsDelete,
	PermRolesRead, PermRolesWrite, PermRolesDelete,
	PermPermsRead, PermPermsWrite, PermPermsDelete,
	PermAppsRead, PermAppsWrite, PermAppsDelete,
	PermClientsRead, PermClientsWrite, PermClientsDelete, PermClientsRotateSecret,
	PermSessionsRead, PermSessionsRevoke,
	PermAuditRead,
	PermSecurityRead, PermSecurityRotate,
	PermSettingsRead, PermSettingsWrite,
	PermAPITokensRead, PermAPITokensWrite, PermAPITokensDelete,
}
