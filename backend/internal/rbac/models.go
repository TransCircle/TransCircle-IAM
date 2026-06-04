// Package rbac owns the identity + authorization data model: users, applications,
// permissions, roles, groups, their assignments, and the effective-permission
// computation that the authz guard and OIDC claims both consume.
package rbac

import (
	"time"

	"github.com/google/uuid"
)

// SystemAppID and SuperAdminRoleID are the fixed seed identities from 0004.
var (
	SystemAppID    = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	SuperAdminRole = uuid.MustParse("00000000-0000-0000-0000-000000000002")
	SystemAppKey   = "system"
	SuperAdminKey  = "super_admin"
)

// User is an account.
type User struct {
	ID                  uuid.UUID `json:"id"`
	Username            string    `json:"username"`
	Email               string    `json:"email"`
	DisplayName         string    `json:"display_name"`
	Status              string    `json:"status"`
	IsActive            bool      `json:"is_active"`
	ForcePasswordChange bool      `json:"force_password_change"`
	MustEnrollMFA       bool      `json:"must_enroll_mfa"`
	PermVersion         int64     `json:"-"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// Application is a permission scope (the built-in "system" app, or an integration).
type Application struct {
	ID          uuid.UUID `json:"id"`
	Key         string    `json:"key"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description"`
	IsSystem    bool      `json:"is_system"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Permission is a single, application-scoped capability with management metadata.
type Permission struct {
	ID            uuid.UUID `json:"id"`
	ApplicationID uuid.UUID `json:"application_id"`
	Key           string    `json:"key"`
	DisplayName   string    `json:"display_name"`
	Description   string    `json:"description"`
	Notes         string    `json:"notes"`
	Category      string    `json:"category"`
	IsSystem      bool      `json:"is_system"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Role is a named bundle of permissions within an application.
type Role struct {
	ID            uuid.UUID `json:"id"`
	ApplicationID uuid.UUID `json:"application_id"`
	Key           string    `json:"key"`
	DisplayName   string    `json:"display_name"`
	Description   string    `json:"description"`
	Notes         string    `json:"notes"`
	IsSystem      bool      `json:"is_system"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Group is a global organizational unit that grants roles to its members.
type Group struct {
	ID          uuid.UUID `json:"id"`
	Key         string    `json:"key"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// EffectivePermission is a resolved permission with its app context.
type EffectivePermission struct {
	AppID   uuid.UUID `json:"app_id"`
	AppKey  string    `json:"app_key"`
	PermKey string    `json:"permission"`
}

// AppPermissions groups a user's effective roles + permissions for one application,
// shaped for the OIDC claims / permissions API.
type AppPermissions struct {
	AppID       uuid.UUID `json:"app_id"`
	AppKey      string    `json:"app_key"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
}
