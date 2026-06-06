export interface MeUser {
  id: string;
  username: string;
  display_name: string;
  email: string;
  status: string;
}

export interface MFAStatus {
  passkeys: number;
  totp: boolean;
  recovery_codes: number;
}

export interface Me {
  user: MeUser;
  required_action: "none" | "change_password" | "enroll_mfa";
  mfa: MFAStatus;
  permissions: string[];
  roles: string[];
  is_super_admin: boolean;
  impersonator: { id: string; username: string } | null;
}

// Fixed built-in role IDs (mirror of backend rbac.SuperAdminRole / AdminRole).
export const SUPER_ADMIN_ROLE_ID = "00000000-0000-0000-0000-000000000002";
export const ADMIN_ROLE_ID = "00000000-0000-0000-0000-000000000003";

export interface User {
  id: string;
  username: string;
  email: string;
  display_name: string;
  status: string;
  is_active: boolean;
  force_password_change: boolean;
  must_enroll_mfa: boolean;
  created_at: string;
  updated_at: string;
}

export interface Application {
  id: string;
  key: string;
  display_name: string;
  description: string;
  is_system: boolean;
  is_active: boolean;
}

export interface Permission {
  id: string;
  application_id: string;
  key: string;
  display_name: string;
  description: string;
  notes: string;
  category: string;
  is_system: boolean;
}

export interface Role {
  id: string;
  application_id: string;
  key: string;
  display_name: string;
  description: string;
  notes: string;
  is_system: boolean;
}

export interface Group {
  id: string;
  key: string;
  display_name: string;
  description: string;
  is_system: boolean;
}

export interface OAuthClient {
  id: string;
  client_id: string;
  client_name: string;
  app_id: string | null;
  public: boolean;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  grant_types: string[];
  allowed_scopes: string[];
  allowed_app_keys: string[];
  skip_consent: boolean;
  active: boolean;
  has_secret: boolean;
}

export interface Session {
  id: string;
  user_id: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  ip: string;
  user_agent: string;
  amr: string[];
  aal: number;
  mfa_satisfied: boolean;
  impersonator_user_id: string | null;
}

export interface AuditEntry {
  id: string;
  occurred_at: string;
  actor_label: string;
  action: string;
  target_type: string;
  target_id: string;
  result: string;
  ip: string;
  request_id: string;
  metadata: unknown;
}

export interface SigningKeyInfo {
  kid: string;
  algorithm: string;
  status: string;
  created_at: string;
  activated_at: string | null;
}

export interface APIToken {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  allowed_app_keys: string[];
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  created_at: string;
}
