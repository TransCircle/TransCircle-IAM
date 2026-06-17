import type { AuditEntry } from "@/lib/types";

// Chinese labels for every audit action emitted by the backend. Dynamic
// grant/revoke actions (iam.user.grant.* / iam.user.revoke.*) are handled by
// prefix in auditActionLabel.
const ACTION_LABELS: Record<string, string> = {
  // 认证 / 会话
  "login.success": "登录成功",
  "login.failure": "登录失败",
  "login.locked": "登录被锁定",
  "login.mfa_failure": "多因素验证失败",
  "login.mfa_locked": "多因素验证被锁定",
  logout: "退出登录",
  "password.change": "修改密码",
  "auth.stepup": "二次验证",
  "auth.stepup_failure": "二次验证失败",
  "auth.stepup_locked": "二次验证被锁定",
  "account.profile.update": "更新个人资料",
  "account.avatar.update": "更新头像",
  // 多因素
  "mfa.totp.enroll": "绑定动态口令",
  "mfa.totp.delete": "移除动态口令",
  "mfa.webauthn.register": "注册通行密钥",
  "mfa.webauthn.delete": "删除通行密钥",
  "mfa.webauthn.rename": "重命名通行密钥",
  "mfa.recovery.generate": "生成恢复码",
  // 两步验证接口（对应用提供）
  "mfa.verify.request": "应用发起两步验证",
  "mfa.verify.success": "完成两步验证",
  // OAuth
  "oauth.consent": "OAuth 授权同意",
  "oauth.consent_denied": "OAuth 授权被拒绝",
  "oauth.login_denied": "应用登录被拒绝（访问受限）",
  // 代登
  "impersonate.start": "开始代登",
  "impersonate.stop": "结束代登",
  "impersonate.denied": "代登被拒绝",
  // 用户
  "iam.user.create": "创建用户",
  "iam.user.update": "更新用户",
  "iam.user.delete": "删除用户",
  "iam.user.reset_password": "重置用户密码",
  "iam.user.avatar.update": "更新用户头像",
  // 应用
  "iam.application.create": "创建应用",
  "iam.application.update": "更新应用",
  "iam.application.delete": "删除应用",
  // 权限
  "iam.permission.create": "创建权限",
  "iam.permission.update": "更新权限",
  "iam.permission.delete": "删除权限",
  // 角色
  "iam.role.create": "创建角色",
  "iam.role.update": "更新角色",
  "iam.role.delete": "删除角色",
  "iam.role.set_permissions": "设置角色权限",
  // 身份组
  "iam.group.create": "创建身份组",
  "iam.group.update": "更新身份组",
  "iam.group.delete": "删除身份组",
  "iam.group.add_role": "身份组添加角色",
  "iam.group.remove_role": "身份组移除角色",
  "iam.group.add_members": "身份组添加成员",
  "iam.group.remove_member": "身份组移除成员",
  // OIDC 客户端
  "iam.client.create": "创建 OIDC 客户端",
  "iam.client.update": "更新 OIDC 客户端",
  "iam.client.delete": "删除 OIDC 客户端",
  "iam.client.rotate_secret": "轮换客户端密钥",
  "iam.client.reveal_secret": "查看客户端密钥",
  // API 令牌
  "iam.apptoken.create": "创建 API 令牌",
  "iam.apptoken.update": "更新 API 令牌",
  "iam.apptoken.revoke": "吊销 API 令牌",
  // 会话 / 设置 / 安全
  "iam.session.revoke": "吊销会话",
  "iam.session.revoke_all": "吊销该用户全部会话",
  "iam.settings.webauthn_update": "更新 WebAuthn 设置",
  "iam.settings.policy_update": "更新安全策略",
  "iam.security.rotate_key": "轮换签名密钥",
};

function grantWhat(suffix: string): string {
  if (suffix.startsWith("perm")) return "权限";
  if (suffix.startsWith("group")) return "身份组";
  return "角色";
}

export function auditActionLabel(action: string): string {
  const known = ACTION_LABELS[action];
  if (known) return known;
  if (action.startsWith("iam.user.grant.")) return `授予用户${grantWhat(action.slice(15))}`;
  if (action.startsWith("iam.user.revoke.")) return `撤销用户${grantWhat(action.slice(16))}`;
  return action; // unknown action: show the raw key rather than nothing
}

const TARGET_TYPE_LABELS: Record<string, string> = {
  user: "用户",
  client: "客户端",
  application: "应用",
  permission: "权限",
  role: "角色",
  group: "身份组",
  session: "会话",
  settings: "系统设置",
  signing_key: "签名密钥",
  api_token: "API 令牌",
  mfa_verification: "两步验证",
};

export function auditTargetTypeLabel(t: string): string {
  return TARGET_TYPE_LABELS[t] || t;
}

// auditTargetText renders the operated-on object as "<类型>：<名称>" using the
// backend-resolved label; it falls back to a short id only when no name exists.
export function auditTargetText(e: AuditEntry): string {
  if (!e.target_type) return "—";
  const typeZh = auditTargetTypeLabel(e.target_type);
  const label = e.target_label?.trim();
  if (label) return `${typeZh}：${label}`;
  if (e.target_id) return `${typeZh}（${e.target_id.slice(0, 8)}…）`;
  return typeZh;
}
