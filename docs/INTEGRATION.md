# TransCircle-IAM 接入指南

把 TransCircle 作为统一登录（SSO）与权限中心接入你的应用。本文是面向第三方开发者的完整、可照做的集成手册。文中以 `https://iam.example.com` 代指 IAM 的对外地址（即你反向代理到的那个端口），请替换为实际值。

---

## 0. 三种接入方式

| 方式 | 面向 | 用途 |
|---|---|---|
| ① OIDC 单点登录 | 用户登录 | 用户经本系统登录你的应用；登录后拿到用户身份与「在你这个应用下」的角色/权限/身份组。 |
| ② 机器权限 API | 后端鉴权 | 你的后端用 API 令牌随时查询「某用户在某应用下」的角色/权限/身份组。 |
| ③ 独立两步验证接口 | 敏感操作前校验本人 | 你的后端发起验证请求拿到验证链接，引导用户到本系统完成 通行密钥 / TOTP，再回查权威结果（见 §3）。需令牌带 `iam.mfa.verify` 作用域。 |

**术语与维度**

- **应用 (application)**：一个独立的权限作用域，唯一 `key`（如 `wiki`）。
- **角色 (role) / 权限 (permission)**：**按应用**划分；用户在应用 A 与应用 B 的角色互不相干。
- **身份组 (group)**：**全局**组织结构，把一批角色批量授予成员。接入方拿到的是「身份组 + 直接授权」共同推导出的最终结果。

---

## 1. OIDC 单点登录

### 1.1 前置

在「管理 → OIDC 客户端」新建客户端，绑定到对应「应用」，勾选所需 scope（`openid profile email tc.permissions`），保存后复制一次性密钥（公共客户端无密钥）。

### 1.2 端点详解（每个端点是什么、怎么用）

签名算法固定 **RS256**，用 JWKS 校验 ID Token；**强制 Authorization Code + PKCE（S256）**。

#### `GET /.well-known/openid-configuration` — OIDC 发现文档（无需认证）

一份机器可读的 JSON，声明本系统的全部端点地址、支持的 scope、响应类型、签名算法、PKCE 方式等。标准 OIDC 客户端库通常只需配置 `issuer`（本系统地址），即可自动拉取此文档得到其余端点，**无需手写端点 URL**。

```json
{
  "issuer": "https://iam.example.com",
  "authorization_endpoint": "https://iam.example.com/oauth2/auth",
  "token_endpoint": "https://iam.example.com/oauth2/token",
  "userinfo_endpoint": "https://iam.example.com/oauth2/userinfo",
  "jwks_uri": "https://iam.example.com/.well-known/jwks.json",
  "introspection_endpoint": "https://iam.example.com/oauth2/introspect",
  "revocation_endpoint": "https://iam.example.com/oauth2/revoke",
  "scopes_supported": ["openid","profile","email","offline_access","tc.permissions"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code","refresh_token","client_credentials"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "code_challenge_methods_supported": ["S256"],
  "claims_supported": ["sub","name","preferred_username","email","tc_app","tc_roles","tc_permissions","tc_groups","tc_perm_version"]
}
```

#### `GET /.well-known/jwks.json`（别名 `/jwks.json`） — JWKS 公钥集（无需认证）

**JWKS = JSON Web Key Set（JSON 网络密钥集）。** 本系统用 **RS256**（RSA 非对称签名）给 `id_token` 与 `access_token` 签名；JWKS 发布对应的**公钥**，供你的应用**验证令牌签名**——即确认令牌确实由本 IAM 签发、且内容未被篡改。私钥永远只在服务端，绝不下发。

- 用法：JWT 头部带一个 `kid`（密钥编号）；在 JWKS 里找到相同 `kid` 的公钥验签。绝大多数 OIDC 库会自动完成。
- **密钥轮换**：会同时发布「当前」与「上一把」公钥，轮换期间旧令牌仍可验。建议**缓存 JWKS**，遇到未知 `kid` 时再刷新，而不是每次请求都拉取。

```json
{ "keys": [
  { "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"<密钥编号>", "n":"<modulus>", "e":"AQAB" }
] }
```

#### `GET|POST /oauth2/auth` — 授权端点（浏览器登录态）

让浏览器重定向到这里发起登录。若用户未登录会先跳登录页，登录后回到授权。**强制 PKCE（S256）**；对非「可信客户端」展示授权同意屏，且**每次授权都需用户确认**（除非客户端被标记为可信、可跳过同意）。成功后 302 回 `redirect_uri`，带 `code` 与 `state`。

#### `POST /oauth2/token` — 令牌端点（客户端凭据 / PKCE）

用授权码换令牌或刷新令牌，支持三种 grant：

- `authorization_code`：用 `code` + `code_verifier` 换 access/id/refresh token。
- `refresh_token`：用 refresh_token 换新令牌（需 `offline_access`；一次性轮换）。
- `client_credentials`：无用户上下文，机器以自身身份取访问令牌。

机密客户端用 `client_secret_basic`/`client_secret_post` 认证；公共客户端用 PKCE 代替密钥。

#### `GET|POST /oauth2/userinfo` — 用户信息（Bearer access_token）

携带 access_token 调用，返回当前用户声明，内容随被授予的 scope 而定；带 `tc.permissions` 时返回**完整**的 `tc_permissions` 与 `tc_groups`（令牌本身不含完整列表）。

#### `POST /oauth2/introspect` — 令牌内省 RFC 7662（客户端凭据）

后端用客户端凭据查询「某令牌是否仍有效」及其元数据（`active`、`scope`、`sub`、`exp` 等）。适合不自己解析 JWT、而向 IdP 核实的场景。

#### `POST /oauth2/revoke` — 令牌吊销 RFC 7009（客户端凭据）

主动作废 **refresh token**（立即失效,并连带其令牌族）。注意:**access token 是自包含 JWT,不做中心化即时吊销**——最多在其较短有效期(TTL,默认 ≤15 分钟)后自然失效;若资源服务需要即时收敛,请用 `/oauth2/introspect` 核实,或借助 `tc_perm_version` 做权限版本校验。

#### `GET /api/v1/permissions` — 机器权限 API（Bearer `tcp_` 令牌）

后端服务用 API 令牌查询「某用户在某应用下」的角色/权限/身份组，详见第 6 节。

### 1.3 步骤 1 — 跳转授权

```
GET https://iam.example.com/oauth2/auth?
  response_type=code
  &client_id=<client_id>
  &redirect_uri=<已登记回调>
  &scope=openid%20profile%20email%20tc.permissions
  &state=<随机, 防 CSRF>
  &nonce=<随机, 防重放>
  &code_challenge=<BASE64URL(SHA256(code_verifier))>
  &code_challenge_method=S256
```

用户登录并授权后跳回 `redirect_uri?code=...&state=...`，请校验 `state`。

### 1.4 步骤 2 — 用 code 换令牌

```bash
curl -X POST https://iam.example.com/oauth2/token \
  -d grant_type=authorization_code \
  -d code=<code> \
  -d redirect_uri=<同上> \
  -d client_id=<client_id> \
  -d client_secret=<client_secret> \   # 机密客户端必填
  -d code_verifier=<verifier>          # 公共客户端用它代替 secret
```

返回：

```json
{
  "access_token": "<JWT>",
  "id_token": "<JWT>",
  "refresh_token": "<仅当 scope 含 offline_access>",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### 1.5 步骤 3 — 校验 ID Token

用 JWKS 校验签名，并校验 `iss` / `aud` / `nonce` / `exp`。ID Token 为**精简载荷**：

```json
{
  "sub": "<用户ID, UUID>",
  "preferred_username": "zhangsan",
  "name": "张三",
  "email": "zhangsan@example.com",
  "tc_app": "wiki",
  "tc_roles": ["editor", "viewer"],
  "tc_perm_version": "a1b2c3d4e5f6"
}
```

### 1.6 步骤 4 — 刷新令牌（需 `offline_access`）

```bash
curl -X POST https://iam.example.com/oauth2/token \
  -d grant_type=refresh_token -d refresh_token=<rt> \
  -d client_id=<client_id> -d client_secret=<client_secret>
```

> refresh_token 一次性轮换：旧令牌用后即废，**复用会触发整条令牌族被吊销**（防盗用）。

---

## 2. 作用域与声明

| scope | 含义 |
|---|---|
| `openid` | 必选，签发 ID Token |
| `profile` | `name`、`preferred_username` |
| `email` | `email` |
| `offline_access` | 签发 refresh_token |
| `tc.permissions` | 该应用下的角色/权限/身份组与权限指纹 |

**令牌为何精简**：为控制体积，**ID Token 与 Access Token 只带 `tc_app`、`tc_roles`、`tc_perm_version`**，不含完整权限表与身份组列表。完整列表通过 UserInfo 或机器 API 获取。

| 声明 | 含义 | 出现位置 |
|---|---|---|
| `tc_app` | 当前客户端绑定的应用 key | id_token / access_token / userinfo |
| `tc_roles` | 用户在该应用下的角色 key 列表 | id_token / access_token / userinfo |
| `tc_permissions` | 用户在该应用下的权限 key 列表 | **仅** userinfo / 机器 API |
| `tc_groups` | 用户所属身份组 key 列表（全局） | **仅** userinfo / 机器 API |
| `tc_perm_version` | 权限集合指纹（变化即代表权限已变） | id_token / access_token / userinfo |

---

## 3. 获取「用户权限表 + 身份组列表」

**方式 A：UserInfo（登录态，带 `tc.permissions`）**

```bash
curl https://iam.example.com/oauth2/userinfo -H "Authorization: Bearer <access_token>"
```

```json
{
  "sub": "<用户ID>",
  "preferred_username": "zhangsan",
  "email": "zhangsan@example.com",
  "tc_app": "wiki",
  "tc_roles": ["editor"],
  "tc_permissions": ["doc.read", "doc.write"],
  "tc_groups": ["engineering", "all-staff"],
  "tc_perm_version": "a1b2c3d4e5f6"
}
```

**方式 B：机器权限 API（后端，见第 5 节）** —— 返回 `roles` / `permissions` / `groups`。

---

## 4. 如何确认某用户是否拥有某权限

系统**不提供**「校验单个权限」的专用端点。推荐取得完整权限列表后在你侧判断成员关系：

```js
const { permissions } = await fetchPermissions(userId, "wiki"); // 机器 API
const allowed = permissions.includes("doc.write");
```

- **权威来源**：机器 API / UserInfo 的实时返回总是以服务端为准。
- **本地缓存（advisory）**：可缓存 `tc_roles` 与 `tc_perm_version`；当 `tc_perm_version` 变化时刷新缓存。

---

## 5. tc_perm_version 与缓存一致性

`tc_perm_version` 是该用户在该应用下「权限集合」的稳定指纹。只要其角色/权限/身份组发生任何变化，它一定改变。

把它当作缓存键：缓存权限结果并记录当时的版本；拿到新令牌或调用接口时若版本不同就刷新。服务端内部以每用户 `perm_version` + 全局 `authz_epoch` 保证缓存一致，你只需遵循「版本变了就刷新」。

---

## 6. 机器权限 API（M2M）

在「管理 → API 令牌」创建令牌（可限定 scope 与可访问应用）。令牌格式 `tcp_<prefix>_<secret>`，仅创建时显示一次。

```bash
curl "https://iam.example.com/api/v1/permissions?user=zhangsan&app=wiki" \
  -H "Authorization: Bearer tcp_xxxxxx_xxxxxxxxxxxxxxxxxxxxxxxx"
```

```json
{
  "app_id": "...",
  "app_key": "wiki",
  "roles": ["editor"],
  "permissions": ["doc.read", "doc.write"],
  "groups": ["engineering", "all-staff"]
}
```

- 令牌必须包含 `iam.permissions.read` 作用域。
- 令牌若设置「限定应用」，只能查询这些应用（否则 403）；留空表示不限定（仅超级管理员可创建）。
- `user` 支持用户名或用户 UUID；`app` 为应用 key。

---

## 6b. 独立两步验证接口（外包 2FA）

当你的应用在某个敏感操作前需要确认「确实是本人」时，可把两步验证外包给本系统：后端发起验证请求，拿到一个本系统的验证链接，把用户引导过去完成 **通行密钥 / 动态口令 (TOTP)**，随后后端用 API 令牌**回查权威结果**。无需自己实现/存储 2FA。

**前置**：API 令牌需勾选 `iam.mfa.verify` 作用域；用户需已登录本系统（未登录会先跳登录页）；若发起时指定 `user`，登录账号必须与之一致。

**步骤 1 · 发起验证请求**

```bash
curl -X POST https://iam.example.com/api/v1/mfa-verifications \
  -H "Authorization: Bearer tcp_xxxxxx_xxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "user": "zhangsan",                        # 可选：限定必须由该用户完成
    "redirect_uri": "https://app/after-verify", # 可选：验证后浏览器回跳地址
    "factors": ["passkey", "totp"],             # 可选：限定可用因素
    "ttl_seconds": 600                           # 可选：有效期，默认 600，范围 [60,1800]
  }'
# 返回
{ "id": "<验证ID>", "verify_url": "https://iam.example.com/verify/<验证ID>",
  "status": "pending", "expires_at": "2026-06-17T10:10:00Z" }
```

**步骤 2 · 引导用户到 `verify_url`** 完成验证。若提供了 `redirect_uri`，成功后浏览器带 `?verification_id=<ID>&status=verified` 自动回跳；回跳参数**仅作提示、不可作为信任凭据**。

**步骤 3 · 后端回查权威结果**

```bash
curl "https://iam.example.com/api/v1/mfa-verifications/<验证ID>" \
  -H "Authorization: Bearer tcp_xxxxxx_xxxxxxxx"
# 返回（已完成）
{ "id": "<验证ID>", "status": "verified", "user_id": "<UUID>",
  "username": "zhangsan", "factor": "passkey", "verified_at": "..." }
```

- 验证**一次性**：完成后结果不可被覆盖；过期后该 `id` 返回 404。
- **仅创建该请求的同一个 API 令牌**可回查其结果（跨令牌读取按 404 处理）。
- 请校验返回的 `user_id`/`username` 是否为你期望验证的用户。

---

## 7. 错误格式与状态码

错误统一为 JSON，含机器可读 `code` 与中文 `detail`：

```json
{ "code": "forbidden", "detail": "令牌缺少 iam.permissions.read 作用域" }
```

| 状态码 | 含义 |
|---|---|
| 400 | 参数缺失/非法 |
| 401 | 令牌缺失/无效/过期/已吊销 |
| 403 | 作用域不足或无权访问该应用 |
| 404 | 用户、应用或验证请求不存在/已过期 |
| 409 | 验证请求已被完成（一次性，不可重复完成） |

---

## 8. 完整示例（Node.js 伪代码）

```js
// 1) 用 code 换令牌
const tok = await fetch("https://iam.example.com/oauth2/token", {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code", code, redirect_uri,
    client_id, client_secret, code_verifier,
  }),
}).then(r => r.json());

// 2) 取用户与完整权限/身份组
const me = await fetch("https://iam.example.com/oauth2/userinfo", {
  headers: { authorization: "Bearer " + tok.access_token },
}).then(r => r.json());

// 3) 判断权限
if (me.tc_permissions.includes("doc.write")) {
  // 允许编辑
}
```
