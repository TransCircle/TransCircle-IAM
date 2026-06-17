# TransCircle IAM

内部统一身份认证与授权系统（IAM）+ OAuth2/OIDC 身份供应商。

- **后端**：Go 1.26（chi · pgx · ory/fosite · go-webauthn · pquerna/otp）
- **前端**：React 19 + Vite + TypeScript + TailwindCSS（shadcn 风格，纯中文）
- **打包**：前端**内嵌进后端二进制**，单一容器同端口(8080)同时提供 UI 与 API。
- **基础设施**：PostgreSQL 17 · Redis 7 · Docker Compose
- **对外网关**：由你们已有的 **nginx** 负责，只需把该单一容器出口反代出去即可，本仓库不内置任何网关。

## 特性

- 管理员手动建号 → **首登强制改密 + 强制绑定 MFA**（Passkey / TOTP + 一次性恢复码）。
- **混合 RBAC**：用户 / 身份组 / 角色 / 权限 / 应用，权限按应用作用域划分；用户可经身份组、直接角色、或单条权限三路径授权。
- 作为 **OAuth2/OIDC 供应商**：`authorization_code`+PKCE、`refresh_token`（轮换+重用检测）、`client_credentials`；ID Token/Access Token 下发精简权限声明（`tc_app`/`tc_roles`/`tc_perm_version`），完整权限表与身份组列表（`tc_permissions`/`tc_groups`）经 UserInfo 与受保护 REST API 获取。
- 密钥**初始化自动生成并入库**（零配置），AES-256-GCM 静态加密，可选 KEK 加固。
- 内置：审计日志、会话远程吊销、Consent 同意屏、M2M API 令牌、管理员代登（防越权）。
- **OAuth/OIDC 客户端登录限制**：可限定某应用仅允许指定用户 / 身份组 / 持有某权限者登录。
- 后端**完全无状态**，可 `--scale backend=N` 横向扩展。

## 部署

### 1. 启动（一个应用容器 + 数据层）

```bash
cp .env.example .env          # 按需修改密码 / IAM_ISSUER（对外域名）
docker compose up -d --build  # postgres + redis + app（前端已内嵌）
docker compose logs app       # 查看首管理员用户名与临时密码
```

`app` 容器在 `${APP_PORT}`（默认 `8080`）同时提供 SPA 与 API，启动时自动迁移+初始化。

### 2. 配置你们的 nginx（把整个出口反代过去）

> 因为前端与 API 同源、同一个端口，nginx 只需把对外域名整体反代到 app 容器即可，**无需区分路径**。

```nginx
server {
    listen 443 ssl;
    server_name iam.transcircle.com;        # 与 .env 的 IAM_ISSUER 一致
    # ssl_certificate     /etc/ssl/...;
    # ssl_certificate_key /etc/ssl/...;

    # 头像上传上限 2MB；nginx 默认 client_max_body_size 仅 1m，会先于后端返回 413。
    client_max_body_size 4m;

    location / {
        proxy_pass http://127.0.0.1:8080;   # = APP_PORT（compose 仅绑定到 127.0.0.1）
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

> 注意：
> - 生产经 HTTPS 反代时，`.env` 设 `IAM_ENV=prod` 与 `IAM_COOKIE_SECURE=true`。
> - 已默认信任所有来源的 `X-Forwarded-*`（`IAM_TRUST_ALL_PROXIES=true`），无需配置来源 IP 段——前提是应用仅经你们的 nginx 暴露。
> - 数据持久化在当前目录：`./data/postgres`、`./data/redis`、`./data/app`（含首管理员凭据 `bootstrap.json`，0600）。
> - 首管理员凭据仅写入 `./data/app/bootstrap.json`（0600），不会打印到容器日志；若该文件写入失败，可用
>   `docker compose run --rm app admin reset-password <用户名>` 重置密码。
> - 生产建议开启信封加密 KEK：设 `IAM_KEK_ENABLED=true` 并提供 `IAM_KEK`（base64 32 字节）或 `IAM_KEK_FILE`，
>   否则 DEK 以明文存于数据库，备份泄露即等同泄露全部静态密钥。
> - 唯一 MFA 因子丢失且无其他管理员时的破玻璃命令：
>   `docker compose run --rm app admin reset-mfa <用户名>`。
> - **超级管理员（super_admin）只能经服务器端 CLI 管理**，Web/API 永远无法授予。每次启动都会把 `user_roles`
>   里的 super_admin 强制对齐到一份「签名名单」，名单外的（含经身份组下发的）一律剥离——**直接改数据库加超管，重启即失效**：
>   `docker compose run --rm app super-admin add <用户名>` / `remove <用户名>` / `list`。
>   系统初始管理员（`IAM_BOOTSTRAP_ADMIN_USERNAME`）恒为不可删除的根超管。
>   名单每行用 DEK 派生子密钥做 HMAC 防伪；**仅在开启 `IAM_KEK_ENABLED` 时**（DEK 在库中为密文）该防伪对「能读库的攻击者」也成立，
>   KEK 关闭时 DEK 明文存库，签名只能阻挡随手直改、挡不住会读库并懂签名构造的人——故生产务必开启 KEK。

登录后：① 强制改密 → ② 绑定 Passkey/TOTP 并保存恢复码 → ③ 进入管理台。

## 接入一个应用（OIDC）

1. 管理台 → **应用**：新建应用（如 `wiki`），并在其下定义权限/角色。
2. 管理台 → **OIDC 客户端**：新建客户端，绑定到该应用，填写回调地址，勾选 `openid profile email tc.permissions`。保存后复制一次性密钥。
3. 应用侧使用标准 OIDC：
   - 发现文档：`/.well-known/openid-configuration`
   - 授权端点：`/oauth2/auth`（强制 PKCE，S256）
   - 令牌端点：`/oauth2/token`
   - UserInfo：`/oauth2/userinfo`（返回 `tc_app` / `tc_roles` / `tc_permissions` / `tc_groups`）
   - 头像：`profile` scope 下，ID Token 与 UserInfo 含 `picture` 声明——一个稳定且公开的头像直链 `/api/v1/avatars/u/<用户ID>`，对每个用户固定不变、随其更换头像自动更新，可直接用于 `<img src>`；用户未设头像时该声明不出现且地址返回 404。
4. 后端服务也可用 **API 令牌** 直接查询权限（返回 `roles` / `permissions` / `groups`）：
   ```
   GET /api/v1/permissions?user=<用户名|uuid>&app=<应用key>
   Authorization: Bearer tcp_xxx
   ```

> 完整、分步、含示例的接入手册见 [`docs/INTEGRATION.md`](docs/INTEGRATION.md)，或登录后访问管理台内的「对接文档」页面（同源内容）。

## 本地开发

```bash
# 仅起数据层
docker compose up -d postgres redis
# 后端（serve 会自动迁移+初始化；本地不内嵌真实前端，仅占位页）
cd backend && go run ./cmd/iam serve
# 前端（dev server 自带代理到 localhost:8080，开发用真实 UI）
cd frontend && npm install && npm run dev
```

常用命令见 `make help`。

## 安全设计要点

- 静态加密：业务秘密 AES-256-GCM（DEK 信封加密，AAD 域分离）；可选 `IAM_KEK_ENABLED` 用 KEK 包裹 DEK。
- 缓存一致性：有效权限以 Postgres `perm_version` 为权威，撤权即时生效（非等 TTL）。
- 超级管理员保护：super_admin 的权威来源是签名名单 `super_admin_grants`，每次启动强制对齐 `user_roles`（名单外的直接/身份组授予一律剥离），仅服务器 CLI 可增删，初始管理员不可删——详见部署注记。
- 令牌：access JWT ≤15m；refresh 轮换 + 整族重用检测；JWKS 发布 active+previous 支持密钥轮换。
- 原子性：所有变更走单事务，审计写入同一事务（fail-closed）；顶层 recover 防 panic，错误统一 RFC7807。
- CSRF：`__Host-` 会话 Cookie + 双提交令牌；OAuth `token/introspect/revoke` 豁免，Consent 提交不豁免。

## 目录结构

```
backend/    Go 后端（cmd/iam + internal/{config,store,crypto,keys,db,rbac,authz,audit,sessions,authn,auth,oauth,api,server,web,app}）
            前端构建产物通过 internal/web (go:embed) 内嵌进二进制
frontend/   React 前端（src/{lib,components,auth,pages}）
Dockerfile  单镜像三阶段：构建 SPA → 内嵌进 Go 二进制 → distroless
docker-compose.yml  postgres + redis + app（单一应用容器）
```
