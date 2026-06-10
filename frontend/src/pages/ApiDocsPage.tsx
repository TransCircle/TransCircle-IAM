import * as React from "react";
import { Copy, Check, X } from "lucide-react";
import { Badge, Card, CardContent, CardHeader, CardTitle, PageHeader } from "@/components/ui";
import { copyText } from "@/lib/utils";

const base = typeof window !== "undefined" ? window.location.origin : "https://iam.example.com";

function Code({ children }: { children: string }) {
  const [state, setState] = React.useState<"idle" | "copied" | "failed">("idle");
  return (
    <div className="group relative">
      <pre className="overflow-x-auto rounded-lg border bg-muted/50 p-3 font-mono text-xs leading-relaxed">
        <code>{children}</code>
      </pre>
      <button
        onClick={async () => {
          const ok = await copyText(children);
          setState(ok ? "copied" : "failed");
          setTimeout(() => setState("idle"), 1500);
        }}
        className="absolute right-2 top-2 rounded-md border bg-card p-1.5 text-muted-foreground transition-colors hover:text-foreground"
        aria-label="复制"
      >
        {state === "copied" ? (
          <Check className="h-3.5 w-3.5 text-success" />
        ) : state === "failed" ? (
          <X className="h-3.5 w-3.5 text-destructive" />
        ) : (
          <Copy className="h-3.5 w-3.5" />
        )}
      </button>
    </div>
  );
}

function Endpoint({ method, path }: { method: string; path: string }) {
  const colors: Record<string, "success" | "default" | "destructive" | "warning"> = {
    GET: "success",
    POST: "default",
    DELETE: "destructive",
    PATCH: "warning",
    PUT: "warning",
  };
  return (
    <div className="flex min-w-0 items-center gap-2 text-sm">
      <Badge variant={colors[method] || "muted"} className="shrink-0">{method}</Badge>
      <code className="break-all text-xs">{path}</code>
    </div>
  );
}

function EndpointDoc({ method, path, auth, children }: { method: string; path: string; auth: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2 rounded-lg border p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Endpoint method={method} path={path} />
        <Badge variant="muted">认证：{auth}</Badge>
      </div>
      <div className="space-y-2 text-sm text-muted-foreground">{children}</div>
    </div>
  );
}

export function ApiDocsPage() {
  return (
    <div className="max-w-4xl">
      <PageHeader
        title="对接文档"
        description="把 TransCircle 作为统一登录与权限中心接入你的应用。本页提供完整、可直接照做的集成指南；同源 Markdown 版见仓库 docs/INTEGRATION.md。"
      />

      <div className="space-y-6">
        {/* 总览 */}
        <Card>
          <CardHeader>
            <CardTitle>一、总览：两种接入方式</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p>
              <b className="text-foreground">① OIDC 单点登录（面向「用户登录」）</b>：用户通过本系统登录你的应用，登录后你的应用即可拿到用户身份，以及该用户「在你这个应用下」的角色、权限与身份组。
            </p>
            <p>
              <b className="text-foreground">② 机器权限 API（面向「后端鉴权」）</b>：你的后端服务用 API 令牌随时查询「某用户在某应用下」的角色、权限、身份组，用于服务端授权判断。
            </p>
            <div className="rounded-lg border bg-muted/30 p-3 text-xs leading-relaxed">
              <p className="mb-1 font-medium text-foreground">术语与维度</p>
              <ul className="list-disc space-y-1 pl-5">
                <li><b>应用 (application)</b>：一个独立的权限作用域，有唯一 <code>key</code>（如 <code>wiki</code>）。</li>
                <li><b>角色 (role) / 权限 (permission)</b>：<b>按应用</b>划分。用户在应用 A 的角色与在应用 B 的角色互不相干。</li>
                <li><b>身份组 (group)</b>：<b>全局</b>组织结构，用于把一批角色批量授予成员；接入方拿到的是「身份组 + 直接授权」共同推导出的最终结果。</li>
              </ul>
            </div>
          </CardContent>
        </Card>

        {/* 端点详解 */}
        <Card>
          <CardHeader>
            <CardTitle>二、端点详解（每个端点是什么、怎么用）</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <EndpointDoc method="GET" path="/.well-known/openid-configuration" auth="无">
              <p>
                <b className="text-foreground">OIDC 发现文档。</b>一份机器可读的 JSON，声明本系统的全部端点地址、支持的 scope、响应类型、签名算法、PKCE 方式等。
                标准 OIDC 客户端库通常只需配置 <code>issuer</code>（本系统地址），即可自动拉取此文档得到其余端点，<b>无需手写端点 URL</b>。
              </p>
              <Code>{`{
  "issuer": "${base}",
  "authorization_endpoint": "${base}/oauth2/auth",
  "token_endpoint": "${base}/oauth2/token",
  "userinfo_endpoint": "${base}/oauth2/userinfo",
  "jwks_uri": "${base}/.well-known/jwks.json",
  "introspection_endpoint": "${base}/oauth2/introspect",
  "revocation_endpoint": "${base}/oauth2/revoke",
  "scopes_supported": ["openid","profile","email","offline_access","tc.permissions"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code","refresh_token","client_credentials"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "code_challenge_methods_supported": ["S256"],
  "claims_supported": ["sub","name","preferred_username","picture","email","tc_app","tc_roles","tc_permissions","tc_groups","tc_perm_version"]
}`}</Code>
            </EndpointDoc>

            <EndpointDoc method="GET" path="/.well-known/jwks.json　(别名 /jwks.json)" auth="无">
              <p>
                <b className="text-foreground">JWKS = JSON Web Key Set（JSON 网络密钥集）。</b>
                本系统用 <b>RS256</b>（RSA 非对称签名）给 <code>id_token</code> 与 <code>access_token</code> 签名。JWKS 发布对应的<b>公钥</b>，
                你的应用用它来<b>验证令牌签名</b>——即确认这个令牌确实由本 IAM 签发、且内容未被篡改。私钥永远只在服务端，绝不下发。
              </p>
              <p>用法：JWT 头部带一个 <code>kid</code>（密钥编号）；在 JWKS 里找到相同 <code>kid</code> 的公钥，用它验签。绝大多数 OIDC 库会自动完成这一步。</p>
              <p>
                <b className="text-foreground">密钥轮换：</b>本系统会同时发布「当前」与「上一把」公钥，因此轮换期间旧令牌仍可被验证。
                建议<b>缓存 JWKS</b>，遇到未知 <code>kid</code> 时再刷新一次，而不是每次请求都拉取。
              </p>
              <Code>{`{ "keys": [
  { "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"<密钥编号>", "n":"<modulus>", "e":"AQAB" }
] }`}</Code>
            </EndpointDoc>

            <EndpointDoc method="GET / POST" path="/oauth2/auth" auth="浏览器会话 (登录态)">
              <p>
                <b className="text-foreground">授权端点。</b>让浏览器重定向到这里发起登录。若用户未登录，会先跳到本系统登录页，登录后自动回到授权流程。
                <b>强制 PKCE（S256）</b>。对非「可信客户端」，会展示<b>授权同意屏</b>，且<b>每次授权都需用户确认</b>（除非该客户端被标记为可信、可跳过同意）。
                成功后浏览器 302 回你的 <code>redirect_uri</code>，附带 <code>code</code> 与 <code>state</code>。
              </p>
            </EndpointDoc>

            <EndpointDoc method="POST" path="/oauth2/token" auth="客户端凭据 / PKCE">
              <p>
                <b className="text-foreground">令牌端点。</b>用授权码换令牌，或刷新令牌。支持三种 grant：
              </p>
              <ul className="list-disc space-y-1 pl-5">
                <li><code>authorization_code</code>：用上一步的 <code>code</code> + <code>code_verifier</code> 换 access/id/refresh token。</li>
                <li><code>refresh_token</code>：用 refresh_token 换新令牌（需 <code>offline_access</code> scope；一次性轮换）。</li>
                <li><code>client_credentials</code>：无用户上下文，机器以自身身份取访问令牌。</li>
              </ul>
              <p>机密客户端用 <code>client_secret_basic</code> 或 <code>client_secret_post</code> 认证；公共客户端（SPA/移动端）用 PKCE 代替密钥。</p>
            </EndpointDoc>

            <EndpointDoc method="GET / POST" path="/oauth2/userinfo" auth="Bearer access_token">
              <p>
                <b className="text-foreground">用户信息端点。</b>携带 access_token 调用，返回当前用户的声明。返回内容随该令牌被授予的 scope 而定；
                带 <code>tc.permissions</code> 时会返回<b>完整</b>的 <code>tc_permissions</code> 与 <code>tc_groups</code>（令牌本身不含完整列表，见第四、五节）。
              </p>
            </EndpointDoc>

            <EndpointDoc method="POST" path="/oauth2/introspect" auth="客户端凭据">
              <p>
                <b className="text-foreground">令牌内省（RFC 7662）。</b>后端用客户端凭据向本系统查询「某个令牌是否仍然有效」及其元数据
                （<code>active</code>、<code>scope</code>、<code>sub</code>、<code>exp</code> 等）。适合不想自己解析 JWT、而是直接向 IdP 核实的场景。
              </p>
            </EndpointDoc>

            <EndpointDoc method="POST" path="/oauth2/revoke" auth="客户端凭据">
              <p>
                <b className="text-foreground">令牌吊销（RFC 7009）。</b>主动作废 <b>refresh token</b>（立即失效,并连带其令牌族)。
                注意:<b>access token 是自包含 JWT,不做中心化即时吊销</b>——最多在其较短有效期(TTL)后失效;
                需要即时收敛时,资源服务可用 <code>/oauth2/introspect</code> 核实,或借助 <code>tc_perm_version</code> 做权限版本校验。
              </p>
            </EndpointDoc>

            <EndpointDoc method="GET" path="/api/v1/permissions?user=&app=" auth="Bearer API 令牌 (tcp_)">
              <p>
                <b className="text-foreground">机器权限 API。</b>后端服务用 API 令牌查询「某用户在某应用下」的角色、权限、身份组。详见第八节。
              </p>
            </EndpointDoc>
          </CardContent>
        </Card>

        {/* OIDC 流程 */}
        <Card>
          <CardHeader>
            <CardTitle>三、OIDC 单点登录（分步）</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <p className="text-muted-foreground">
              <b className="text-foreground">前置：</b>在「管理 → OIDC 客户端」新建客户端，绑定到对应「应用」，勾选所需 scope（<code>openid profile email tc.permissions</code>），保存后复制一次性密钥（公共客户端无密钥）。
            </p>

            <p className="font-medium text-foreground">步骤 1 · 跳转授权（强制 Authorization Code + PKCE / S256）</p>
            <Code>{`# 生成 code_verifier 与 code_challenge=BASE64URL(SHA256(verifier))
GET ${base}/oauth2/auth?
  response_type=code
  &client_id=<你的 client_id>
  &redirect_uri=<已登记的回调地址>
  &scope=openid%20profile%20email%20tc.permissions
  &state=<随机防 CSRF>
  &nonce=<随机防重放>
  &code_challenge=<challenge>
  &code_challenge_method=S256`}</Code>
            <p className="text-xs text-muted-foreground">用户完成登录与授权后，浏览器带 <code>code</code> 与 <code>state</code> 跳回你的 <code>redirect_uri</code>。请校验 <code>state</code> 一致。</p>

            <p className="font-medium text-foreground">步骤 2 · 用 code 换令牌</p>
            <Code>{`curl -X POST ${base}/oauth2/token \\
  -d grant_type=authorization_code \\
  -d code=<上一步的 code> \\
  -d redirect_uri=<同上> \\
  -d client_id=<client_id> \\
  -d client_secret=<client_secret> \\   # 机密客户端必填
  -d code_verifier=<verifier>           # 公共客户端用它代替密钥

# 返回
{
  "access_token": "<JWT>",
  "id_token": "<JWT>",
  "refresh_token": "<仅当 scope 含 offline_access>",
  "token_type": "bearer",
  "expires_in": 3600
}`}</Code>

            <p className="font-medium text-foreground">步骤 3 · 校验 ID Token 并读取身份</p>
            <p className="text-xs text-muted-foreground">用 JWKS 校验 <code>id_token</code> 签名与 <code>iss</code>/<code>aud</code>/<code>nonce</code>/<code>exp</code>。ID Token 为精简载荷：</p>
            <Code>{`{
  "sub": "<用户ID, UUID>",
  "preferred_username": "zhangsan",   // profile scope
  "name": "张三",                      // profile scope
  "picture": "${base}/api/v1/avatars/u/<用户ID>", // profile scope: 头像直链（见下）
  "email": "zhangsan@example.com",     // email scope
  "tc_app": "wiki",                    // tc.permissions: 该客户端绑定的应用 key
  "tc_roles": ["editor", "viewer"],    // tc.permissions: 用户在该应用下的角色
  "tc_perm_version": "a1b2c3d4e5f6"    // tc.permissions: 权限指纹，变化即代表权限已变
}`}</Code>
            <div className="rounded-md border bg-muted/40 p-3 text-xs leading-relaxed text-muted-foreground">
              <b className="text-foreground">关于 <code>picture</code>（头像）：</b>这是一个<b>稳定且公开</b>的直链
              <code>{base}/api/v1/avatars/u/&lt;用户ID&gt;</code>，无需任何凭据即可直接用于 <code>&lt;img src&gt;</code>。
              该地址对每个用户固定不变，但内容<b>随用户更换头像自动更新</b>，因此可放心缓存这个 URL（按需加 CDN/浏览器缓存）。
              用户未设置头像时该 claim 不出现，且该地址返回 <code>404</code>，请回退到你方的默认头像。
            </div>

            <p className="font-medium text-foreground">步骤 4 · 刷新令牌（需 offline_access）</p>
            <Code>{`curl -X POST ${base}/oauth2/token \\
  -d grant_type=refresh_token \\
  -d refresh_token=<refresh_token> \\
  -d client_id=<client_id> -d client_secret=<client_secret>`}</Code>
            <p className="text-xs text-muted-foreground">刷新令牌一次性轮换：旧 refresh_token 用后即废，复用会触发整条令牌族被吊销（防盗用）。</p>
          </CardContent>
        </Card>

        {/* scope & claims */}
        <Card>
          <CardHeader>
            <CardTitle>四、作用域 (scope) 与声明 (claims)</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="text-left text-muted-foreground">
                  <tr><th className="py-1 pr-4">scope</th><th className="py-1">含义</th></tr>
                </thead>
                <tbody className="divide-y">
                  <tr><td className="py-1.5 pr-4"><code>openid</code></td><td>必选，签发 ID Token。</td></tr>
                  <tr><td className="py-1.5 pr-4"><code>profile</code></td><td>返回 <code>name</code>、<code>preferred_username</code>、<code>picture</code>（头像直链）。</td></tr>
                  <tr><td className="py-1.5 pr-4"><code>email</code></td><td>返回 <code>email</code>。</td></tr>
                  <tr><td className="py-1.5 pr-4"><code>offline_access</code></td><td>签发 refresh_token。</td></tr>
                  <tr><td className="py-1.5 pr-4"><code>tc.permissions</code></td><td>返回该应用下的角色、权限、身份组与权限指纹。</td></tr>
                </tbody>
              </table>
            </div>
            <p className="text-xs text-muted-foreground">
              <b className="text-foreground">为何令牌精简：</b>为控制令牌体积，<b>ID Token 与 Access Token 只携带 <code>tc_app</code>、<code>tc_roles</code>、<code>tc_perm_version</code></b>，
              <b>不含</b>完整权限表与身份组列表。完整列表通过 UserInfo 或机器权限 API 获取（见第五节）。
            </p>
            <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
              <li><code>tc_app</code>：当前客户端绑定的应用 key。</li>
              <li><code>tc_roles</code>：用户在该应用下的角色 key 列表。</li>
              <li><code>tc_permissions</code>：用户在该应用下的权限 key 列表（仅 UserInfo / 机器 API）。</li>
              <li><code>tc_groups</code>：用户所属身份组 key 列表（全局，仅 UserInfo / 机器 API）。</li>
              <li><code>tc_perm_version</code>：权限集合指纹，权限变化时一定变化（见第七节）。</li>
            </ul>
          </CardContent>
        </Card>

        {/* 取权限表与身份组 */}
        <Card>
          <CardHeader>
            <CardTitle>五、获取「用户权限表 + 身份组列表」</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <p className="text-muted-foreground">方式 A：登录态下用 access_token 调 UserInfo（带 <code>tc.permissions</code> scope）。</p>
            <Code>{`curl ${base}/oauth2/userinfo -H "Authorization: Bearer <access_token>"

# 返回（含完整权限表与身份组）
{
  "sub": "<用户ID>",
  "preferred_username": "zhangsan",
  "picture": "${base}/api/v1/avatars/u/<用户ID>",
  "email": "zhangsan@example.com",
  "tc_app": "wiki",
  "tc_roles": ["editor"],
  "tc_permissions": ["doc.read", "doc.write"],
  "tc_groups": ["engineering", "all-staff"],
  "tc_perm_version": "a1b2c3d4e5f6"
}`}</Code>
            <p className="text-muted-foreground">方式 B：后端用机器 API 主动查询（见第八节），返回 <code>roles</code> / <code>permissions</code> / <code>groups</code>。</p>
          </CardContent>
        </Card>

        {/* 确认权限 */}
        <Card>
          <CardHeader>
            <CardTitle>六、如何确认某用户是否拥有某权限</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p>系统不提供「校验单个权限」的专用端点；推荐做法是取得完整权限列表后在你侧判断成员关系：</p>
            <Code>{`// 服务端权威判断（推荐）：调机器 API 取全集后判断
const { permissions } = await fetchPermissions(userId, "wiki");
const allowed = permissions.includes("doc.write");`}</Code>
            <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
              <li><b className="text-foreground">权威来源</b>：机器权限 API / UserInfo 实时返回的结果总是以服务端为准。</li>
              <li><b className="text-foreground">本地缓存（advisory）</b>：可缓存令牌内的 <code>tc_roles</code> 与 <code>tc_perm_version</code>；当 <code>tc_perm_version</code> 变化时，说明权限已变，应重新拉取全集。</li>
            </ul>
          </CardContent>
        </Card>

        {/* perm_version */}
        <Card>
          <CardHeader>
            <CardTitle>七、tc_perm_version 与缓存一致性</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm text-muted-foreground">
            <p><code>tc_perm_version</code> 是该用户在该应用下「权限集合」的稳定指纹（哈希）。只要用户的角色/权限/身份组发生任何变化，它一定会变。</p>
            <p>接入方可以把它当作缓存键：缓存权限结果并记录当时的 <code>tc_perm_version</code>；下次拿到新令牌或调用接口时，若版本不同就刷新缓存。服务端内部通过每用户的 <code>perm_version</code> 与全局 <code>authz_epoch</code> 保证缓存一致，无需你关心实现细节——你只需「版本变了就刷新」。</p>
          </CardContent>
        </Card>

        {/* 机器 API */}
        <Card>
          <CardHeader>
            <CardTitle>八、机器权限 API（M2M）</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <p className="text-muted-foreground">
              在「管理 → API 令牌」创建令牌（可限定 scope 与可访问的应用）。令牌格式为 <code>tcp_&lt;prefix&gt;_&lt;secret&gt;</code>，仅在创建时显示一次。
            </p>
            <Endpoint method="GET" path="/api/v1/permissions?user=<用户名或UUID>&app=<应用key>" />
            <Code>{`curl "${base}/api/v1/permissions?user=zhangsan&app=wiki" \\
  -H "Authorization: Bearer tcp_xxxxxx_xxxxxxxxxxxxxxxxxxxxxxxx"

# 返回
{
  "app_id": "...",
  "app_key": "wiki",
  "roles": ["editor"],
  "permissions": ["doc.read", "doc.write"],
  "groups": ["engineering", "all-staff"]
}`}</Code>
            <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
              <li>令牌必须包含 <code>iam.permissions.read</code> 作用域。</li>
              <li>令牌若设置了「限定应用」，只能查询这些应用，否则返回 403；留空表示不限定（仅超级管理员可创建）。</li>
              <li><code>user</code> 支持用户名或用户 UUID；<code>app</code> 为应用 key。</li>
            </ul>
          </CardContent>
        </Card>

        {/* 错误格式 */}
        <Card>
          <CardHeader>
            <CardTitle>九、错误格式与状态码</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p className="text-muted-foreground">管理与机器 API 的错误统一返回 JSON，含机器可读的 <code>code</code> 与中文 <code>detail</code>：</p>
            <Code>{`{ "code": "forbidden", "detail": "令牌缺少 iam.permissions.read 作用域" }`}</Code>
            <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
              <li><b>400</b> 参数缺失/非法（如缺少 <code>user</code>/<code>app</code>）。</li>
              <li><b>401</b> 令牌缺失/无效/过期/已吊销。</li>
              <li><b>403</b> 令牌作用域不足或无权访问该应用。</li>
              <li><b>404</b> 用户或应用不存在。</li>
            </ul>
          </CardContent>
        </Card>

        {/* 完整示例 */}
        <Card>
          <CardHeader>
            <CardTitle>十、完整示例（Node.js 伪代码）</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <Code>{`// 1) 用 code 换令牌
const tok = await fetch("${base}/oauth2/token", {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code", code, redirect_uri,
    client_id, client_secret, code_verifier,
  }),
}).then(r => r.json());

// 2) 取用户与完整权限/身份组
const me = await fetch("${base}/oauth2/userinfo", {
  headers: { authorization: "Bearer " + tok.access_token },
}).then(r => r.json());

// 3) 在你的应用里判断权限
if (me.tc_permissions.includes("doc.write")) {
  // 允许编辑
}`}</Code>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
