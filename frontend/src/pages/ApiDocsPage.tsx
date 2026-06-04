import * as React from "react";
import { Copy, Check } from "lucide-react";
import { Badge, Card, CardContent, CardHeader, CardTitle, PageHeader } from "@/components/ui";

const base = typeof window !== "undefined" ? window.location.origin : "https://iam.example.com";

function Code({ children }: { children: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <div className="group relative">
      <pre className="overflow-x-auto rounded-lg border bg-muted/50 p-3 text-xs leading-relaxed">
        <code>{children}</code>
      </pre>
      <button
        onClick={() => {
          navigator.clipboard?.writeText(children);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        }}
        className="absolute right-2 top-2 rounded-md border bg-card p-1.5 text-muted-foreground opacity-0 transition-opacity hover:text-foreground group-hover:opacity-100"
        aria-label="复制"
      >
        {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
      </button>
    </div>
  );
}

function Endpoint({ method, path }: { method: string; path: string }) {
  const colors: Record<string, string> = {
    GET: "success",
    POST: "default",
    DELETE: "destructive",
  };
  return (
    <div className="flex items-center gap-2 text-sm">
      <Badge variant={(colors[method] as "success" | "default" | "destructive") || "muted"}>{method}</Badge>
      <code className="text-xs">{path}</code>
    </div>
  );
}

export function ApiDocsPage() {
  return (
    <div>
      <PageHeader title="对接文档" description="把 TransCircle 作为统一登录与权限中心接入你的应用。复杂接口在此说明，其余功能在对应页面旁均有内联提示。" />

      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>两种接入方式</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm text-muted-foreground">
            <p>
              <b className="text-foreground">① OIDC 单点登录</b>：用户通过本系统登录你的应用，登录后应用即可拿到用户身份与「在该应用下」的角色/权限声明。
            </p>
            <p>
              <b className="text-foreground">② 机器对机器权限查询</b>：你的后端用 API 令牌随时查询「某用户在某应用下」的角色与权限，用于服务端鉴权。
            </p>
            <p className="text-xs">
              说明：身份组（Group）是内部组织结构，对外不直接暴露；应用拿到的是由身份组/直接授权共同推导出的「角色 + 权限」集合。
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>① OIDC 单点登录</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <p className="text-muted-foreground">在「管理 → OIDC 客户端」创建客户端，绑定到对应「应用」，勾选 scope <code>openid profile email tc.permissions</code>，保存后复制一次性密钥。标准 OIDC 端点：</p>
            <div className="space-y-1.5">
              <Endpoint method="GET" path="/.well-known/openid-configuration" />
              <Endpoint method="GET" path="/.well-known/jwks.json" />
              <Endpoint method="GET" path="/oauth2/auth" />
              <Endpoint method="POST" path="/oauth2/token" />
              <Endpoint method="GET" path="/oauth2/userinfo" />
            </div>
            <p className="text-muted-foreground">发现文档：</p>
            <Code>{`${base}/.well-known/openid-configuration`}</Code>
            <p className="text-muted-foreground">强制使用 Authorization Code + PKCE（S256）。ID Token 中携带精简声明：</p>
            <Code>{`{
  "sub": "<用户ID>",
  "preferred_username": "zhangsan",
  "email": "zhangsan@example.com",
  "tc_app": "wiki",                 // 该客户端绑定的应用 key
  "tc_roles": ["editor", "viewer"], // 用户在该应用下的角色
  "tc_perm_version": "a1b2c3d4e5f6" // 权限指纹，变化即代表权限已变
}`}</Code>
            <p className="text-muted-foreground">
              为控制令牌体积，ID Token 不含完整权限列表。需要完整权限时调用 UserInfo（携带 access token）：
            </p>
            <Code>{`curl ${base}/oauth2/userinfo \\
  -H "Authorization: Bearer <access_token>"

# 返回（含完整权限）
{
  "sub": "<用户ID>",
  "tc_app": "wiki",
  "tc_roles": ["editor"],
  "tc_permissions": ["doc.read", "doc.write"]
}`}</Code>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>② 权限查询 REST API（机器对机器）</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <p className="text-muted-foreground">
              在「管理 → API 令牌」创建令牌（可限定 scope 与允许的应用）。用 Bearer 头调用，随时查询某用户在某应用下的角色与权限：
            </p>
            <Endpoint method="GET" path="/api/v1/permissions?user=<用户名或ID>&app=<应用key>" />
            <Code>{`curl "${base}/api/v1/permissions?user=zhangsan&app=wiki" \\
  -H "Authorization: Bearer tcp_xxxxxxxx"

# 返回
{
  "app_id": "...",
  "app_key": "wiki",
  "roles": ["editor"],
  "permissions": ["doc.read", "doc.write"]
}`}</Code>
            <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
              <li>令牌必须包含 <code>iam.permissions.read</code> 作用域。</li>
              <li>若令牌设置了「限定应用」，只能查询这些应用，否则返回 403。</li>
              <li><code>user</code> 支持用户名或用户 UUID。</li>
            </ul>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
