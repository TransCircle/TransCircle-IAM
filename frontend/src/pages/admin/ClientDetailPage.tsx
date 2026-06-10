import * as React from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, RefreshCw, Eye, Trash2, Save } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Checkbox,
  CopyButton,
  Field,
  Input,
  PageHeader,
  Select,
  Spinner,
  Switch,
  Textarea,
} from "@/components/ui";
import { Dialog, ConfirmDialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { Application, OAuthClient } from "@/lib/types";

const ALL_SCOPES = ["openid", "profile", "email", "offline_access", "tc.permissions"];
const ALL_GRANTS = ["authorization_code", "refresh_token", "client_credentials"];
const ALL_RESPONSES = ["code"];

const lines = (s: string) => s.split("\n").map((x) => x.trim()).filter(Boolean);

interface Form {
  client_name: string;
  app_id: string;
  redirects: string;
  postLogout: string;
  scopes: string[];
  grants: string[];
  responses: string[];
  audience: string;
  allowedAppKeys: string;
  skip_consent: boolean;
  pkce_required: boolean;
  active: boolean;
}

function toForm(c: OAuthClient): Form {
  return {
    client_name: c.client_name,
    app_id: c.app_id ?? "",
    redirects: (c.redirect_uris ?? []).join("\n"),
    postLogout: (c.post_logout_redirect_uris ?? []).join("\n"),
    scopes: c.allowed_scopes ?? [],
    grants: c.grant_types ?? [],
    responses: c.response_types ?? ["code"],
    audience: (c.audience ?? []).join("\n"),
    allowedAppKeys: (c.allowed_app_keys ?? []).join("\n"),
    skip_consent: c.skip_consent,
    pkce_required: c.pkce_required,
    active: c.active,
  };
}

function CheckGroup({
  all,
  value,
  onChange,
  disabled,
  locked = [],
}: {
  all: string[];
  value: string[];
  onChange: (v: string[]) => void;
  disabled?: boolean;
  // Entries that can't be toggled off (e.g. openid is mandatory for OIDC).
  locked?: string[];
}) {
  return (
    <div className="flex flex-wrap gap-3">
      {all.map((s) => (
        <label key={s} className="flex items-center gap-1.5 font-mono text-sm">
          <Checkbox
            checked={value.includes(s)}
            disabled={disabled || locked.includes(s)}
            onCheckedChange={(c) => onChange(c ? [...value, s] : value.filter((x) => x !== s))}
          />
          {s}
        </label>
      ))}
    </div>
  );
}

export function ClientDetailPage() {
  const { clientId = "" } = useParams();
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.clients.write");

  const [form, setForm] = React.useState<Form | null>(null);
  const [secret, setSecret] = React.useState<string | null>(null);
  const [confirmDel, setConfirmDel] = React.useState(false);
  const [confirmRotate, setConfirmRotate] = React.useState(false);

  const client = useQuery<OAuthClient>({
    queryKey: ["client", clientId],
    queryFn: async () => (await api.get(`/api/v1/admin/clients/${clientId}`)).data.client,
  });
  const apps = useQuery<Application[]>({
    queryKey: ["applications"],
    queryFn: async () => (await api.get("/api/v1/admin/applications")).data.applications ?? [],
  });

  React.useEffect(() => {
    if (client.data) setForm(toForm(client.data));
  }, [client.data]);

  const save = useMutation({
    mutationFn: () =>
      api.patch(`/api/v1/admin/clients/${clientId}`, {
        client_name: form!.client_name,
        app_id: form!.app_id || null,
        redirect_uris: lines(form!.redirects),
        post_logout_redirect_uris: lines(form!.postLogout),
        allowed_scopes: form!.scopes,
        grant_types: form!.grants,
        response_types: form!.responses,
        audience: lines(form!.audience),
        allowed_app_keys: lines(form!.allowedAppKeys),
        skip_consent: form!.skip_consent,
        pkce_required: form!.pkce_required,
        active: form!.active,
      }),
    onSuccess: () => {
      toast("已保存", "success");
      qc.invalidateQueries({ queryKey: ["client", clientId] });
      qc.invalidateQueries({ queryKey: ["clients"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const rotate = useMutation({
    mutationFn: () => api.post(`/api/v1/admin/clients/${clientId}/rotate-secret`),
    onSuccess: (r) => {
      setConfirmRotate(false);
      setSecret(r.data.client_secret);
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const reveal = useMutation({
    mutationFn: () => api.post(`/api/v1/admin/clients/${clientId}/secret/reveal`),
    onSuccess: (r) => setSecret(r.data.client_secret),
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const del = useMutation({
    mutationFn: () => api.delete(`/api/v1/admin/clients/${clientId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["clients"] });
      navigate("/admin/clients");
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  // Order matters: on a fetch error `form` never gets set, so the error check
  // must run BEFORE the loading check or this page spins forever.
  if (client.isError) {
    return (
      <div className="bracket-frame rounded-lg border border-dashed bg-card/50 p-10 text-center text-sm text-muted-foreground">
        客户端不存在或加载失败。
        <div className="mt-3">
          <Button variant="outline" size="sm" onClick={() => navigate("/admin/clients")}>
            返回客户端列表
          </Button>
        </div>
      </div>
    );
  }
  if (client.isLoading || !form || !client.data) {
    return (
      <div className="flex justify-center p-10">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }
  const c = client.data;
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));

  return (
    <div className="mx-auto max-w-3xl">
      <button
        onClick={() => navigate("/admin/clients")}
        className="mb-4 flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> 返回客户端列表
      </button>
      <PageHeader
        title={c.client_name}
        description="编辑该 OIDC 客户端的全部可变配置。Client ID 与客户端类型不可更改。"
        action={
          canWrite && (
            <Button
              onClick={() => {
                if (!form.scopes.includes("openid")) {
                  toast("openid 是 OIDC 必需范围，不能取消", "error");
                  return;
                }
                save.mutate();
              }}
              loading={save.isPending}
            >
              <Save className="h-4 w-4" /> 保存
            </Button>
          )
        }
      />

      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>基本信息</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Field label="Client ID（不可更改）">
              <div className="flex items-center justify-between gap-2 rounded-lg border bg-muted/40 p-2.5 font-mono text-sm">
                <span className="break-all">{c.client_id}</span>
                <CopyButton value={c.client_id} />
              </div>
            </Field>
            <Field label="名称">
              <Input value={form.client_name} disabled={!canWrite} onChange={(e) => set("client_name", e.target.value)} />
            </Field>
            <Field label="绑定应用" help="绑定后，登录用户的令牌/UserInfo 会携带该应用下的角色与权限声明。">
              <Select
                value={form.app_id}
                disabled={!canWrite}
                onValueChange={(v) => set("app_id", v)}
                placeholder="（不绑定）"
                options={[{ value: "", label: "（不绑定）" }, ...(apps.data ?? []).map((a) => ({ value: a.id, label: a.display_name }))]}
              />
            </Field>
            <div className="flex flex-wrap gap-2 text-xs">
              <Badge variant="muted">{c.public ? "公共客户端 (PKCE, 无密钥)" : "机密客户端"}</Badge>
              <Badge variant="muted">认证方式: {c.token_endpoint_auth_method}</Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>回调与登出地址</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Field label="回调地址（每行一个）" help="授权完成后允许跳转回的地址，必须与应用实际回调完全一致。">
              <Textarea value={form.redirects} disabled={!canWrite} spellCheck={false} onChange={(e) => set("redirects", e.target.value)} placeholder="https://app.example.com/callback" />
            </Field>
            <Field label="登出后回调地址（每行一个）">
              <Textarea value={form.postLogout} disabled={!canWrite} spellCheck={false} onChange={(e) => set("postLogout", e.target.value)} />
            </Field>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>授权范围与授权类型</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Field label="授权范围 (Scopes)" help="openid 必选；tc.permissions 用于下发该应用下用户的角色与权限。">
              <CheckGroup all={ALL_SCOPES} value={form.scopes} onChange={(v) => set("scopes", v)} disabled={!canWrite} locked={["openid"]} />
            </Field>
            <Field label="授权类型 (Grant Types)">
              <CheckGroup all={ALL_GRANTS} value={form.grants} onChange={(v) => set("grants", v)} disabled={!canWrite} />
            </Field>
            <Field label="响应类型 (Response Types)">
              <CheckGroup all={ALL_RESPONSES} value={form.responses} onChange={(v) => set("responses", v)} disabled={!canWrite} />
            </Field>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>高级</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Field label="令牌受众 Audience（每行一个）" help="写入访问令牌的 aud 声明，标识目标资源服务器。留空则不限定。">
              <Textarea value={form.audience} disabled={!canWrite} spellCheck={false} onChange={(e) => set("audience", e.target.value)} />
            </Field>
            <Field label="允许查询的应用 key（每行一个）" help="若该客户端也用于机器权限查询，限定其可访问的应用；留空表示不限定。">
              <Textarea value={form.allowedAppKeys} disabled={!canWrite} spellCheck={false} onChange={(e) => set("allowedAppKeys", e.target.value)} />
            </Field>
            <div className="flex items-center justify-between gap-3 rounded-lg border p-3 text-sm">
              <span>启用客户端</span>
              <Switch checked={form.active} disabled={!canWrite} onCheckedChange={(v) => set("active", v)} />
            </div>
            <div className="flex items-center justify-between gap-3 rounded-lg border p-3 text-sm">
              <span>强制 PKCE (S256)<span className="ml-2 text-xs text-muted-foreground">全局强制,始终开启</span></span>
              <Switch checked disabled onCheckedChange={() => {}} />
            </div>
            <div className="flex items-center justify-between gap-3 rounded-lg border p-3 text-sm">
              <span>可信应用（跳过授权同意屏）</span>
              <Switch checked={form.skip_consent} disabled={!canWrite} onCheckedChange={(v) => set("skip_consent", v)} />
            </div>
          </CardContent>
        </Card>

        {canWrite && (
          <Card>
            <CardHeader>
              <CardTitle>密钥与危险操作</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {!c.public && (
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" onClick={() => setConfirmRotate(true)}>
                    <RefreshCw className="h-4 w-4" /> 轮换密钥
                  </Button>
                  <Button variant="outline" onClick={() => reveal.mutate()} loading={reveal.isPending}>
                    <Eye className="h-4 w-4" /> 查看当前密钥
                  </Button>
                  <span className="self-center text-xs text-muted-foreground">查看/轮换密钥需二次验证。</span>
                </div>
              )}
              <div className="flex flex-col gap-3 rounded-lg border border-destructive/30 p-3 sm:flex-row sm:items-center sm:justify-between">
                <span className="text-sm">删除此客户端后，使用它的应用将无法再登录。</span>
                <Button variant="destructive" className="shrink-0 self-start sm:self-auto" onClick={() => setConfirmDel(true)}>
                  <Trash2 className="h-4 w-4" /> 删除
                </Button>
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      <ConfirmDialog
        open={confirmDel}
        onClose={() => setConfirmDel(false)}
        onConfirm={() => del.mutate()}
        title={`删除客户端「${c.client_name}」?`}
        description="删除后使用该客户端的应用将无法再登录。此操作需要二次验证。"
        confirmLabel="删除"
        destructive
        loading={del.isPending}
      />

      <ConfirmDialog
        open={confirmRotate}
        onClose={() => setConfirmRotate(false)}
        onConfirm={() => rotate.mutate()}
        loading={rotate.isPending}
        title="轮换客户端密钥？"
        description="将生成新密钥并立即生效；旧密钥仅在短暂的宽限期内可用，请尽快更新接入应用的配置。"
        confirmLabel="轮换"
        destructive
      />

      <Dialog
        open={!!secret}
        onClose={() => setSecret(null)}
        title="客户端密钥"
        lockClose
        footer={<Button onClick={() => setSecret(null)}>我已保存</Button>}
      >
        <p className="text-sm text-muted-foreground">请妥善保管密钥，关闭后无法再次查看。</p>
        <div className="mt-3 flex items-center justify-between gap-2 break-all rounded-md border bg-muted/40 p-3 font-mono text-sm">
          <span className="break-all">{secret}</span>
          {secret && <CopyButton value={secret} />}
        </div>
      </Dialog>
    </div>
  );
}
