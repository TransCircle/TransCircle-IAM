import * as React from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, Checkbox, CopyButton, Field, Input, PageHeader, Select, Switch, Textarea } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { Dialog, ConfirmDialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { Application, OAuthClient } from "@/lib/types";

const ALL_SCOPES = ["openid", "profile", "email", "offline_access", "tc.permissions"];

export function ClientsPage() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const canWrite = hasPermission("iam.clients.write");
  const [open, setOpen] = React.useState(false);
  const [secret, setSecret] = React.useState<{ id: string; secret: string } | null>(null);
  const [confirm, setConfirm] = React.useState<OAuthClient | null>(null);

  const clients = useQuery<OAuthClient[]>({
    queryKey: ["clients"],
    queryFn: async () => (await api.get("/api/v1/admin/clients")).data.clients ?? [],
  });
  const apps = useQuery<Application[]>({
    queryKey: ["applications"],
    queryFn: async () => (await api.get("/api/v1/admin/applications")).data.applications ?? [],
  });

  const del = useMutation({
    mutationFn: (cid: string) => api.delete(`/api/v1/admin/clients/${cid}`),
    onSuccess: () => {
      setConfirm(null);
      qc.invalidateQueries({ queryKey: ["clients"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <div>
      <PageHeader
        title="OIDC 客户端"
        description="接入应用通过 OAuth2/OIDC 登录并读取用户权限。点击任一客户端进入详情可编辑全部配置。"
        action={canWrite && <Button onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> 新建客户端</Button>}
      />
      <DataTable<OAuthClient>
        loading={clients.isLoading}
        error={clients.isError ? clients.error : undefined}
        onRetry={() => clients.refetch()}
        rows={clients.data}
        rowKey={(c) => c.id}
        onRowClick={(c) => navigate(`/admin/clients/${c.client_id}`)}
        columns={[
          { header: "名称", cell: (c) => <span className="font-medium">{c.client_name}</span> },
          { header: "Client ID", cell: (c) => <code className="font-mono text-xs">{c.client_id}</code> },
          { header: "类型", cell: (c) => (c.public ? <Badge variant="muted">公共</Badge> : <Badge>机密</Badge>) },
          { header: "状态", cell: (c) => (c.active ? <Badge variant="success">启用</Badge> : <Badge variant="muted">停用</Badge>) },
          {
            header: "",
            className: "text-right",
            cell: (c) =>
              canWrite && (
                <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                  <Button size="icon" variant="ghost" title="删除" onClick={() => setConfirm(c)}><Trash2 className="h-4 w-4" /></Button>
                </div>
              ),
          },
        ]}
      />

      <CreateClientDialog open={open} onClose={() => setOpen(false)} apps={apps.data ?? []}
        onCreated={(s) => { setOpen(false); qc.invalidateQueries({ queryKey: ["clients"] }); if (s) setSecret(s); }} />

      <ConfirmDialog
        open={!!confirm}
        onClose={() => setConfirm(null)}
        onConfirm={() => confirm && del.mutate(confirm.client_id)}
        title={`删除客户端「${confirm?.client_name}」?`}
        description="删除后使用该客户端的应用将无法再登录。此操作需要二次验证。"
        confirmLabel="删除"
        destructive
        loading={del.isPending}
      />

      <Dialog
        open={!!secret}
        onClose={() => setSecret(null)}
        title="客户端密钥（仅显示一次）"
        lockClose
        footer={<Button onClick={() => setSecret(null)}>我已保存</Button>}
      >
        <p className="text-sm text-muted-foreground">请立即复制保存，关闭后无法再次查看。</p>
        <div className="mt-3 flex items-center justify-between gap-2 break-all rounded-md border bg-muted/40 p-3 font-mono text-sm">
          <span className="break-all">{secret?.secret}</span>
          {secret && <CopyButton value={secret.secret} />}
        </div>
      </Dialog>
    </div>
  );
}

function CreateClientDialog({
  open, onClose, apps, onCreated,
}: {
  open: boolean;
  onClose: () => void;
  apps: Application[];
  onCreated: (secret: { id: string; secret: string } | null) => void;
}) {
  const { toast } = useToast();
  const [name, setName] = React.useState("");
  const [appId, setAppId] = React.useState("");
  const [pub, setPub] = React.useState(false);
  const [redirects, setRedirects] = React.useState("");
  const [scopes, setScopes] = React.useState<string[]>(["openid", "profile", "email", "tc.permissions"]);
  const [skipConsent, setSkipConsent] = React.useState(false);

  React.useEffect(() => {
    if (!open) {
      setName("");
      setAppId("");
      setPub(false);
      setRedirects("");
      setScopes(["openid", "profile", "email", "tc.permissions"]);
      setSkipConsent(false);
    }
  }, [open]);

  const create = useMutation({
    mutationFn: () =>
      api.post("/api/v1/admin/clients", {
        client_name: name.trim(),
        app_id: appId || null,
        public: pub,
        redirect_uris: redirects.split("\n").map((s) => s.trim()).filter(Boolean),
        allowed_scopes: scopes,
        grant_types: pub ? ["authorization_code", "refresh_token"] : ["authorization_code", "refresh_token", "client_credentials"],
        skip_consent: skipConsent,
      }),
    onSuccess: (r) => {
      const s = r.data.client_secret ? { id: r.data.client.client_id, secret: r.data.client_secret } : null;
      onCreated(s);
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  function submit() {
    if (!name.trim()) {
      toast("名称不能为空", "error");
      return;
    }
    if (!scopes.includes("openid")) {
      toast("openid 是 OIDC 必需范围，不能取消", "error");
      return;
    }
    create.mutate();
  }

  return (
    <Dialog open={open} onClose={onClose} title="新建 OIDC 客户端" onSubmit={submit} submitting={create.isPending}
      footer={<><Button variant="outline" type="button" onClick={onClose}>取消</Button><Button type="submit" loading={create.isPending}>创建</Button></>}>
      <div className="space-y-4">
        <Field label="名称"><Input value={name} autoFocus onChange={(e) => setName(e.target.value)} /></Field>
        <Field label="绑定应用" help="绑定后，该客户端登录的用户会在令牌/UserInfo 中携带这个应用下的角色与权限声明。">
          <Select
            value={appId}
            onValueChange={setAppId}
            placeholder="（不绑定）"
            options={[{ value: "", label: "（不绑定）" }, ...apps.map((a) => ({ value: a.id, label: a.display_name }))]}
          />
        </Field>
        <Field label="回调地址（每行一个）" help="OAuth 授权完成后允许跳转回的地址，必须与应用实际回调完全一致。">
          <Textarea value={redirects} spellCheck={false} onChange={(e) => setRedirects(e.target.value)} placeholder="https://app.example.com/callback" />
        </Field>
        <Field label="授权范围 (Scopes)" help="openid 必选；tc.permissions 用于下发该应用下用户的角色与权限。">
          <div className="flex flex-wrap gap-3">
            {ALL_SCOPES.map((s) => (
              <label key={s} className="flex items-center gap-1.5 font-mono text-sm">
                <Checkbox
                  checked={scopes.includes(s)}
                  disabled={s === "openid"}
                  onCheckedChange={(checked) => setScopes((prev) => (checked ? [...prev, s] : prev.filter((x) => x !== s)))}
                />
                {s}
              </label>
            ))}
          </div>
        </Field>
        <div className="flex items-center justify-between rounded-lg border p-3 text-sm">
          <span>公共客户端（SPA/移动端，使用 PKCE 且无密钥）</span>
          <Switch checked={pub} onCheckedChange={setPub} />
        </div>
        <div className="flex items-center justify-between rounded-lg border p-3 text-sm">
          <span>可信应用（跳过授权同意屏）</span>
          <Switch checked={skipConsent} onCheckedChange={setSkipConsent} />
        </div>
        <p className="text-xs text-muted-foreground">创建后可在详情页编辑回调、范围、授权类型、受众、PKCE、启停等全部配置。</p>
      </div>
    </Dialog>
  );
}
