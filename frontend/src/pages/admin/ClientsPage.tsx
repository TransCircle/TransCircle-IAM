import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, RefreshCw } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, Checkbox, Field, Input, PageHeader, Select, Switch, Textarea } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { Dialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { Application, OAuthClient } from "@/lib/types";

const ALL_SCOPES = ["openid", "profile", "email", "offline_access", "tc.permissions"];

export function ClientsPage() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.clients.write");
  const [open, setOpen] = React.useState(false);
  const [secret, setSecret] = React.useState<{ id: string; secret: string } | null>(null);

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
    onSuccess: () => qc.invalidateQueries({ queryKey: ["clients"] }),
  });
  const rotate = useMutation({
    mutationFn: (cid: string) => api.post(`/api/v1/admin/clients/${cid}/rotate-secret`),
    onSuccess: (r, cid) => setSecret({ id: cid, secret: r.data.client_secret }),
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <div>
      <PageHeader
        title="OIDC 客户端"
        description="接入应用通过 OAuth2/OIDC 登录并读取用户权限。"
        action={canWrite && <Button onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> 新建客户端</Button>}
      />
      <DataTable<OAuthClient>
        loading={clients.isLoading}
        rows={clients.data}
        rowKey={(c) => c.id}
        columns={[
          { header: "名称", cell: (c) => <span className="font-medium">{c.client_name}</span> },
          { header: "Client ID", cell: (c) => <code className="text-xs">{c.client_id}</code> },
          { header: "类型", cell: (c) => (c.public ? <Badge variant="muted">公共</Badge> : <Badge>机密</Badge>) },
          { header: "免同意", cell: (c) => (c.skip_consent ? "是" : "否") },
          {
            header: "",
            className: "text-right",
            cell: (c) =>
              canWrite && (
                <div className="flex justify-end gap-1">
                  {!c.public && (
                    <Button size="icon" variant="ghost" title="轮换密钥" onClick={() => rotate.mutate(c.client_id)}>
                      <RefreshCw className="h-4 w-4" />
                    </Button>
                  )}
                  <Button size="icon" variant="ghost" onClick={() => del.mutate(c.client_id)}><Trash2 className="h-4 w-4" /></Button>
                </div>
              ),
          },
        ]}
      />

      <CreateClientDialog open={open} onClose={() => setOpen(false)} apps={apps.data ?? []}
        onCreated={(s) => { setOpen(false); qc.invalidateQueries({ queryKey: ["clients"] }); if (s) setSecret(s); }} />

      <Dialog open={!!secret} onClose={() => setSecret(null)} title="客户端密钥（仅显示一次）" footer={<Button onClick={() => setSecret(null)}>我已保存</Button>}>
        <p className="text-sm text-muted-foreground">请立即复制保存，关闭后无法再次查看。</p>
        <div className="mt-3 break-all rounded-md border bg-muted/40 p-3 font-mono text-sm">{secret?.secret}</div>
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
    if (!open) { setName(""); setAppId(""); setPub(false); setRedirects(""); setSkipConsent(false); }
  }, [open]);

  const create = useMutation({
    mutationFn: () =>
      api.post("/api/v1/admin/clients", {
        client_name: name,
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

  return (
    <Dialog open={open} onClose={onClose} title="新建 OIDC 客户端"
      footer={<><Button variant="outline" onClick={onClose}>取消</Button><Button onClick={() => create.mutate()} loading={create.isPending}>创建</Button></>}>
      <div className="space-y-4">
        <Field label="名称"><Input value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <Field label="绑定应用" help="绑定后，该客户端登录的用户会在令牌/UserInfo 中携带这个应用下的角色与权限声明。">
          <Select
            value={appId}
            onValueChange={setAppId}
            placeholder="（不绑定）"
            options={[{ value: "", label: "（不绑定）" }, ...apps.map((a) => ({ value: a.id, label: a.display_name }))]}
          />
        </Field>
        <Field label="回调地址（每行一个）" help="OAuth 授权完成后允许跳转回的地址，必须与应用实际回调完全一致。">
          <Textarea value={redirects} onChange={(e) => setRedirects(e.target.value)} placeholder="https://app.example.com/callback" />
        </Field>
        <Field label="授权范围 (Scopes)" help="openid 必选；tc.permissions 用于下发该应用下用户的角色与权限。">
          <div className="flex flex-wrap gap-3">
            {ALL_SCOPES.map((s) => (
              <label key={s} className="flex items-center gap-1.5 text-sm">
                <Checkbox
                  checked={scopes.includes(s)}
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
      </div>
    </Dialog>
  );
}
