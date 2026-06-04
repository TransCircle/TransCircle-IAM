import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, Field, Input, PageHeader } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { Dialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { APIToken } from "@/lib/types";
import { formatDate } from "@/lib/utils";

export function ApiTokensPage() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.apptokens.write");
  const [open, setOpen] = React.useState(false);
  const [created, setCreated] = React.useState<string | null>(null);
  const [form, setForm] = React.useState({ name: "", apps: "", scopes: "iam.permissions.read", days: 0 });

  const tokens = useQuery<APIToken[]>({
    queryKey: ["api-tokens"],
    queryFn: async () => (await api.get("/api/v1/admin/api-tokens")).data.tokens ?? [],
  });
  const create = useMutation({
    mutationFn: () =>
      api.post("/api/v1/admin/api-tokens", {
        name: form.name,
        scopes: form.scopes.split(",").map((s) => s.trim()).filter(Boolean),
        allowed_app_keys: form.apps.split(",").map((s) => s.trim()).filter(Boolean),
        expires_in_days: form.days,
      }),
    onSuccess: (r) => {
      setOpen(false);
      setCreated(r.data.token);
      qc.invalidateQueries({ queryKey: ["api-tokens"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/admin/api-tokens/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-tokens"] }),
  });

  return (
    <div>
      <PageHeader
        title="API 令牌"
        description="供后端服务调用权限查询 API 的机器令牌（M2M）。"
        action={canWrite && <Button onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> 新建令牌</Button>}
      />
      <DataTable<APIToken>
        loading={tokens.isLoading}
        rows={tokens.data}
        rowKey={(t) => t.id}
        columns={[
          { header: "名称", cell: (t) => <span className="font-medium">{t.name}</span> },
          { header: "前缀", cell: (t) => <code className="text-xs">tcp_{t.prefix}…</code> },
          { header: "限定应用", cell: (t) => (t.allowed_app_keys?.length ? t.allowed_app_keys.join(", ") : "全部") },
          { header: "状态", cell: (t) => (t.revoked_at ? <Badge variant="muted">已吊销</Badge> : <Badge variant="success">有效</Badge>) },
          { header: "最近使用", cell: (t) => formatDate(t.last_used_at) },
          {
            header: "",
            className: "text-right",
            cell: (t) =>
              canWrite && !t.revoked_at && <Button size="icon" variant="ghost" onClick={() => revoke.mutate(t.id)}><Trash2 className="h-4 w-4" /></Button>,
          },
        ]}
      />

      <Dialog open={open} onClose={() => setOpen(false)} title="新建 API 令牌"
        footer={<><Button variant="outline" onClick={() => setOpen(false)}>取消</Button><Button onClick={() => create.mutate()} loading={create.isPending}>创建</Button></>}>
        <div className="space-y-4">
          <Field label="名称"><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
          <Field label="作用域 (逗号分隔)"><Input value={form.scopes} onChange={(e) => setForm({ ...form, scopes: e.target.value })} /></Field>
          <Field label="限定应用 Key (逗号分隔，留空=全部)"><Input value={form.apps} onChange={(e) => setForm({ ...form, apps: e.target.value })} /></Field>
          <Field label="有效天数 (0=永久)"><Input type="number" value={form.days} onChange={(e) => setForm({ ...form, days: Number(e.target.value) })} /></Field>
        </div>
      </Dialog>

      <Dialog open={!!created} onClose={() => setCreated(null)} title="令牌已创建（仅显示一次）" footer={<Button onClick={() => setCreated(null)}>我已保存</Button>}>
        <p className="text-sm text-muted-foreground">请立即保存，关闭后无法再次查看。在请求头中使用 <code>Authorization: Bearer &lt;token&gt;</code>。</p>
        <div className="mt-3 break-all rounded-md border bg-muted/40 p-3 font-mono text-sm">{created}</div>
      </Dialog>
    </div>
  );
}
