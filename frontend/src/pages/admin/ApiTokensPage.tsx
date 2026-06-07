import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Pencil } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, CopyButton, Field, Input, PageHeader, RelativeTime } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { Dialog, ConfirmDialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { APIToken } from "@/lib/types";

interface TokenForm {
  name: string;
  apps: string;
  scopes: string;
  days: number;
}

const emptyForm: TokenForm = { name: "", apps: "", scopes: "iam.permissions.read", days: 0 };

function remainingDays(expiresAt: string | null): number {
  if (!expiresAt) return 0;
  return Math.max(0, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 86400000));
}

export function ApiTokensPage() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.apptokens.write");
  const [open, setOpen] = React.useState(false);
  const [edit, setEdit] = React.useState<APIToken | null>(null);
  const [created, setCreated] = React.useState<string | null>(null);
  const [confirm, setConfirm] = React.useState<APIToken | null>(null);
  const [form, setForm] = React.useState<TokenForm>(emptyForm);

  const tokens = useQuery<APIToken[]>({
    queryKey: ["api-tokens"],
    queryFn: async () => (await api.get("/api/v1/admin/api-tokens")).data.tokens ?? [],
  });
  const create = useMutation({
    mutationFn: () =>
      api.post("/api/v1/admin/api-tokens", {
        name: form.name.trim(),
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
  const update = useMutation({
    mutationFn: () =>
      api.patch(`/api/v1/admin/api-tokens/${edit!.id}`, {
        name: form.name.trim(),
        scopes: form.scopes.split(",").map((s) => s.trim()).filter(Boolean),
        allowed_app_keys: form.apps.split(",").map((s) => s.trim()).filter(Boolean),
        expires_in_days: form.days,
      }),
    onSuccess: () => {
      setEdit(null);
      toast("已保存", "success");
      qc.invalidateQueries({ queryKey: ["api-tokens"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/admin/api-tokens/${id}`),
    onSuccess: () => {
      setConfirm(null);
      qc.invalidateQueries({ queryKey: ["api-tokens"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  function openCreate() {
    setForm(emptyForm);
    setOpen(true);
  }
  function openEdit(t: APIToken) {
    setForm({ name: t.name, apps: (t.allowed_app_keys ?? []).join(", "), scopes: (t.scopes ?? []).join(", "), days: remainingDays(t.expires_at) });
    setEdit(t);
  }
  function submitCreate() {
    if (!form.name.trim()) {
      toast("名称不能为空", "error");
      return;
    }
    create.mutate();
  }
  function submitEdit() {
    if (!form.name.trim()) {
      toast("名称不能为空", "error");
      return;
    }
    update.mutate();
  }

  const formFields = (
    <div className="space-y-4">
      <Field label="名称"><Input value={form.name} autoFocus onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
      <Field label="作用域 (逗号分隔)" help="查询用户权限的令牌需包含 iam.permissions.read。">
        <Input value={form.scopes} onChange={(e) => setForm({ ...form, scopes: e.target.value })} />
      </Field>
      <Field label="限定应用 (应用 key，逗号分隔)" help="留空表示可查询全部应用；填写后该令牌只能查询这些应用的用户权限。">
        <Input value={form.apps} onChange={(e) => setForm({ ...form, apps: e.target.value })} />
      </Field>
      <Field label="有效天数 (0 = 永久)" help="编辑时填写的天数从现在重新计算到期时间。">
        <Input type="number" inputMode="numeric" value={form.days} onChange={(e) => setForm({ ...form, days: Number(e.target.value) })} />
      </Field>
    </div>
  );

  return (
    <div>
      <PageHeader
        title="API 令牌"
        description="供后端服务调用权限查询 API 的机器令牌（M2M）。"
        action={canWrite && <Button onClick={openCreate}><Plus className="h-4 w-4" /> 新建令牌</Button>}
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
          { header: "最近使用", cell: (t) => <RelativeTime value={t.last_used_at} /> },
          {
            header: "",
            className: "text-right",
            cell: (t) =>
              canWrite && !t.revoked_at ? (
                <div className="flex justify-end gap-1">
                  <Button size="icon" variant="ghost" title="编辑" onClick={() => openEdit(t)}><Pencil className="h-4 w-4" /></Button>
                  <Button size="icon" variant="ghost" title="吊销" onClick={() => setConfirm(t)}><Trash2 className="h-4 w-4" /></Button>
                </div>
              ) : null,
          },
        ]}
      />

      <Dialog open={open} onClose={() => setOpen(false)} title="新建 API 令牌" onSubmit={submitCreate}
        footer={<><Button variant="outline" type="button" onClick={() => setOpen(false)}>取消</Button><Button type="submit" loading={create.isPending}>创建</Button></>}>
        {formFields}
      </Dialog>

      <Dialog open={!!edit} onClose={() => setEdit(null)} title={`编辑令牌 · ${edit?.name ?? ""}`} onSubmit={submitEdit}
        footer={<><Button variant="outline" type="button" onClick={() => setEdit(null)}>取消</Button><Button type="submit" loading={update.isPending}>保存</Button></>}>
        {formFields}
      </Dialog>

      <ConfirmDialog
        open={!!confirm}
        onClose={() => setConfirm(null)}
        onConfirm={() => confirm && revoke.mutate(confirm.id)}
        title={`吊销令牌「${confirm?.name}」?`}
        description="吊销后使用该令牌的服务将立即失去访问权限。"
        confirmLabel="吊销"
        destructive
        loading={revoke.isPending}
      />

      <Dialog open={!!created} onClose={() => setCreated(null)} title="令牌已创建（仅显示一次）" footer={<Button onClick={() => setCreated(null)}>我已保存</Button>}>
        <p className="text-sm text-muted-foreground">请立即保存，关闭后无法再次查看。在请求头中使用 <code>Authorization: Bearer &lt;token&gt;</code>。</p>
        <div className="mt-3 flex items-center justify-between gap-2 break-all rounded-lg border bg-muted/40 p-3 font-mono text-sm">
          <span className="break-all">{created}</span>
          {created && <CopyButton value={created} />}
        </div>
      </Dialog>
    </div>
  );
}
