import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Pencil } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, CheckRow, CopyButton, Field, Input, Label, PageHeader, RelativeTime, Select, Spinner } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { Dialog, ConfirmDialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { APIToken } from "@/lib/types";

interface TokenMeta {
  scopes: { key: string; label: string; description: string }[];
  applications: { key: string; display_name: string }[];
  can_unrestrict: boolean;
}

interface TokenForm {
  name: string;
  scopes: string[];
  apps: string[];
  // Expiry preset in days; "0" = never, "keep" (edit only) = leave unchanged.
  days: string;
}

const emptyForm: TokenForm = { name: "", scopes: ["iam.permissions.read"], apps: [], days: "90" };

const DAY_PRESETS = [
  { value: "30", label: "30 天" },
  { value: "90", label: "90 天" },
  { value: "180", label: "180 天" },
  { value: "365", label: "365 天" },
  { value: "0", label: "永久（不过期）" },
];

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
  const meta = useQuery<TokenMeta>({
    queryKey: ["api-tokens-meta"],
    queryFn: async () => (await api.get("/api/v1/admin/api-tokens/meta")).data,
  });

  function body() {
    return {
      name: form.name.trim(),
      scopes: form.scopes,
      allowed_app_keys: form.apps,
    };
  }
  const create = useMutation({
    mutationFn: () => api.post("/api/v1/admin/api-tokens", { ...body(), expires_in_days: Number(form.days) || 0 }),
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
        ...body(),
        // Only re-anchor the expiry when the admin actually picked a new preset.
        ...(form.days === "keep" ? {} : { expires_in_days: Number(form.days) || 0 }),
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
    setForm({ name: t.name, apps: t.allowed_app_keys ?? [], scopes: t.scopes ?? [], days: "keep" });
    setEdit(t);
  }
  function validate(): boolean {
    if (!form.name.trim()) {
      toast("名称不能为空", "error");
      return false;
    }
    if (form.scopes.length === 0) {
      toast("请至少选择一个作用域", "error");
      return false;
    }
    if (form.apps.length === 0 && !(meta.data?.can_unrestrict)) {
      toast("请至少选择一个可访问的应用（仅超级管理员可创建不限应用的令牌）", "error");
      return false;
    }
    return true;
  }

  const toggle = (list: string[], key: string, on: boolean) => (on ? [...list, key] : list.filter((x) => x !== key));

  const formFields = !meta.data ? (
    <div className="flex justify-center py-8">
      <Spinner className="h-6 w-6" />
    </div>
  ) : (
    <div className="space-y-5">
      <Field label="名称" hint="用于辨识用途，例如「Wiki 后端鉴权」。">
        <Input value={form.name} autoFocus onChange={(e) => setForm({ ...form, name: e.target.value })} />
      </Field>

      <div className="space-y-2">
        <Label>作用域（该令牌能调用哪些接口）</Label>
        <div className="space-y-1.5">
          {meta.data.scopes.map((s) => (
            <CheckRow key={s.key} checked={form.scopes.includes(s.key)} onToggle={(c) => setForm({ ...form, scopes: toggle(form.scopes, s.key, c) })}>
              <span className="flex min-w-0 flex-col">
                <span className="flex flex-wrap items-center gap-x-2">
                  <code className="font-mono text-xs">{s.key}</code>
                  <span className="font-medium">{s.label}</span>
                </span>
                <span className="text-xs text-muted-foreground">{s.description}</span>
              </span>
            </CheckRow>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        <Label>限定应用（该令牌只能访问勾选的应用）</Label>
        {meta.data.applications.length === 0 ? (
          <p className="text-xs text-muted-foreground">暂无应用。</p>
        ) : (
          <div className="grid gap-1.5 sm:grid-cols-2">
            {meta.data.applications.map((a) => (
              <CheckRow key={a.key} checked={form.apps.includes(a.key)} onToggle={(c) => setForm({ ...form, apps: toggle(form.apps, a.key, c) })}>
                <span className="flex min-w-0 flex-col">
                  <span className="truncate font-medium">{a.display_name}</span>
                  <code className="truncate font-mono text-[11px] text-muted-foreground">{a.key}</code>
                </span>
              </CheckRow>
            ))}
          </div>
        )}
        <p className="text-xs text-muted-foreground">
          {form.apps.length === 0
            ? meta.data.can_unrestrict
              ? "未勾选 = 不限应用（可访问全部应用）。"
              : "请至少勾选一个应用。"
            : `已限定 ${form.apps.length} 个应用。`}
        </p>
      </div>

      <Field label="有效期">
        <Select
          value={form.days}
          onValueChange={(v) => setForm({ ...form, days: v })}
          options={edit ? [{ value: "keep", label: "保持不变" }, ...DAY_PRESETS] : DAY_PRESETS}
        />
      </Field>
    </div>
  );

  return (
    <div>
      <PageHeader
        title="API 令牌"
        description="供后端服务调用的机器令牌（M2M）。勾选作用域与可访问应用即可，无需手填。"
        action={canWrite && <Button onClick={openCreate}><Plus className="h-4 w-4" /> 新建令牌</Button>}
      />
      <DataTable<APIToken>
        loading={tokens.isLoading}
        error={tokens.isError ? tokens.error : undefined}
        onRetry={() => tokens.refetch()}
        rows={tokens.data}
        rowKey={(t) => t.id}
        columns={[
          { header: "名称", cell: (t) => <span className="font-medium">{t.name}</span> },
          { header: "前缀", cell: (t) => <code className="text-xs">tcp_{t.prefix}…</code> },
          {
            header: "作用域",
            cell: (t) =>
              t.scopes?.length ? (
                <div className="flex flex-wrap gap-1">
                  {t.scopes.map((s) => (
                    <Badge key={s} variant="muted">{s}</Badge>
                  ))}
                </div>
              ) : (
                <span className="text-muted-foreground">—</span>
              ),
          },
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

      <Dialog open={open} onClose={() => setOpen(false)} title="新建 API 令牌" onSubmit={() => validate() && create.mutate()} submitting={create.isPending}
        footer={<><Button variant="outline" type="button" onClick={() => setOpen(false)}>取消</Button><Button type="submit" loading={create.isPending}>创建</Button></>}>
        {formFields}
      </Dialog>

      <Dialog open={!!edit} onClose={() => setEdit(null)} title={`编辑令牌 · ${edit?.name ?? ""}`} onSubmit={() => validate() && update.mutate()} submitting={update.isPending}
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

      <Dialog open={!!created} onClose={() => setCreated(null)} title="令牌已创建（仅显示一次）" lockClose footer={<Button onClick={() => setCreated(null)}>我已保存</Button>}>
        <p className="text-sm text-muted-foreground">请立即保存，关闭后无法再次查看。在请求头中使用 <code className="font-mono">Authorization: Bearer &lt;token&gt;</code>。</p>
        <div className="mt-3 flex items-center justify-between gap-2 break-all rounded-md border bg-muted/40 p-3 font-mono text-sm">
          <span className="break-all">{created}</span>
          {created && <CopyButton value={created} />}
        </div>
      </Dialog>
    </div>
  );
}
