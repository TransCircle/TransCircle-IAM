import * as React from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Settings2, Pencil, Save } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Checkbox,
  Field,
  Input,
  PageHeader,
  Spinner,
  Switch,
  Tabs,
  Textarea,
} from "@/components/ui";
import { Dialog, ConfirmDialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { Application, Permission, Role } from "@/lib/types";

export function ApplicationDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [tab, setTab] = React.useState("permissions");
  const app = useQuery<Application[]>({
    queryKey: ["applications"],
    queryFn: async () => (await api.get("/api/v1/admin/applications")).data.applications ?? [],
  });
  const current = app.data?.find((a) => a.id === id);

  if (app.isLoading) {
    return (
      <div className="flex justify-center p-10">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }
  // A bad/stale id must not render a fake-empty page that still fires
  // sub-queries against the unknown application.
  if (app.isError || !current) {
    return (
      <div className="bracket-frame rounded-lg border border-dashed bg-card/50 p-10 text-center text-sm text-muted-foreground">
        应用不存在或加载失败。
        <div className="mt-3">
          <Button variant="outline" size="sm" onClick={() => navigate("/admin/applications")}>
            返回应用列表
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="stagger">
      <PageHeader title={current.display_name} description={current.description} />
      <AppBasicInfo app={current} />
      <div className="mb-4 mt-6">
        <Tabs
          value={tab}
          onValueChange={setTab}
          tabs={[
            { value: "permissions", label: "权限" },
            { value: "roles", label: "角色" },
          ]}
        />
      </div>
      {tab === "permissions" ? <PermissionsTab appId={id} /> : <RolesTab appId={id} />}
    </div>
  );
}

function AppBasicInfo({ app }: { app: Application }) {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.applications.write") && !app.is_system;
  const [form, setForm] = React.useState({ display_name: app.display_name, description: app.description, is_active: app.is_active });
  React.useEffect(() => {
    setForm({ display_name: app.display_name, description: app.description, is_active: app.is_active });
  }, [app]);

  const save = useMutation({
    mutationFn: () => api.patch(`/api/v1/admin/applications/${app.id}`, form),
    onSuccess: () => {
      toast("已保存", "success");
      qc.invalidateQueries({ queryKey: ["applications"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>基本信息</CardTitle>
        {app.is_system && <Badge variant="muted">系统内置（只读）</Badge>}
      </CardHeader>
      <CardContent className="space-y-4">
        <Field label="标识 (key)（不可更改）">
          <Input value={app.key} disabled />
        </Field>
        <Field label="名称">
          <Input value={form.display_name} disabled={!canWrite} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
        </Field>
        <Field label="描述">
          <Textarea value={form.description} disabled={!canWrite} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </Field>
        <div className="flex items-center justify-between rounded-lg border p-3 text-sm">
          <span>启用应用</span>
          <Switch checked={form.is_active} disabled={!canWrite} onCheckedChange={(v) => setForm({ ...form, is_active: v })} />
        </div>
        {canWrite && (
          <div className="flex justify-end">
            <Button onClick={() => save.mutate()} loading={save.isPending}>
              <Save className="h-4 w-4" /> 保存
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function PermissionsTab({ appId }: { appId: string }) {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.permissions.write");
  const empty = { key: "", display_name: "", description: "", notes: "", category: "" };
  const [open, setOpen] = React.useState(false);
  const [edit, setEdit] = React.useState<Permission | null>(null);
  const [confirmDel, setConfirmDel] = React.useState<Permission | null>(null);
  const [form, setForm] = React.useState(empty);
  React.useEffect(() => {
    if (!open) setForm(empty);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const perms = useQuery<Permission[]>({
    queryKey: ["app-perms", appId],
    queryFn: async () => (await api.get(`/api/v1/admin/applications/${appId}/permissions`)).data.permissions ?? [],
  });
  const create = useMutation({
    mutationFn: () => api.post(`/api/v1/admin/applications/${appId}/permissions`, form),
    onSuccess: () => {
      setOpen(false);
      setForm(empty);
      qc.invalidateQueries({ queryKey: ["app-perms", appId] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const update = useMutation({
    mutationFn: (p: Permission) =>
      api.patch(`/api/v1/admin/permissions/${p.id}`, {
        display_name: p.display_name,
        description: p.description,
        notes: p.notes,
        category: p.category,
      }),
    onSuccess: () => {
      setEdit(null);
      qc.invalidateQueries({ queryKey: ["app-perms", appId] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const del = useMutation({
    mutationFn: (pid: string) => api.delete(`/api/v1/admin/permissions/${pid}`),
    onSuccess: () => {
      setConfirmDel(null);
      qc.invalidateQueries({ queryKey: ["app-perms", appId] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <div className="space-y-3">
      {canWrite && (
        <div className="flex justify-end">
          <Button size="sm" onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> 新建权限</Button>
        </div>
      )}
      <div className="grid gap-2">
        {(perms.data ?? []).map((p) => (
          <Card key={p.id}>
            <CardContent className="flex items-center justify-between p-4">
              <div>
                <div className="flex items-center gap-2 text-sm font-medium">
                  {p.display_name} <Badge variant="muted">{p.key}</Badge>
                  {p.category && <Badge>{p.category}</Badge>}
                </div>
                {p.description && <div className="mt-1 text-xs text-muted-foreground">{p.description}</div>}
                {p.notes && <div className="mt-0.5 text-xs text-muted-foreground">备注：{p.notes}</div>}
              </div>
              {canWrite && !p.is_system && (
                <div className="flex gap-1">
                  <Button size="icon" variant="ghost" title="编辑" onClick={() => setEdit(p)}><Pencil className="h-4 w-4" /></Button>
                  <Button size="icon" variant="ghost" title="删除" onClick={() => setConfirmDel(p)}><Trash2 className="h-4 w-4" /></Button>
                </div>
              )}
              {p.is_system && <Badge variant="muted">内置</Badge>}
            </CardContent>
          </Card>
        ))}
        {(perms.data ?? []).length === 0 && <p className="text-sm text-muted-foreground">暂无权限。</p>}
      </div>

      <ConfirmDialog
        open={!!confirmDel}
        onClose={() => setConfirmDel(null)}
        onConfirm={() => confirmDel && del.mutate(confirmDel.id)}
        loading={del.isPending}
        title={`删除权限「${confirmDel?.display_name}」？`}
        description={`标识 ${confirmDel?.key}。删除后所有用户/角色对它的授权将一并移除。`}
        confirmLabel="删除"
        destructive
      />

      <Dialog open={open} onClose={() => setOpen(false)} title="新建权限" onSubmit={() => create.mutate()} submitting={create.isPending}
        footer={<><Button variant="outline" type="button" onClick={() => setOpen(false)}>取消</Button><Button type="submit" loading={create.isPending}>创建</Button></>}>
        <div className="space-y-4">
          <Field label="标识 (key)" hint="如 doc.read" help="应用内唯一的权限标识，应用会用它来判断用户能否执行某操作。">
            <Input value={form.key} autoFocus onChange={(e) => setForm({ ...form, key: e.target.value })} />
          </Field>
          <Field label="名称"><Input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
          <Field label="分类"><Input value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} /></Field>
          <Field label="描述"><Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
          <Field label="备注"><Textarea value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></Field>
        </div>
      </Dialog>

      {edit && (
        <Dialog open onClose={() => setEdit(null)} title={`编辑权限 · ${edit.key}`} onSubmit={() => update.mutate(edit)}
          footer={<><Button variant="outline" type="button" onClick={() => setEdit(null)}>取消</Button><Button type="submit" loading={update.isPending}>保存</Button></>}>
          <div className="space-y-4">
            <Field label="标识 (key)（不可更改）"><Input value={edit.key} disabled /></Field>
            <Field label="名称"><Input value={edit.display_name} autoFocus onChange={(e) => setEdit({ ...edit, display_name: e.target.value })} /></Field>
            <Field label="分类"><Input value={edit.category} onChange={(e) => setEdit({ ...edit, category: e.target.value })} /></Field>
            <Field label="描述"><Textarea value={edit.description} onChange={(e) => setEdit({ ...edit, description: e.target.value })} /></Field>
            <Field label="备注"><Textarea value={edit.notes} onChange={(e) => setEdit({ ...edit, notes: e.target.value })} /></Field>
          </div>
        </Dialog>
      )}
    </div>
  );
}

function RolesTab({ appId }: { appId: string }) {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.roles.write");
  const empty = { key: "", display_name: "", description: "", notes: "" };
  const [open, setOpen] = React.useState(false);
  const [editPerms, setEditPerms] = React.useState<Role | null>(null);
  const [editMeta, setEditMeta] = React.useState<Role | null>(null);
  const [confirmDel, setConfirmDel] = React.useState<Role | null>(null);
  const [form, setForm] = React.useState(empty);
  React.useEffect(() => {
    if (!open) setForm(empty);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const roles = useQuery<Role[]>({
    queryKey: ["app-roles", appId],
    queryFn: async () => (await api.get(`/api/v1/admin/applications/${appId}/roles`)).data.roles ?? [],
  });
  const create = useMutation({
    mutationFn: () => api.post(`/api/v1/admin/applications/${appId}/roles`, form),
    onSuccess: () => {
      setOpen(false);
      setForm(empty);
      qc.invalidateQueries({ queryKey: ["app-roles", appId] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const update = useMutation({
    mutationFn: (r: Role) =>
      api.patch(`/api/v1/admin/roles/${r.id}`, { display_name: r.display_name, description: r.description, notes: r.notes }),
    onSuccess: () => {
      setEditMeta(null);
      qc.invalidateQueries({ queryKey: ["app-roles", appId] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const del = useMutation({
    mutationFn: (rid: string) => api.delete(`/api/v1/admin/roles/${rid}`),
    onSuccess: () => {
      setConfirmDel(null);
      qc.invalidateQueries({ queryKey: ["app-roles", appId] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <div className="space-y-3">
      {canWrite && (
        <div className="flex justify-end">
          <Button size="sm" onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> 新建角色</Button>
        </div>
      )}
      <div className="grid gap-2">
        {(roles.data ?? []).map((r) => (
          <Card key={r.id}>
            <CardContent className="flex items-center justify-between p-4">
              <div>
                <div className="flex items-center gap-2 text-sm font-medium">
                  {r.display_name} <Badge variant="muted">{r.key}</Badge>
                  {r.is_system && <Badge variant="muted">内置</Badge>}
                </div>
                {r.description && <div className="mt-1 text-xs text-muted-foreground">{r.description}</div>}
                {r.notes && <div className="mt-0.5 text-xs text-muted-foreground">备注：{r.notes}</div>}
              </div>
              {canWrite && (
                <div className="flex gap-1">
                  <Button size="icon" variant="ghost" title="权限" onClick={() => setEditPerms(r)}><Settings2 className="h-4 w-4" /></Button>
                  {!r.is_system && <Button size="icon" variant="ghost" title="编辑" onClick={() => setEditMeta(r)}><Pencil className="h-4 w-4" /></Button>}
                  {!r.is_system && <Button size="icon" variant="ghost" title="删除" onClick={() => setConfirmDel(r)}><Trash2 className="h-4 w-4" /></Button>}
                </div>
              )}
            </CardContent>
          </Card>
        ))}
        {(roles.data ?? []).length === 0 && <p className="text-sm text-muted-foreground">暂无角色。</p>}
      </div>

      <ConfirmDialog
        open={!!confirmDel}
        onClose={() => setConfirmDel(null)}
        onConfirm={() => confirmDel && del.mutate(confirmDel.id)}
        loading={del.isPending}
        title={`删除角色「${confirmDel?.display_name}」？`}
        description={`标识 ${confirmDel?.key}。删除后拥有该角色的用户/身份组将失去其权限。`}
        confirmLabel="删除"
        destructive
      />

      <Dialog open={open} onClose={() => setOpen(false)} title="新建角色" onSubmit={() => create.mutate()} submitting={create.isPending}
        footer={<><Button variant="outline" type="button" onClick={() => setOpen(false)}>取消</Button><Button type="submit" loading={create.isPending}>创建</Button></>}>
        <div className="space-y-4">
          <Field label="标识 (key)" hint="如 editor" help="角色是一组权限的集合；标识用于在该应用内唯一标记此角色。">
            <Input value={form.key} autoFocus onChange={(e) => setForm({ ...form, key: e.target.value })} />
          </Field>
          <Field label="名称"><Input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
          <Field label="描述"><Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
          <Field label="备注"><Textarea value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></Field>
        </div>
      </Dialog>

      {editMeta && (
        <Dialog open onClose={() => setEditMeta(null)} title={`编辑角色 · ${editMeta.key}`} onSubmit={() => update.mutate(editMeta)}
          footer={<><Button variant="outline" type="button" onClick={() => setEditMeta(null)}>取消</Button><Button type="submit" loading={update.isPending}>保存</Button></>}>
          <div className="space-y-4">
            <Field label="标识 (key)（不可更改）"><Input value={editMeta.key} disabled /></Field>
            <Field label="名称"><Input value={editMeta.display_name} autoFocus onChange={(e) => setEditMeta({ ...editMeta, display_name: e.target.value })} /></Field>
            <Field label="描述"><Textarea value={editMeta.description} onChange={(e) => setEditMeta({ ...editMeta, description: e.target.value })} /></Field>
            <Field label="备注"><Textarea value={editMeta.notes} onChange={(e) => setEditMeta({ ...editMeta, notes: e.target.value })} /></Field>
          </div>
        </Dialog>
      )}

      {editPerms && <RolePermsDialog role={editPerms} appId={appId} onClose={() => setEditPerms(null)} canWrite={canWrite} />}
    </div>
  );
}

function RolePermsDialog({ role, appId, onClose, canWrite }: { role: Role; appId: string; onClose: () => void; canWrite: boolean }) {
  const { toast } = useToast();
  const perms = useQuery<Permission[]>({
    queryKey: ["app-perms", appId],
    queryFn: async () => (await api.get(`/api/v1/admin/applications/${appId}/permissions`)).data.permissions ?? [],
  });
  const current = useQuery<{ permission_ids: string[] }>({
    queryKey: ["role-perms", role.id],
    queryFn: async () => (await api.get(`/api/v1/admin/roles/${role.id}/permissions`)).data,
  });
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  React.useEffect(() => {
    if (current.data) setSelected(new Set(current.data.permission_ids));
  }, [current.data]);

  const save = useMutation({
    mutationFn: () => api.put(`/api/v1/admin/roles/${role.id}/permissions`, { permission_ids: [...selected] }),
    onSuccess: () => {
      toast("已保存角色权限", "success");
      onClose();
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <Dialog open onClose={onClose} title={`角色权限 · ${role.display_name}`}
      footer={canWrite && <Button onClick={() => save.mutate()} loading={save.isPending}>保存</Button>}>
      <div className="max-h-80 space-y-2 overflow-y-auto">
        {(perms.data ?? []).map((p) => (
          <label key={p.id} className="flex items-center gap-2 text-sm">
            <Checkbox
              checked={selected.has(p.id)}
              disabled={!canWrite}
              onCheckedChange={(checked) => {
                const next = new Set(selected);
                if (checked) next.add(p.id);
                else next.delete(p.id);
                setSelected(next);
              }}
            />
            {p.display_name} <Badge variant="muted">{p.key}</Badge>
          </label>
        ))}
      </div>
    </Dialog>
  );
}
