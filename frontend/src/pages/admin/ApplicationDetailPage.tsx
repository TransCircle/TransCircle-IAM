import * as React from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Settings2 } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, Card, CardContent, Checkbox, Field, Input, PageHeader, Textarea } from "@/components/ui";
import { Dialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { Application, Permission, Role } from "@/lib/types";

export function ApplicationDetailPage() {
  const { id = "" } = useParams();
  const [tab, setTab] = React.useState<"permissions" | "roles">("permissions");
  const app = useQuery<Application[]>({
    queryKey: ["applications"],
    queryFn: async () => (await api.get("/api/v1/admin/applications")).data.applications ?? [],
  });
  const current = app.data?.find((a) => a.id === id);

  return (
    <div>
      <PageHeader title={current?.display_name || "应用"} description={current?.description} />
      <div className="mb-4 flex gap-2 rounded-md bg-muted p-1 text-sm w-fit">
        <button className={`rounded px-4 py-1.5 ${tab === "permissions" ? "bg-card shadow" : ""}`} onClick={() => setTab("permissions")}>权限</button>
        <button className={`rounded px-4 py-1.5 ${tab === "roles" ? "bg-card shadow" : ""}`} onClick={() => setTab("roles")}>角色</button>
      </div>
      {tab === "permissions" ? <PermissionsTab appId={id} /> : <RolesTab appId={id} />}
    </div>
  );
}

function PermissionsTab({ appId }: { appId: string }) {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.permissions.write");
  const [open, setOpen] = React.useState(false);
  const [form, setForm] = React.useState({ key: "", display_name: "", description: "", notes: "", category: "" });

  const perms = useQuery<Permission[]>({
    queryKey: ["app-perms", appId],
    queryFn: async () => (await api.get(`/api/v1/admin/applications/${appId}/permissions`)).data.permissions ?? [],
  });
  const create = useMutation({
    mutationFn: () => api.post(`/api/v1/admin/applications/${appId}/permissions`, form),
    onSuccess: () => {
      setOpen(false);
      setForm({ key: "", display_name: "", description: "", notes: "", category: "" });
      qc.invalidateQueries({ queryKey: ["app-perms", appId] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const del = useMutation({
    mutationFn: (pid: string) => api.delete(`/api/v1/admin/permissions/${pid}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["app-perms", appId] }),
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
                <Button size="icon" variant="ghost" onClick={() => del.mutate(p.id)}><Trash2 className="h-4 w-4" /></Button>
              )}
            </CardContent>
          </Card>
        ))}
        {(perms.data ?? []).length === 0 && <p className="text-sm text-muted-foreground">暂无权限。</p>}
      </div>

      <Dialog open={open} onClose={() => setOpen(false)} title="新建权限"
        footer={<><Button variant="outline" onClick={() => setOpen(false)}>取消</Button><Button onClick={() => create.mutate()} loading={create.isPending}>创建</Button></>}>
        <div className="space-y-4">
          <Field label="标识 (key)" hint="如 doc.read" help="应用内唯一的权限标识，应用会用它来判断用户能否执行某操作。">
            <Input value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} />
          </Field>
          <Field label="名称"><Input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
          <Field label="分类"><Input value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} /></Field>
          <Field label="描述"><Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
          <Field label="备注"><Textarea value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></Field>
        </div>
      </Dialog>
    </div>
  );
}

function RolesTab({ appId }: { appId: string }) {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.roles.write");
  const [open, setOpen] = React.useState(false);
  const [editRole, setEditRole] = React.useState<Role | null>(null);
  const [form, setForm] = React.useState({ key: "", display_name: "", description: "", notes: "" });

  const roles = useQuery<Role[]>({
    queryKey: ["app-roles", appId],
    queryFn: async () => (await api.get(`/api/v1/admin/applications/${appId}/roles`)).data.roles ?? [],
  });
  const create = useMutation({
    mutationFn: () => api.post(`/api/v1/admin/applications/${appId}/roles`, form),
    onSuccess: () => {
      setOpen(false);
      setForm({ key: "", display_name: "", description: "", notes: "" });
      qc.invalidateQueries({ queryKey: ["app-roles", appId] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const del = useMutation({
    mutationFn: (rid: string) => api.delete(`/api/v1/admin/roles/${rid}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["app-roles", appId] }),
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
                <div className="flex items-center gap-2 text-sm font-medium">{r.display_name} <Badge variant="muted">{r.key}</Badge></div>
                {r.description && <div className="mt-1 text-xs text-muted-foreground">{r.description}</div>}
              </div>
              {canWrite && (
                <div className="flex gap-1">
                  <Button size="icon" variant="ghost" onClick={() => setEditRole(r)}><Settings2 className="h-4 w-4" /></Button>
                  {!r.is_system && <Button size="icon" variant="ghost" onClick={() => del.mutate(r.id)}><Trash2 className="h-4 w-4" /></Button>}
                </div>
              )}
            </CardContent>
          </Card>
        ))}
        {(roles.data ?? []).length === 0 && <p className="text-sm text-muted-foreground">暂无角色。</p>}
      </div>

      <Dialog open={open} onClose={() => setOpen(false)} title="新建角色"
        footer={<><Button variant="outline" onClick={() => setOpen(false)}>取消</Button><Button onClick={() => create.mutate()} loading={create.isPending}>创建</Button></>}>
        <div className="space-y-4">
          <Field label="标识 (key)" hint="如 editor" help="角色是一组权限的集合；标识用于在该应用内唯一标记此角色。">
            <Input value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} />
          </Field>
          <Field label="名称"><Input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
          <Field label="描述"><Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        </div>
      </Dialog>

      {editRole && <RolePermsDialog role={editRole} appId={appId} onClose={() => setEditRole(null)} canWrite={canWrite} />}
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
