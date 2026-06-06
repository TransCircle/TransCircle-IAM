import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Settings2 } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, Checkbox, Field, Help, Input, PageHeader, Select, Textarea } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { Dialog, ConfirmDialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import { ADMIN_ROLE_ID, SUPER_ADMIN_ROLE_ID, type Application, type Group, type Role } from "@/lib/types";

export function GroupsPage() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.groups.write");
  const [open, setOpen] = React.useState(false);
  const [manage, setManage] = React.useState<Group | null>(null);
  const [confirm, setConfirm] = React.useState<Group | null>(null);
  const [form, setForm] = React.useState({ key: "", display_name: "", description: "" });

  const groups = useQuery<Group[]>({
    queryKey: ["groups"],
    queryFn: async () => (await api.get("/api/v1/admin/groups")).data.groups ?? [],
  });

  const create = useMutation({
    mutationFn: () => api.post("/api/v1/admin/groups", form),
    onSuccess: () => {
      setOpen(false);
      setForm({ key: "", display_name: "", description: "" });
      qc.invalidateQueries({ queryKey: ["groups"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const del = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/admin/groups/${id}`),
    onSuccess: () => {
      setConfirm(null);
      qc.invalidateQueries({ queryKey: ["groups"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <div>
      <PageHeader
        title="身份组"
        description="身份组将一组角色批量授予其成员。"
        action={canWrite && <Button onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> 新建身份组</Button>}
      />
      <DataTable<Group>
        loading={groups.isLoading}
        rows={groups.data}
        rowKey={(g) => g.id}
        columns={[
          { header: "名称", cell: (g) => <span className="font-medium">{g.display_name}</span> },
          { header: "标识", cell: (g) => <Badge variant="muted">{g.key}</Badge> },
          { header: "描述", cell: (g) => g.description || "—" },
          {
            header: "",
            className: "text-right",
            cell: (g) =>
              canWrite && (
                <div className="flex justify-end gap-1">
                  <Button size="icon" variant="ghost" onClick={() => setManage(g)}><Settings2 className="h-4 w-4" /></Button>
                  {!g.is_system && (
                    <Button size="icon" variant="ghost" title="删除" onClick={() => setConfirm(g)}><Trash2 className="h-4 w-4" /></Button>
                  )}
                </div>
              ),
          },
        ]}
      />

      <Dialog open={open} onClose={() => setOpen(false)} title="新建身份组"
        footer={<><Button variant="outline" onClick={() => setOpen(false)}>取消</Button><Button onClick={() => create.mutate()} loading={create.isPending}>创建</Button></>}>
        <div className="space-y-4">
          <Field label="Key"><Input value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} /></Field>
          <Field label="名称"><Input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
          <Field label="描述"><Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        </div>
      </Dialog>

      {manage && <ManageGroupRolesDialog group={manage} onClose={() => setManage(null)} canWrite={canWrite} />}

      <ConfirmDialog
        open={!!confirm}
        onClose={() => setConfirm(null)}
        onConfirm={() => confirm && del.mutate(confirm.id)}
        title={`删除身份组「${confirm?.display_name}」?`}
        description="删除后组成员将失去该组授予的角色。"
        confirmLabel="删除"
        destructive
        loading={del.isPending}
      />
    </div>
  );
}

function ManageGroupRolesDialog({ group, onClose, canWrite }: { group: Group; onClose: () => void; canWrite: boolean }) {
  const { toast } = useToast();
  const { isSuperAdmin } = useAuth();
  const roleLocked = (r: Role) => (r.id === SUPER_ADMIN_ROLE_ID || r.id === ADMIN_ROLE_ID) && !isSuperAdmin;
  const [appId, setAppId] = React.useState("");
  const detail = useQuery<{ role_ids: string[] }>({
    queryKey: ["group", group.id],
    queryFn: async () => (await api.get(`/api/v1/admin/groups/${group.id}`)).data,
  });
  const apps = useQuery<Application[]>({
    queryKey: ["applications"],
    queryFn: async () => (await api.get("/api/v1/admin/applications")).data.applications ?? [],
  });
  React.useEffect(() => {
    if (!appId && apps.data?.length) setAppId(apps.data[0].id);
  }, [apps.data, appId]);
  const roles = useQuery<Role[]>({
    queryKey: ["app-roles", appId],
    queryFn: async () => (await api.get(`/api/v1/admin/applications/${appId}/roles`)).data.roles ?? [],
    enabled: !!appId,
  });
  const qc = useQueryClient();
  const roleIds = new Set(detail.data?.role_ids ?? []);

  return (
    <Dialog open onClose={onClose} title={`管理身份组角色 · ${group.display_name}`} footer={<Button onClick={onClose}>完成</Button>}>
      <div className="space-y-4">
        <Select
          value={appId}
          onValueChange={setAppId}
          options={(apps.data ?? []).map((a) => ({ value: a.id, label: a.display_name }))}
        />
        <p className="text-xs text-muted-foreground">勾选后，组内所有成员都会获得该应用下的对应角色。</p>
        <div className="space-y-2">
          {(roles.data ?? []).map((r) => (
            <label key={r.id} className="flex items-center gap-2.5 text-sm">
              <Checkbox
                checked={roleIds.has(r.id)}
                disabled={!canWrite || roleLocked(r)}
                onCheckedChange={async (checked) => {
                  try {
                    if (checked) await api.post(`/api/v1/admin/groups/${group.id}/roles`, { id: r.id });
                    else await api.delete(`/api/v1/admin/groups/${group.id}/roles/${r.id}`);
                    qc.invalidateQueries({ queryKey: ["group", group.id] });
                  } catch (e) {
                    toast(errorMessage(e), "error");
                  }
                }}
              />
              {r.display_name} <Badge variant="muted">{r.key}</Badge>
              {roleLocked(r) && <Help text="仅超级管理员可将管理员/超级管理员角色授予身份组。" />}
            </label>
          ))}
          {(roles.data ?? []).length === 0 && <p className="text-xs text-muted-foreground">该应用暂无角色。</p>}
        </div>
      </div>
    </Dialog>
  );
}
