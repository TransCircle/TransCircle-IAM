import * as React from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Save, Trash2 } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import {
  Avatar,
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CheckRow,
  Field,
  Input,
  PageHeader,
  Select,
  Spinner,
  Textarea,
} from "@/components/ui";
import { UserSearchSelect } from "@/components/UserSearchSelect";
import { ConfirmDialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import { ADMIN_ROLE_ID, SUPER_ADMIN_ROLE_ID, type Application, type Group, type Role, type User } from "@/lib/types";

interface GroupMember {
  id: string;
  username: string;
  display_name: string;
  avatar_url: string;
}

interface GroupDetail {
  group: Group;
  members: GroupMember[];
  role_ids: string[];
}

export function GroupDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { hasPermission, isSuperAdmin } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.groups.write");

  const [meta, setMeta] = React.useState<{ display_name: string; description: string } | null>(null);
  const [appId, setAppId] = React.useState("");
  const [confirmDel, setConfirmDel] = React.useState(false);

  const detail = useQuery<GroupDetail>({
    queryKey: ["group", id],
    queryFn: async () => (await api.get(`/api/v1/admin/groups/${id}`)).data,
  });
  const apps = useQuery<Application[]>({
    queryKey: ["applications"],
    queryFn: async () => (await api.get("/api/v1/admin/applications")).data.applications ?? [],
  });
  const roles = useQuery<Role[]>({
    queryKey: ["app-roles", appId],
    queryFn: async () => (await api.get(`/api/v1/admin/applications/${appId}/roles`)).data.roles ?? [],
    enabled: !!appId,
  });

  React.useEffect(() => {
    if (detail.data?.group) setMeta({ display_name: detail.data.group.display_name, description: detail.data.group.description });
  }, [detail.data]);
  React.useEffect(() => {
    if (!appId && apps.data?.length) setAppId(apps.data[0].id);
  }, [apps.data, appId]);

  const save = useMutation({
    mutationFn: () => api.patch(`/api/v1/admin/groups/${id}`, meta),
    onSuccess: () => {
      toast("已保存", "success");
      qc.invalidateQueries({ queryKey: ["group", id] });
      qc.invalidateQueries({ queryKey: ["groups"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const del = useMutation({
    mutationFn: () => api.delete(`/api/v1/admin/groups/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["groups"] });
      navigate("/admin/groups");
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  // Optimistic role toggle: flip role_ids in the ["group", id] cache immediately,
  // roll back on error, reconcile on settle.
  const toggleRole = useMutation({
    mutationFn: ({ role, checked }: { role: Role; checked: boolean }) =>
      checked
        ? api.post(`/api/v1/admin/groups/${id}/roles`, { id: role.id })
        : api.delete(`/api/v1/admin/groups/${id}/roles/${role.id}`),
    onMutate: async ({ role, checked }) => {
      await qc.cancelQueries({ queryKey: ["group", id] });
      const prev = qc.getQueryData<GroupDetail>(["group", id]);
      qc.setQueryData<GroupDetail>(["group", id], (old) =>
        old
          ? { ...old, role_ids: checked ? [...new Set([...old.role_ids, role.id])] : old.role_ids.filter((x) => x !== role.id) }
          : old
      );
      return { prev };
    },
    onError: (e, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(["group", id], ctx.prev);
      toast(errorMessage(e), "error");
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["group", id] }),
  });

  const addMember = useMutation({
    mutationFn: (opt: { id: string; label: string; sublabel?: string; avatar_url?: string | null }) =>
      api.post(`/api/v1/admin/groups/${id}/members`, { user_ids: [opt.id] }),
    onMutate: async (opt) => {
      await qc.cancelQueries({ queryKey: ["group", id] });
      const prev = qc.getQueryData<GroupDetail>(["group", id]);
      qc.setQueryData<GroupDetail>(["group", id], (old) =>
        old && !old.members.some((m) => m.id === opt.id)
          ? { ...old, members: [...old.members, { id: opt.id, username: opt.sublabel || "", display_name: opt.label, avatar_url: opt.avatar_url || "" }] }
          : old
      );
      return { prev };
    },
    onError: (e, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(["group", id], ctx.prev);
      toast(errorMessage(e), "error");
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["group", id] }),
  });

  const removeMember = useMutation({
    mutationFn: (userId: string) => api.delete(`/api/v1/admin/groups/${id}/members/${userId}`),
    onMutate: async (userId) => {
      await qc.cancelQueries({ queryKey: ["group", id] });
      const prev = qc.getQueryData<GroupDetail>(["group", id]);
      qc.setQueryData<GroupDetail>(["group", id], (old) => (old ? { ...old, members: old.members.filter((m) => m.id !== userId) } : old));
      return { prev };
    },
    onError: (e, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(["group", id], ctx.prev);
      toast(errorMessage(e), "error");
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["group", id] }),
  });

  const fetchUsers = async (search: string) => {
    const res = await api.get(`/api/v1/admin/users?search=${encodeURIComponent(search)}&limit=20`);
    return ((res.data.users as User[]) ?? []).map((u) => ({
      id: u.id,
      label: u.display_name || u.username,
      sublabel: u.username,
      avatar_url: u.avatar_url,
    }));
  };

  // Order matters: on a fetch error `meta` never gets set, so the error check
  // must run BEFORE the loading check or this page spins forever.
  if (detail.isError) {
    return (
      <div className="bracket-frame rounded-lg border border-dashed bg-card/50 p-10 text-center text-sm text-muted-foreground">
        身份组不存在或加载失败。
        <div className="mt-3">
          <Button variant="outline" size="sm" onClick={() => navigate("/admin/groups")}>
            返回身份组列表
          </Button>
        </div>
      </div>
    );
  }
  if (detail.isLoading || !meta || !detail.data) {
    return (
      <div className="flex justify-center p-10">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }
  const g = detail.data.group;
  const roleIds = new Set(detail.data.role_ids ?? []);
  const members = detail.data.members ?? [];
  const memberIds = new Set(members.map((m) => m.id));
  const roleLocked = (r: Role) => (r.id === SUPER_ADMIN_ROLE_ID || r.id === ADMIN_ROLE_ID) && !isSuperAdmin;

  return (
    <div className="mx-auto max-w-3xl">
      <button
        onClick={() => navigate("/admin/groups")}
        className="mb-4 flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> 返回身份组列表
      </button>
      <PageHeader
        title={g.display_name}
        description="编辑身份组信息并管理它授予成员的角色。标识 (key) 不可更改。"
        action={
          canWrite && !g.is_system && (
            <Button onClick={() => save.mutate()} loading={save.isPending}>
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
            <Field label="标识 (key)（不可更改）">
              <Input value={g.key} disabled />
            </Field>
            <Field label="名称">
              <Input value={meta.display_name} disabled={!canWrite || g.is_system} onChange={(e) => setMeta({ ...meta, display_name: e.target.value })} />
            </Field>
            <Field label="描述">
              <Textarea value={meta.description} disabled={!canWrite || g.is_system} onChange={(e) => setMeta({ ...meta, description: e.target.value })} />
            </Field>
            <p className="text-xs text-muted-foreground">成员数量：{members.length}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>成员</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {canWrite && (
              <div>
                <UserSearchSelect
                  selectedIds={memberIds}
                  fetchOptions={fetchUsers}
                  onAdd={(o) => addMember.mutate(o)}
                  onRemove={(o) => removeMember.mutate(o.id)}
                />
                <p className="mt-1.5 text-xs text-muted-foreground">搜索并点选用户即可批量加入；已是成员的会显示对勾。</p>
              </div>
            )}
            <div className="space-y-2">
              {members.length === 0 && <p className="text-sm text-muted-foreground">暂无成员。</p>}
              {members.map((m) => (
                <div key={m.id} className="flex items-center justify-between gap-2 rounded-lg border p-2.5">
                  <div className="flex min-w-0 items-center gap-2.5">
                    <Avatar src={m.avatar_url} name={m.display_name || m.username} size="sm" />
                    <div className="min-w-0 leading-tight">
                      <div className="truncate text-sm font-medium">{m.display_name || m.username}</div>
                      <div className="truncate text-xs text-muted-foreground">@{m.username}</div>
                    </div>
                  </div>
                  {canWrite && (
                    <Button size="icon" variant="ghost" className="shrink-0" onClick={() => removeMember.mutate(m.id)} aria-label="移除成员">
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>授予的角色</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Select
              value={appId}
              onValueChange={setAppId}
              options={(apps.data ?? []).map((a) => ({ value: a.id, label: a.display_name }))}
            />
            <p className="text-xs text-muted-foreground">勾选后，组内所有成员都会获得该应用下的对应角色。</p>
            <div className="space-y-2">
              {(roles.data ?? []).map((r) => (
                <CheckRow
                  key={r.id}
                  checked={roleIds.has(r.id)}
                  disabled={!canWrite}
                  locked={roleLocked(r)}
                  lockedHint="仅超级管理员可将管理员/超级管理员角色授予身份组。"
                  onToggle={(checked) => toggleRole.mutate({ role: r, checked })}
                >
                  {r.display_name} <Badge variant="muted">{r.key}</Badge>
                </CheckRow>
              ))}
              {(roles.data ?? []).length === 0 && <p className="text-xs text-muted-foreground">该应用暂无角色。</p>}
            </div>
          </CardContent>
        </Card>

        {canWrite && !g.is_system && (
          <Card>
            <CardHeader>
              <CardTitle>危险操作</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col gap-3 rounded-lg border border-destructive/30 p-3 sm:flex-row sm:items-center sm:justify-between">
                <span className="text-sm">删除后组成员将失去该组授予的角色。</span>
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
        title={`删除身份组「${g.display_name}」?`}
        description="删除后组成员将失去该组授予的角色。"
        confirmLabel="删除"
        destructive
        loading={del.isPending}
      />
    </div>
  );
}
