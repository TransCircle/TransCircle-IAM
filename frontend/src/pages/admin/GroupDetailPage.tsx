import * as React from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Save, Trash2 } from "lucide-react";
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
  Help,
  Input,
  PageHeader,
  Select,
  Spinner,
  Textarea,
} from "@/components/ui";
import { ConfirmDialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import { ADMIN_ROLE_ID, SUPER_ADMIN_ROLE_ID, type Application, type Group, type Role } from "@/lib/types";

interface GroupDetail {
  group: Group;
  member_ids: string[];
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

  if (detail.isLoading || !meta) {
    return (
      <div className="flex justify-center p-10">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }
  if (detail.isError || !detail.data) {
    return <div className="text-sm text-destructive">身份组不存在或加载失败。</div>;
  }
  const g = detail.data.group;
  const roleIds = new Set(detail.data.role_ids);
  const roleLocked = (r: Role) => (r.id === SUPER_ADMIN_ROLE_ID || r.id === ADMIN_ROLE_ID) && !isSuperAdmin;

  async function toggleRole(r: Role, checked: boolean) {
    try {
      if (checked) await api.post(`/api/v1/admin/groups/${id}/roles`, { id: r.id });
      else await api.delete(`/api/v1/admin/groups/${id}/roles/${r.id}`);
      qc.invalidateQueries({ queryKey: ["group", id] });
    } catch (e) {
      toast(errorMessage(e), "error");
    }
  }

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
            <p className="text-xs text-muted-foreground">成员数量：{detail.data.member_ids.length}（成员通过用户详情页的「身份组」管理）。</p>
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
                <label key={r.id} className="flex items-center gap-2.5 text-sm">
                  <Checkbox
                    checked={roleIds.has(r.id)}
                    disabled={!canWrite || roleLocked(r)}
                    onCheckedChange={(checked) => toggleRole(r, checked)}
                  />
                  {r.display_name} <Badge variant="muted">{r.key}</Badge>
                  {roleLocked(r) && <Help text="仅超级管理员可将管理员/超级管理员角色授予身份组。" />}
                </label>
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
              <div className="flex items-center justify-between rounded-lg border border-destructive/30 p-3">
                <span className="text-sm">删除后组成员将失去该组授予的角色。</span>
                <Button variant="destructive" onClick={() => setConfirmDel(true)}>
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
