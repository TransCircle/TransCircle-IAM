import * as React from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Checkbox, PageHeader, Select } from "@/components/ui";
import { Dialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { Application, Group, Permission, Role, User } from "@/lib/types";

export function UserDetailPage() {
  const { id = "" } = useParams();
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.users.write");
  const [resetResult, setResetResult] = React.useState<string | null>(null);

  const user = useQuery<User>({
    queryKey: ["user", id],
    queryFn: async () => (await api.get(`/api/v1/admin/users/${id}`)).data,
  });
  const assignments = useQuery<{ roles: string[]; permissions: string[]; groups: string[] }>({
    queryKey: ["assignments", id],
    queryFn: async () => (await api.get(`/api/v1/admin/users/${id}/assignments`)).data,
  });
  const apps = useQuery<Application[]>({
    queryKey: ["applications"],
    queryFn: async () => (await api.get("/api/v1/admin/applications")).data.applications ?? [],
  });
  const groups = useQuery<Group[]>({
    queryKey: ["groups"],
    queryFn: async () => (await api.get("/api/v1/admin/groups")).data.groups ?? [],
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["assignments", id] });
  };

  const resetPwd = useMutation({
    mutationFn: () => api.post(`/api/v1/admin/users/${id}/reset-password`),
    onSuccess: (r) => setResetResult(r.data.temp_password),
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const impersonate = useMutation({
    mutationFn: () => api.post(`/api/v1/admin/users/${id}/impersonate`),
    onSuccess: () => {
      toast("已切换为代登会话", "success");
      window.location.href = "/account";
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const toggleStatus = useMutation({
    mutationFn: (status: string) =>
      api.patch(`/api/v1/admin/users/${id}`, {
        email: user.data?.email ?? "",
        display_name: user.data?.display_name ?? "",
        status,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["user", id] }),
  });

  if (!user.data) return null;
  const roleIds = new Set(assignments.data?.roles ?? []);
  const permIds = new Set(assignments.data?.permissions ?? []);
  const groupIds = new Set(assignments.data?.groups ?? []);

  return (
    <div>
      <PageHeader
        title={user.data.username}
        description={user.data.display_name || user.data.email}
        action={
          canWrite && (
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => resetPwd.mutate()}>重置密码</Button>
              {hasPermission("iam.users.impersonate") && (
                <Button variant="outline" onClick={() => impersonate.mutate()}>代登</Button>
              )}
              <Button
                variant={user.data.status === "active" ? "destructive" : "default"}
                onClick={() => toggleStatus.mutate(user.data!.status === "active" ? "disabled" : "active")}
              >
                {user.data.status === "active" ? "禁用" : "启用"}
              </Button>
            </div>
          )
        }
      />

      <div className="grid gap-6">
        <Card>
          <CardHeader><CardTitle>身份组成员</CardTitle></CardHeader>
          <CardContent className="grid gap-2 sm:grid-cols-2">
            {(groups.data ?? []).map((g) => (
              <label key={g.id} className="flex items-center gap-2 rounded-md border p-2 text-sm">
                <Checkbox
                  checked={groupIds.has(g.id)}
                  disabled={!canWrite}
                  onChange={async (e) => {
                    if (e.target.checked) await api.post(`/api/v1/admin/users/${id}/groups`, { id: g.id });
                    else await api.delete(`/api/v1/admin/users/${id}/groups/${g.id}`);
                    invalidate();
                  }}
                />
                <span className="font-medium">{g.display_name}</span>
                <span className="text-xs text-muted-foreground">{g.key}</span>
              </label>
            ))}
          </CardContent>
        </Card>

        <AppScopedAssignments
          userId={id}
          apps={apps.data ?? []}
          roleIds={roleIds}
          permIds={permIds}
          canWrite={canWrite}
          onChange={invalidate}
        />
      </div>

      <Dialog open={!!resetResult} onClose={() => setResetResult(null)} title="密码已重置" footer={<Button onClick={() => setResetResult(null)}>完成</Button>}>
        <p className="text-sm text-muted-foreground">新的临时密码（用户下次登录须改密）：</p>
        <div className="mt-3 rounded-md border bg-muted/40 p-3 font-mono text-sm">{resetResult}</div>
      </Dialog>
    </div>
  );
}

function AppScopedAssignments({
  userId,
  apps,
  roleIds,
  permIds,
  canWrite,
  onChange,
}: {
  userId: string;
  apps: Application[];
  roleIds: Set<string>;
  permIds: Set<string>;
  canWrite: boolean;
  onChange: () => void;
}) {
  const [appId, setAppId] = React.useState("");
  React.useEffect(() => {
    if (!appId && apps.length) setAppId(apps[0].id);
  }, [apps, appId]);

  const roles = useQuery<Role[]>({
    queryKey: ["app-roles", appId],
    queryFn: async () => (await api.get(`/api/v1/admin/applications/${appId}/roles`)).data.roles ?? [],
    enabled: !!appId,
  });
  const perms = useQuery<Permission[]>({
    queryKey: ["app-perms", appId],
    queryFn: async () => (await api.get(`/api/v1/admin/applications/${appId}/permissions`)).data.permissions ?? [],
    enabled: !!appId,
  });

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>按应用直接授权</CardTitle>
        <Select value={appId} onChange={(e) => setAppId(e.target.value)} className="max-w-[220px]">
          {apps.map((a) => (
            <option key={a.id} value={a.id}>
              {a.display_name}
            </option>
          ))}
        </Select>
      </CardHeader>
      <CardContent className="grid gap-6 md:grid-cols-2">
        <div>
          <h4 className="mb-2 text-sm font-medium">直接角色</h4>
          <div className="space-y-2">
            {(roles.data ?? []).map((r) => (
              <label key={r.id} className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={roleIds.has(r.id)}
                  disabled={!canWrite}
                  onChange={async (e) => {
                    if (e.target.checked) await api.post(`/api/v1/admin/users/${userId}/roles`, { id: r.id });
                    else await api.delete(`/api/v1/admin/users/${userId}/roles/${r.id}`);
                    onChange();
                  }}
                />
                {r.display_name} <Badge variant="muted">{r.key}</Badge>
              </label>
            ))}
            {(roles.data ?? []).length === 0 && <p className="text-xs text-muted-foreground">该应用暂无角色。</p>}
          </div>
        </div>
        <div>
          <h4 className="mb-2 text-sm font-medium">直接权限</h4>
          <div className="space-y-2">
            {(perms.data ?? []).map((p) => (
              <label key={p.id} className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={permIds.has(p.id)}
                  disabled={!canWrite}
                  onChange={async (e) => {
                    if (e.target.checked) await api.post(`/api/v1/admin/users/${userId}/permissions`, { id: p.id });
                    else await api.delete(`/api/v1/admin/users/${userId}/permissions/${p.id}`);
                    onChange();
                  }}
                />
                {p.display_name} <Badge variant="muted">{p.key}</Badge>
              </label>
            ))}
            {(perms.data ?? []).length === 0 && <p className="text-xs text-muted-foreground">该应用暂无权限。</p>}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
