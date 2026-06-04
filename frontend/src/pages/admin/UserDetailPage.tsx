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

  const invalidate = () => qc.invalidateQueries({ queryKey: ["assignments", id] });

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
    onError: (e) => toast(errorMessage(e), "error"),
  });

  if (!user.data) return null;
  const roleIds = new Set(assignments.data?.roles ?? []);
  const permIds = new Set(assignments.data?.permissions ?? []);
  const groupIds = new Set(assignments.data?.groups ?? []);

  return (
    <div>
      <PageHeader
        title={user.data.username}
        description={user.data.display_name || user.data.email || "用户详情"}
        action={
          canWrite && (
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={() => resetPwd.mutate()}>
                重置密码
              </Button>
              {hasPermission("iam.users.impersonate") && (
                <Button variant="outline" onClick={() => impersonate.mutate()}>
                  代登
                </Button>
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
          <CardHeader>
            <CardTitle>身份组成员</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-2 sm:grid-cols-2">
            {(groups.data ?? []).map((g) => (
              <label key={g.id} className="flex items-center gap-2.5 rounded-lg border p-2.5 text-sm">
                <Checkbox
                  checked={groupIds.has(g.id)}
                  disabled={!canWrite}
                  onCheckedChange={async (checked) => {
                    try {
                      if (checked) await api.post(`/api/v1/admin/users/${id}/groups`, { id: g.id });
                      else await api.delete(`/api/v1/admin/users/${id}/groups/${g.id}`);
                      invalidate();
                    } catch (e) {
                      toast(errorMessage(e), "error");
                    }
                  }}
                />
                <span className="font-medium">{g.display_name}</span>
                <span className="text-xs text-muted-foreground">{g.key}</span>
              </label>
            ))}
            {(groups.data ?? []).length === 0 && <p className="text-sm text-muted-foreground">暂无身份组。</p>}
          </CardContent>
        </Card>

        <AppScopedAssignments
          userId={id}
          apps={apps.data ?? []}
          roleIds={roleIds}
          permIds={permIds}
          canWrite={canWrite}
          onChange={invalidate}
          onError={(e) => toast(errorMessage(e), "error")}
        />
      </div>

      <Dialog
        open={!!resetResult}
        onClose={() => setResetResult(null)}
        title="密码已重置"
        footer={<Button onClick={() => setResetResult(null)}>完成</Button>}
      >
        <p className="text-sm text-muted-foreground">新的临时密码（用户下次登录须改密）：</p>
        <div className="mt-3 rounded-lg border bg-muted/40 p-3 font-mono text-sm">{resetResult}</div>
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
  onError,
}: {
  userId: string;
  apps: Application[];
  roleIds: Set<string>;
  permIds: Set<string>;
  canWrite: boolean;
  onChange: () => void;
  onError: (e: unknown) => void;
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

  async function toggle(fn: () => Promise<unknown>) {
    try {
      await fn();
      onChange();
    } catch (e) {
      onError(e);
    }
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-3">
        <CardTitle>按应用直接授权</CardTitle>
        <Select
          value={appId}
          onValueChange={setAppId}
          className="max-w-[240px]"
          options={apps.map((a) => ({ value: a.id, label: a.display_name }))}
        />
      </CardHeader>
      <CardContent className="grid gap-6 md:grid-cols-2">
        <div>
          <h4 className="mb-2 text-sm font-medium">直接角色</h4>
          <div className="space-y-2">
            {(roles.data ?? []).map((r) => (
              <label key={r.id} className="flex items-center gap-2.5 text-sm">
                <Checkbox
                  checked={roleIds.has(r.id)}
                  disabled={!canWrite}
                  onCheckedChange={(checked) =>
                    toggle(() =>
                      checked
                        ? api.post(`/api/v1/admin/users/${userId}/roles`, { id: r.id })
                        : api.delete(`/api/v1/admin/users/${userId}/roles/${r.id}`)
                    )
                  }
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
              <label key={p.id} className="flex items-center gap-2.5 text-sm">
                <Checkbox
                  checked={permIds.has(p.id)}
                  disabled={!canWrite}
                  onCheckedChange={(checked) =>
                    toggle(() =>
                      checked
                        ? api.post(`/api/v1/admin/users/${userId}/permissions`, { id: p.id })
                        : api.delete(`/api/v1/admin/users/${userId}/permissions/${p.id}`)
                    )
                  }
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
