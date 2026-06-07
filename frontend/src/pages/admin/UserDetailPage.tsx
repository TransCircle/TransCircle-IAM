import * as React from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Checkbox, CopyButton, Field, Help, Input, PageHeader, Select, Switch, Tabs } from "@/components/ui";
import { Dialog, ConfirmDialog } from "@/components/Dialog";
import { Save } from "lucide-react";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import { ADMIN_ROLE_ID, SUPER_ADMIN_ROLE_ID, type Application, type Group, type Permission, type Role, type User } from "@/lib/types";

export function UserDetailPage() {
  const { id = "" } = useParams();
  const { me, hasPermission, isSuperAdmin } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.users.write");
  const [resetOpen, setResetOpen] = React.useState(false);
  const [confirmDisable, setConfirmDisable] = React.useState(false);
  const [basic, setBasic] = React.useState({ email: "", display_name: "", force_password_change: false, must_enroll_mfa: false });

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

  React.useEffect(() => {
    if (user.data) {
      setBasic({
        email: user.data.email,
        display_name: user.data.display_name,
        force_password_change: user.data.force_password_change,
        must_enroll_mfa: user.data.must_enroll_mfa,
      });
    }
  }, [user.data]);

  const invalidate = () => qc.invalidateQueries({ queryKey: ["assignments", id] });
  const directRoles = new Set(assignments.data?.roles ?? []);
  const targetIsSuper = directRoles.has(SUPER_ADMIN_ROLE_ID);
  const targetIsAdmin = directRoles.has(ADMIN_ROLE_ID);
  const isSelf = me?.user.id === id;
  // Per the backend rule, these actions are not allowed on a super-admin or on
  // oneself; hide them so the UI matches what the server will accept.
  const canManage = canWrite && !isSelf && !targetIsSuper;

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
      api.patch(`/api/v1/admin/users/${id}`, { email: user.data?.email ?? "", display_name: user.data?.display_name ?? "", status }),
    onSuccess: () => {
      setConfirmDisable(false);
      qc.invalidateQueries({ queryKey: ["user", id] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const saveBasic = useMutation({
    mutationFn: () => api.patch(`/api/v1/admin/users/${id}`, { ...basic, status: user.data!.status }),
    onSuccess: () => {
      toast("已保存", "success");
      qc.invalidateQueries({ queryKey: ["user", id] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  if (!user.data) return null;
  const permIds = new Set(assignments.data?.permissions ?? []);
  const groupIds = new Set(assignments.data?.groups ?? []);

  return (
    <div>
      <PageHeader
        title={user.data.username}
        description={user.data.display_name || user.data.email || "用户详情"}
        action={
          <div className="flex flex-wrap gap-2">
            {targetIsSuper && <Badge variant="warning">超级管理员</Badge>}
            {targetIsAdmin && !targetIsSuper && <Badge variant="muted">管理员</Badge>}
            {canManage && (
              <>
                <Button variant="outline" onClick={() => setResetOpen(true)}>
                  重置密码
                </Button>
                {hasPermission("iam.users.impersonate") && (
                  <Button variant="outline" onClick={() => impersonate.mutate()}>
                    代登
                  </Button>
                )}
                <Button
                  variant={user.data.status === "active" ? "destructive" : "default"}
                  onClick={() => (user.data!.status === "active" ? setConfirmDisable(true) : toggleStatus.mutate("active"))}
                >
                  {user.data.status === "active" ? "禁用账户" : "启用账户"}
                </Button>
              </>
            )}
          </div>
        }
      />

      {(isSelf || targetIsSuper) && canWrite && (
        <div className="mb-5 flex items-start gap-2.5 rounded-xl border bg-accent/40 p-3 text-sm text-accent-foreground">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{isSelf ? "你不能在此重置自己的密码或禁用自己,请前往「个人中心」。" : "超级管理员的密码与状态不可在此修改。"}</span>
        </div>
      )}

      <div className="grid gap-6">
        {canManage && (
          <Card>
            <CardHeader>
              <CardTitle>基本信息</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Field label="用户名（不可更改）">
                <Input value={user.data.username} disabled />
              </Field>
              <Field label="显示名">
                <Input value={basic.display_name} onChange={(e) => setBasic({ ...basic, display_name: e.target.value })} />
              </Field>
              <Field label="邮箱">
                <Input value={basic.email} type="email" onChange={(e) => setBasic({ ...basic, email: e.target.value })} />
              </Field>
              <div className="flex items-center justify-between rounded-lg border p-3 text-sm">
                <span>首次登录强制改密</span>
                <Switch checked={basic.force_password_change} onCheckedChange={(v) => setBasic({ ...basic, force_password_change: v })} />
              </div>
              <div className="flex items-center justify-between rounded-lg border p-3 text-sm">
                <span>要求绑定多因素认证 (MFA)</span>
                <Switch checked={basic.must_enroll_mfa} onCheckedChange={(v) => setBasic({ ...basic, must_enroll_mfa: v })} />
              </div>
              <div className="flex justify-end">
                <Button onClick={() => saveBasic.mutate()} loading={saveBasic.isPending}>
                  <Save className="h-4 w-4" /> 保存
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle>身份组成员</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-2 sm:grid-cols-2">
            {(groups.data ?? []).map((g) => (
              <label key={g.id} className="flex items-center gap-2.5 rounded-lg border p-2.5 text-sm">
                <Checkbox
                  checked={groupIds.has(g.id)}
                  disabled={!canManage}
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
          roleIds={directRoles}
          permIds={permIds}
          canWrite={canManage}
          isSuperAdmin={isSuperAdmin}
          onChange={invalidate}
          onError={(e) => toast(errorMessage(e), "error")}
        />
      </div>

      <ResetPasswordDialog open={resetOpen} onClose={() => setResetOpen(false)} userId={id} username={user.data.username} />

      <ConfirmDialog
        open={confirmDisable}
        onClose={() => setConfirmDisable(false)}
        onConfirm={() => toggleStatus.mutate("disabled")}
        title={`禁用「${user.data.username}」?`}
        description="该用户将立即被登出并无法再登录,直到重新启用。"
        confirmLabel="禁用"
        destructive
        loading={toggleStatus.isPending}
      />
    </div>
  );
}

function ResetPasswordDialog({ open, onClose, userId, username }: { open: boolean; onClose: () => void; userId: string; username: string }) {
  const { toast } = useToast();
  const [mode, setMode] = React.useState("temp");
  const [password, setPassword] = React.useState("");
  const [result, setResult] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!open) {
      setMode("temp");
      setPassword("");
      setResult(null);
    }
  }, [open]);

  const reset = useMutation({
    mutationFn: () => api.post(`/api/v1/admin/users/${userId}/reset-password`, { mode, password: mode === "manual" ? password : undefined }),
    onSuccess: (r) => {
      if (r.data.temp_password) setResult(r.data.temp_password);
      else {
        toast("密码已更新", "success");
        onClose();
      }
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  if (result) {
    return (
      <Dialog open={open} onClose={onClose} title="临时密码已生成" footer={<Button onClick={onClose}>完成</Button>}>
        <p className="text-sm text-muted-foreground">请将以下一次性临时密码线下告知 {username},其首次登录须改密。</p>
        <div className="mt-3 flex items-center justify-between gap-2 rounded-lg border bg-muted/40 p-3 font-mono text-sm">
          <span className="break-all">{result}</span>
          <CopyButton value={result} />
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`重置「${username}」的密码`}
      onSubmit={() => reset.mutate()}
      footer={
        <>
          <Button variant="outline" type="button" onClick={onClose}>取消</Button>
          <Button variant="destructive" type="submit" loading={reset.isPending}>确认重置</Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="flex items-start gap-2.5 rounded-lg bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-400">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <span>重置会立即吊销该用户所有登录会话。此操作需要二次验证。</span>
        </div>
        <Tabs
          value={mode}
          onValueChange={setMode}
          tabs={[{ value: "temp", label: "生成临时密码" }, { value: "manual", label: "手动设置" }]}
        />
        {mode === "temp" ? (
          <p className="text-sm text-muted-foreground">系统生成一次性临时密码并展示给你;该用户首次登录将被强制改密。</p>
        ) : (
          <Field label="新密码" help="直接设为该密码,用户登录后无需强制改密。至少 12 位。">
            <Input type="text" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="至少 12 个字符" />
          </Field>
        )}
      </div>
    </Dialog>
  );
}

function AppScopedAssignments({
  userId, apps, roleIds, permIds, canWrite, isSuperAdmin, onChange, onError,
}: {
  userId: string;
  apps: Application[];
  roleIds: Set<string>;
  permIds: Set<string>;
  canWrite: boolean;
  isSuperAdmin: boolean;
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

  function roleLocked(r: Role) {
    // Only super-admins may assign the built-in admin / super_admin roles.
    return (r.id === SUPER_ADMIN_ROLE_ID || r.id === ADMIN_ROLE_ID) && !isSuperAdmin;
  }

  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-center justify-between gap-3">
        <CardTitle>按应用直接授权</CardTitle>
        <Select value={appId} onValueChange={setAppId} className="w-full max-w-[240px]" options={apps.map((a) => ({ value: a.id, label: a.display_name }))} />
      </CardHeader>
      <CardContent className="grid gap-6 md:grid-cols-2">
        <div>
          <h4 className="mb-2 text-sm font-medium">直接角色</h4>
          <div className="space-y-2">
            {(roles.data ?? []).map((r) => (
              <label key={r.id} className="flex items-center gap-2.5 text-sm">
                <Checkbox
                  checked={roleIds.has(r.id)}
                  disabled={!canWrite || roleLocked(r)}
                  onCheckedChange={(checked) =>
                    toggle(() =>
                      checked
                        ? api.post(`/api/v1/admin/users/${userId}/roles`, { id: r.id })
                        : api.delete(`/api/v1/admin/users/${userId}/roles/${r.id}`)
                    )
                  }
                />
                {r.display_name} <Badge variant="muted">{r.key}</Badge>
                {roleLocked(r) && <Help text="仅超级管理员可授予管理员/超级管理员角色。" />}
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
