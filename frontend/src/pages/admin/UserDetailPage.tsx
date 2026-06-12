import * as React from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, Save } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Avatar, Badge, Button, Card, CardContent, CardHeader, CardTitle, CheckRow, CopyButton, Field, Input, PageHeader, Select, Spinner, Switch, Tabs } from "@/components/ui";
import { Dialog, ConfirmDialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import { ADMIN_ROLE_ID, SUPER_ADMIN_ROLE_ID, type Application, type Group, type Permission, type Role, type User } from "@/lib/types";

type Assignments = { roles: string[]; permissions: string[]; groups: string[] };

// useAssignmentToggle wires an optimistic add/remove of one assignment id into the
// ["assignments", userId] cache so the checkmark flips instantly; it rolls back on
// error and reconciles on settle.
function useAssignmentToggle(
  qc: ReturnType<typeof useQueryClient>,
  userId: string,
  toast: (message: string, kind?: "success" | "error" | "info") => void,
  kind: keyof Assignments,
  endpoint: string
) {
  return useMutation({
    mutationFn: (v: { targetId: string; checked: boolean }) =>
      v.checked ? api.post(endpoint, { id: v.targetId }) : api.delete(`${endpoint}/${v.targetId}`),
    onMutate: async (v: { targetId: string; checked: boolean }) => {
      await qc.cancelQueries({ queryKey: ["assignments", userId] });
      const prev = qc.getQueryData<Assignments>(["assignments", userId]);
      qc.setQueryData<Assignments>(["assignments", userId], (old) => {
        if (!old) return old;
        const set = new Set(old[kind]);
        if (v.checked) set.add(v.targetId);
        else set.delete(v.targetId);
        return { ...old, [kind]: [...set] };
      });
      return { prev };
    },
    onError: (e, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(["assignments", userId], ctx.prev);
      toast(errorMessage(e), "error");
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["assignments", userId] }),
  });
}

export function UserDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { me, hasPermission, isSuperAdmin } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.users.write");
  const [resetOpen, setResetOpen] = React.useState(false);
  const [confirmDisable, setConfirmDisable] = React.useState(false);
  const [basic, setBasic] = React.useState({ email: "", display_name: "", force_password_change: false, must_enroll_mfa: false });
  const fileRef = React.useRef<HTMLInputElement>(null);

  const user = useQuery<User>({
    queryKey: ["user", id],
    queryFn: async () => (await api.get(`/api/v1/admin/users/${id}`)).data,
  });
  const assignments = useQuery<Assignments>({
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

  const directRoles = new Set(assignments.data?.roles ?? []);
  const targetIsSuper = directRoles.has(SUPER_ADMIN_ROLE_ID);
  const targetIsAdmin = directRoles.has(ADMIN_ROLE_ID);
  const isSelf = me?.user.id === id;
  // Granular gates (feature 7): a super-admin TARGET keeps basic info / password
  // reset / disable locked, but its group membership and non-system app role &
  // permission assignments stay editable — including by oneself (the backend
  // permits self-management and locks the system app separately), so a lone
  // super admin can still grant themselves other applications' permissions.
  const canEditBasic = canWrite && !isSelf && !targetIsSuper;
  const canManageMembership = canWrite;
  const canManageAppAssign = canWrite;

  const groupToggle = useAssignmentToggle(qc, id, toast, "groups", `/api/v1/admin/users/${id}/groups`);
  const roleToggle = useAssignmentToggle(qc, id, toast, "roles", `/api/v1/admin/users/${id}/roles`);
  const permToggle = useAssignmentToggle(qc, id, toast, "permissions", `/api/v1/admin/users/${id}/permissions`);

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
  const uploadAvatar = useMutation({
    mutationFn: (file: File) => {
      const fd = new FormData();
      fd.append("avatar", file);
      return api.post(`/api/v1/admin/users/${id}/avatar`, fd);
    },
    onSuccess: () => {
      toast("头像已更新", "success");
      qc.invalidateQueries({ queryKey: ["user", id] });
      qc.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  function pickAvatar(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
      toast("仅支持 PNG/JPEG/WebP 图片", "error");
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      toast("头像不能超过 2MB", "error");
      return;
    }
    uploadAvatar.mutate(file);
  }

  if (user.isError) {
    return (
      <div className="bracket-frame rounded-lg border border-dashed bg-card/50 p-10 text-center text-sm text-muted-foreground">
        用户不存在或加载失败。
        <div className="mt-3">
          <Button variant="outline" size="sm" onClick={() => navigate("/admin/users")}>
            返回用户列表
          </Button>
        </div>
      </div>
    );
  }
  if (!user.data) {
    return (
      <div className="flex justify-center p-10">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }
  // A failed assignments query must NOT render everything as "unassigned" —
  // an admin could be misled into re-granting or mis-reading a super-admin.
  if (assignments.isError) {
    return (
      <div className="bracket-frame rounded-lg border border-dashed bg-card/50 p-10 text-center text-sm text-muted-foreground">
        无法加载该用户的授权数据，页面已停止渲染以免误导操作。
        <div className="mt-3">
          <Button variant="outline" size="sm" onClick={() => assignments.refetch()}>
            重试
          </Button>
        </div>
      </div>
    );
  }
  const permIds = new Set(assignments.data?.permissions ?? []);
  const groupIds = new Set(assignments.data?.groups ?? []);

  return (
    <div>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
        <Avatar src={user.data.avatar_url} name={user.data.display_name || user.data.username} size="lg" />
        <div className="min-w-0 flex-1">
          <PageHeader
            title={user.data.username}
            description={user.data.display_name || user.data.email || "用户详情"}
            action={
              <div className="flex flex-wrap gap-2">
                {targetIsSuper && <Badge variant="warning">超级管理员</Badge>}
                {targetIsAdmin && !targetIsSuper && <Badge variant="muted">管理员</Badge>}
                {canEditBasic && (
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
        </div>
      </div>

      {(isSelf || targetIsSuper) && canWrite && (
        <div className="mb-5 flex items-start gap-2.5 rounded-xl border bg-accent/40 p-3 text-sm text-accent-foreground">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            {isSelf
              ? "你不能在此重置自己的密码或禁用自己,请前往「个人中心」。"
              : "超级管理员的密码与账户状态不可在此修改,但可调整其身份组与其它应用的授权。"}
          </span>
        </div>
      )}

      <div className="grid gap-6">
        {canEditBasic && (
          <Card>
            <CardHeader>
              <CardTitle>基本信息</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-3">
                <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp" className="hidden" onChange={pickAvatar} />
                <Button variant="outline" size="sm" type="button" onClick={() => fileRef.current?.click()} loading={uploadAvatar.isPending}>
                  更换头像
                </Button>
                <p className="text-xs text-muted-foreground">支持 PNG/JPEG/WebP，最大 2MB。</p>
              </div>
              <Field label="用户名（不可更改）">
                <Input value={user.data.username} disabled />
              </Field>
              <Field label="显示名">
                <Input value={basic.display_name} onChange={(e) => setBasic({ ...basic, display_name: e.target.value })} />
              </Field>
              <Field label="邮箱">
                <Input value={basic.email} type="email" onChange={(e) => setBasic({ ...basic, email: e.target.value })} />
              </Field>
              <div className="flex items-center justify-between gap-3 rounded-lg border p-3 text-sm">
                <span>首次登录强制改密</span>
                <Switch checked={basic.force_password_change} onCheckedChange={(v) => setBasic({ ...basic, force_password_change: v })} />
              </div>
              <div className="flex items-center justify-between gap-3 rounded-lg border p-3 text-sm">
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
              <CheckRow
                key={g.id}
                checked={groupIds.has(g.id)}
                disabled={!canManageMembership}
                onToggle={(checked) => groupToggle.mutate({ targetId: g.id, checked })}
              >
                <span className="font-medium">{g.display_name}</span>
                <span className="text-xs text-muted-foreground">{g.key}</span>
              </CheckRow>
            ))}
            {(groups.data ?? []).length === 0 && <p className="text-sm text-muted-foreground">暂无身份组。</p>}
          </CardContent>
        </Card>

        <AppScopedAssignments
          apps={apps.data ?? []}
          roleIds={directRoles}
          permIds={permIds}
          canWrite={canManageAppAssign}
          isSuperAdmin={isSuperAdmin}
          targetIsSuper={targetIsSuper}
          onToggleRole={(targetId, checked) => roleToggle.mutate({ targetId, checked })}
          onTogglePerm={(targetId, checked) => permToggle.mutate({ targetId, checked })}
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
      <Dialog open={open} onClose={onClose} title="临时密码已生成" lockClose footer={<Button onClick={onClose}>我已保存，完成</Button>}>
        <p className="text-sm text-muted-foreground">
          请将以下一次性临时密码线下告知 {username}，其首次登录须改密。<b>关闭后无法再次查看。</b>
        </p>
        <div className="mt-3 flex items-center justify-between gap-2 rounded-md border bg-muted/40 p-3 font-mono text-sm">
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
  apps,
  roleIds,
  permIds,
  canWrite,
  isSuperAdmin,
  targetIsSuper,
  onToggleRole,
  onTogglePerm,
}: {
  apps: Application[];
  roleIds: Set<string>;
  permIds: Set<string>;
  canWrite: boolean;
  isSuperAdmin: boolean;
  targetIsSuper: boolean;
  onToggleRole: (targetId: string, checked: boolean) => void;
  onTogglePerm: (targetId: string, checked: boolean) => void;
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

  // The IAM-self (system) application's role + permission grants stay locked for a
  // super-admin target (feature 7); the backend rejects direct system permission
  // grants on super-admin targets too. Harmless for a super admin, who already
  // holds every system permission via their role.
  const currentApp = apps.find((a) => a.id === appId);
  const sysLocked = !!currentApp?.is_system && targetIsSuper;

  function roleLocked(r: Role) {
    // super_admin can never be granted from the frontend (backend refuses it
    // too); the admin role stays restricted to super-admin actors.
    if (r.id === SUPER_ADMIN_ROLE_ID) return true;
    return r.id === ADMIN_ROLE_ID && !isSuperAdmin;
  }

  function roleLockHint(r: Role) {
    if (r.id === SUPER_ADMIN_ROLE_ID) return "超级管理员角色不可在前端授予。";
    if (sysLocked) return "IAM 系统应用的角色与权限不可在此修改。";
    return "仅超级管理员可授予/移除管理员角色。";
  }

  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-center justify-between gap-3">
        <CardTitle>按应用直接授权</CardTitle>
        <Select value={appId} onValueChange={setAppId} className="w-full sm:max-w-[240px]" options={apps.map((a) => ({ value: a.id, label: a.display_name }))} />
      </CardHeader>
      <CardContent className="grid gap-6 md:grid-cols-2">
        <div>
          <h4 className="mb-2 text-sm font-medium">直接角色</h4>
          <div className="space-y-2">
            {(roles.data ?? []).map((r) => (
              <CheckRow
                key={r.id}
                checked={roleIds.has(r.id)}
                disabled={!canWrite}
                locked={roleLocked(r) || sysLocked}
                lockedHint={roleLockHint(r)}
                onToggle={(checked) => onToggleRole(r.id, checked)}
              >
                {r.display_name} <Badge variant="muted">{r.key}</Badge>
              </CheckRow>
            ))}
            {(roles.data ?? []).length === 0 && <p className="text-xs text-muted-foreground">该应用暂无角色。</p>}
          </div>
        </div>
        <div>
          <h4 className="mb-2 text-sm font-medium">直接权限</h4>
          <div className="space-y-2">
            {(perms.data ?? []).map((p) => (
              <CheckRow
                key={p.id}
                checked={permIds.has(p.id)}
                disabled={!canWrite}
                locked={sysLocked}
                lockedHint="IAM 系统应用的角色与权限不可在此修改。"
                onToggle={(checked) => onTogglePerm(p.id, checked)}
              >
                {p.display_name} <Badge variant="muted">{p.key}</Badge>
              </CheckRow>
            ))}
            {(perms.data ?? []).length === 0 && <p className="text-xs text-muted-foreground">该应用暂无权限。</p>}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
