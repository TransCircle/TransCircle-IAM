import * as React from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Search } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Avatar, Badge, Button, CopyButton, Field, Input, PageHeader } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { Dialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { User } from "@/lib/types";
import { formatDate } from "@/lib/utils";

export function UsersPage() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [search, setSearch] = React.useState("");
  const [open, setOpen] = React.useState(false);
  const [created, setCreated] = React.useState<{ username: string; password: string } | null>(null);

  const { data, isLoading } = useQuery<{ users: User[]; total: number }>({
    queryKey: ["users", search],
    queryFn: async () => (await api.get(`/api/v1/admin/users?search=${encodeURIComponent(search)}&limit=50`)).data,
  });

  const create = useMutation({
    mutationFn: (body: { username: string; email: string; display_name: string }) =>
      api.post("/api/v1/admin/users", body),
    onSuccess: (res) => {
      setOpen(false);
      setCreated({ username: res.data.user.username, password: res.data.temp_password });
      qc.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <div>
      <PageHeader
        title="用户"
        description="管理内部成员账户。"
        action={
          hasPermission("iam.users.write") && (
            <Button onClick={() => setOpen(true)}>
              <Plus className="h-4 w-4" /> 新建用户
            </Button>
          )
        }
      />
      <div className="relative mb-4 max-w-sm">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input className="pl-9" placeholder="搜索用户名或显示名" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      <DataTable<User>
        loading={isLoading}
        rows={data?.users}
        rowKey={(u) => u.id}
        columns={[
          {
            header: "用户",
            cell: (u) => (
              <Link to={`/admin/users/${u.id}`} className="flex items-center gap-2.5 font-medium text-primary hover:underline">
                <Avatar src={u.avatar_url} name={u.display_name || u.username} size="sm" />
                {u.username}
              </Link>
            ),
          },
          { header: "显示名", cell: (u) => u.display_name || "—" },
          { header: "邮箱", cell: (u) => u.email || "—" },
          {
            header: "状态",
            cell: (u) =>
              u.status === "disabled" ? (
                <Badge variant="muted">已禁用</Badge>
              ) : u.force_password_change ? (
                <Badge variant="warning">待激活</Badge>
              ) : (
                <Badge variant="success">正常</Badge>
              ),
          },
          { header: "创建时间", cell: (u) => formatDate(u.created_at) },
        ]}
      />

      <CreateUserDialog open={open} onClose={() => setOpen(false)} onSubmit={(b) => create.mutate(b)} loading={create.isPending} />

      <Dialog
        open={!!created}
        onClose={() => setCreated(null)}
        title="用户已创建"
        footer={<Button onClick={() => setCreated(null)}>完成</Button>}
      >
        <p className="text-sm text-muted-foreground">请将以下临时密码线下告知成员，首次登录将强制改密并绑定 MFA。</p>
        <div className="mt-3 space-y-2 rounded-lg border bg-muted/40 p-3 font-mono text-sm">
          <div>用户名：{created?.username}</div>
          <div className="flex items-center justify-between gap-2">
            <span>临时密码：{created?.password}</span>
            {created && <CopyButton value={created.password} />}
          </div>
        </div>
      </Dialog>
    </div>
  );
}

function CreateUserDialog({
  open,
  onClose,
  onSubmit,
  loading,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (b: { username: string; email: string; display_name: string }) => void;
  loading: boolean;
}) {
  const { toast } = useToast();
  const [username, setUsername] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [displayName, setDisplayName] = React.useState("");
  React.useEffect(() => {
    if (!open) {
      setUsername("");
      setEmail("");
      setDisplayName("");
    }
  }, [open]);
  function submit() {
    if (!username.trim()) {
      toast("用户名不能为空", "error");
      return;
    }
    onSubmit({ username: username.trim(), email, display_name: displayName });
  }
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="新建用户"
      onSubmit={submit}
      footer={
        <>
          <Button variant="outline" type="button" onClick={onClose}>取消</Button>
          <Button type="submit" loading={loading}>创建</Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="用户名">
          <Input value={username} autoFocus autoComplete="off" onChange={(e) => setUsername(e.target.value)} />
        </Field>
        <Field label="显示名">
          <Input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </Field>
        <Field label="邮箱">
          <Input value={email} type="email" autoComplete="off" onChange={(e) => setEmail(e.target.value)} />
        </Field>
      </div>
    </Dialog>
  );
}
