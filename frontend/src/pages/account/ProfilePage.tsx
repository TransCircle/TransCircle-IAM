import * as React from "react";
import { useMutation } from "@tanstack/react-query";
import { useAuth } from "@/auth/AuthProvider";
import { api, errorMessage } from "@/lib/api";
import { Avatar, Badge, Button, Card, CardContent, CardHeader, CardTitle, Field, Input, PageHeader } from "@/components/ui";
import { useToast } from "@/components/Toast";

export function ProfilePage() {
  const { me, refresh } = useAuth();
  const { toast } = useToast();
  const [email, setEmail] = React.useState("");
  const [displayName, setDisplayName] = React.useState("");
  const [initialized, setInitialized] = React.useState(false);

  React.useEffect(() => {
    if (me && !initialized) {
      setEmail(me.user.email);
      setDisplayName(me.user.display_name);
      setInitialized(true);
    }
  }, [me, initialized]);

  const save = useMutation({
    mutationFn: () => api.patch("/api/v1/account/profile", { email, display_name: displayName }),
    onSuccess: () => {
      toast("资料已更新", "success");
      refresh();
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  const fileRef = React.useRef<HTMLInputElement>(null);
  const uploadAvatar = useMutation({
    mutationFn: (file: File) => {
      const fd = new FormData();
      fd.append("avatar", file);
      return api.post("/api/v1/account/avatar", fd);
    },
    onSuccess: () => {
      toast("头像已更新", "success");
      refresh();
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  function pickAvatar(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = ""; // allow re-selecting the same file
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

  if (!me) return null;

  return (
    <div>
      <PageHeader title="个人资料" description="查看与编辑你的账户信息。登录名不可修改，邮箱与显示名可自行编辑。" />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>编辑资料</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-4">
              <Avatar src={me.user.avatar_url} name={me.user.display_name || me.user.username} size="lg" />
              <div>
                <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp" className="hidden" onChange={pickAvatar} />
                <Button variant="outline" size="sm" type="button" onClick={() => fileRef.current?.click()} loading={uploadAvatar.isPending}>
                  更换头像
                </Button>
                <p className="mt-1.5 text-xs text-muted-foreground">支持 PNG/JPEG/WebP，最大 2MB。</p>
              </div>
            </div>
            <Field label="登录名" help="登录名由管理员创建后不可更改。">
              <Input value={me.user.username} disabled />
            </Field>
            <Field label="显示名">
              <Input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="你的显示名" />
            </Field>
            <Field label="邮箱" help="邮箱仅作展示用途，无需验证，可自行填写。">
              <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
            </Field>
            <Button onClick={() => save.mutate()} loading={save.isPending}>
              保存修改
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>账户与安全状态</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <Row label="状态" value={me.user.status === "active" ? "已启用" : "已禁用"} />
            <Row
              label="多因素"
              value={`通行密钥 ${me.mfa.passkeys} 个 · TOTP ${me.mfa.totp ? "已绑定" : "未绑定"} · 恢复码剩 ${me.mfa.recovery_codes} 个`}
            />
            <div className="pt-2">
              <div className="mb-2 text-muted-foreground">系统管理权限</div>
              {(me.permissions ?? []).length === 0 ? (
                <p className="text-muted-foreground">你没有任何系统管理权限。</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {(me.permissions ?? []).map((p) => (
                    <Badge key={p} variant="muted">
                      {p}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4 border-b pb-2 last:border-0">
      <span className="shrink-0 text-muted-foreground">{label}</span>
      <span className="text-right font-medium">{value}</span>
    </div>
  );
}
