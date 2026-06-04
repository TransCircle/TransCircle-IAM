import { useAuth } from "@/auth/AuthProvider";
import { Badge, Card, CardContent, CardHeader, CardTitle, PageHeader } from "@/components/ui";

export function ProfilePage() {
  const { me } = useAuth();
  if (!me) return null;
  return (
    <div>
      <PageHeader title="个人资料" description="你的账户信息与系统权限。" />
      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>账户</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <Row label="用户名" value={me.user.username} />
            <Row label="显示名" value={me.user.display_name || "—"} />
            <Row label="邮箱" value={me.user.email || "—"} />
            <Row label="状态" value={me.user.status} />
            <Row
              label="MFA"
              value={`通行密钥 ${me.mfa.passkeys} · TOTP ${me.mfa.totp ? "已绑定" : "未绑定"} · 恢复码 ${me.mfa.recovery_codes}`}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>系统权限</CardTitle>
          </CardHeader>
          <CardContent>
            {me.permissions.length === 0 ? (
              <p className="text-sm text-muted-foreground">你没有任何系统管理权限。</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {me.permissions.map((p) => (
                  <Badge key={p} variant="muted">
                    {p}
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between border-b pb-2 last:border-0">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}
