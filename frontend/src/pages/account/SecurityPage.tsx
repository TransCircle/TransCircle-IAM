import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Trash2 } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { api, errorMessage } from "@/lib/api";
import { registerPasskey } from "@/lib/webauthn";
import { useAuth } from "@/auth/AuthProvider";
import { Button, Card, CardContent, CardHeader, CardTitle, Field, Input, PageHeader } from "@/components/ui";
import { Dialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { formatDate } from "@/lib/utils";

interface Passkey {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

export function SecurityPage() {
  const { me, refresh } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [totpOpen, setTotpOpen] = React.useState(false);
  const [recovery, setRecovery] = React.useState<string[] | null>(null);

  const passkeys = useQuery<Passkey[]>({
    queryKey: ["passkeys"],
    queryFn: async () => (await api.get("/api/v1/account/passkeys")).data.passkeys ?? [],
  });

  const addPasskey = useMutation({
    mutationFn: () => registerPasskey("通行密钥"),
    onSuccess: () => {
      toast("通行密钥已添加", "success");
      qc.invalidateQueries({ queryKey: ["passkeys"] });
      refresh();
    },
    onError: (e) => toast(errorMessage(e) || "已取消", "error"),
  });

  const delPasskey = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/account/passkeys/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["passkeys"] });
      refresh();
    },
  });

  const regenRecovery = useMutation({
    mutationFn: async () => (await api.post("/api/v1/auth/recovery/generate")).data.codes as string[],
    onSuccess: (codes) => {
      setRecovery(codes);
      refresh();
    },
  });

  return (
    <div>
      <PageHeader title="安全与多因素" description="修改密码,管理你的通行密钥、TOTP 与恢复码。" />
      <div className="grid gap-6">
        <ChangePasswordCard />

        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>通行密钥</CardTitle>
            <Button size="sm" onClick={() => addPasskey.mutate()} loading={addPasskey.isPending}>
              <Fingerprint className="h-4 w-4" /> 添加
            </Button>
          </CardHeader>
          <CardContent className="space-y-2">
            {(passkeys.data ?? []).length === 0 && <p className="text-sm text-muted-foreground">尚未注册通行密钥。</p>}
            {(passkeys.data ?? []).map((pk) => (
              <div key={pk.id} className="flex items-center justify-between rounded-md border p-3 text-sm">
                <div>
                  <div className="font-medium">{pk.name}</div>
                  <div className="text-xs text-muted-foreground">
                    添加于 {formatDate(pk.created_at)} · 最近使用 {formatDate(pk.last_used_at)}
                  </div>
                </div>
                <Button size="icon" variant="ghost" onClick={() => delPasskey.mutate(pk.id)}>
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>动态口令 (TOTP)</CardTitle>
            {me?.mfa.totp ? (
              <Button
                size="sm"
                variant="outline"
                onClick={async () => {
                  await api.delete("/api/v1/account/totp");
                  toast("已移除 TOTP", "success");
                  refresh();
                }}
              >
                移除
              </Button>
            ) : (
              <Button size="sm" onClick={() => setTotpOpen(true)}>
                绑定
              </Button>
            )}
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{me?.mfa.totp ? "已绑定 TOTP。" : "未绑定 TOTP。"}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>恢复码</CardTitle>
            <Button size="sm" variant="outline" onClick={() => regenRecovery.mutate()} loading={regenRecovery.isPending}>
              重新生成
            </Button>
          </CardHeader>
          <CardContent>
            {recovery ? (
              <div className="grid grid-cols-2 gap-2 rounded-md border bg-muted/40 p-3 font-mono text-sm">
                {recovery.map((c) => (
                  <span key={c}>{c}</span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">剩余 {me?.mfa.recovery_codes ?? 0} 个未使用恢复码。重新生成将作废旧码。</p>
            )}
          </CardContent>
        </Card>
      </div>

      <TOTPDialog open={totpOpen} onClose={() => setTotpOpen(false)} onDone={() => { setTotpOpen(false); refresh(); }} />
    </div>
  );
}

function TOTPDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const { toast } = useToast();
  const [otpauth, setOtpauth] = React.useState("");
  const [code, setCode] = React.useState("");
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    if (open && !otpauth) {
      api.post("/api/v1/auth/mfa/totp/enroll/begin").then((r) => setOtpauth(r.data.otpauth_url)).catch((e) => toast(errorMessage(e), "error"));
    }
    if (!open) {
      setOtpauth("");
      setCode("");
    }
  }, [open]); // eslint-disable-line

  async function confirm() {
    setLoading(true);
    try {
      await api.post("/api/v1/auth/mfa/totp/enroll/finish", { code });
      toast("TOTP 已绑定", "success");
      onDone();
    } catch (e) {
      toast(errorMessage(e), "error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Dialog open={open} onClose={onClose} title="绑定 TOTP" footer={<Button onClick={confirm} loading={loading}>确认</Button>}>
      <div className="space-y-3">
        {otpauth && (
          <div className="flex justify-center rounded-md border bg-white p-4">
            <QRCodeSVG value={otpauth} size={160} />
          </div>
        )}
        <Field label="验证码">
          <Input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" />
        </Field>
      </div>
    </Dialog>
  );
}

function ChangePasswordCard() {
  const { toast } = useToast();
  const [current, setCurrent] = React.useState("");
  const [next, setNext] = React.useState("");
  const [confirm, setConfirm] = React.useState("");

  const change = useMutation({
    mutationFn: () => api.post("/api/v1/auth/password/change", { current_password: current, new_password: next }),
    onSuccess: () => {
      toast("密码已修改", "success");
      setCurrent("");
      setNext("");
      setConfirm("");
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (next.length < 12) return toast("新密码至少需要 12 个字符", "error");
    if (next !== confirm) return toast("两次输入的新密码不一致", "error");
    change.mutate();
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>修改密码</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="grid max-w-md gap-4">
          <Field label="当前密码">
            <Input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" />
          </Field>
          <Field label="新密码" hint="至少 12 个字符">
            <Input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" />
          </Field>
          <Field label="确认新密码">
            <Input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
          </Field>
          <div>
            <Button type="submit" loading={change.isPending}>
              更新密码
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
