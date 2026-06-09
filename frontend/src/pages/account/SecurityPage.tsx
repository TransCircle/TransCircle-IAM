import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Pencil, Trash2 } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { api, errorMessage } from "@/lib/api";
import { registerPasskey } from "@/lib/webauthn";
import { useAuth } from "@/auth/AuthProvider";
import { Button, Card, CardContent, CardHeader, CardTitle, CopyButton, Field, Input, PageHeader, PasswordInput } from "@/components/ui";
import { Dialog, ConfirmDialog } from "@/components/Dialog";
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
  const [confirmRemoveTotp, setConfirmRemoveTotp] = React.useState(false);
  const [confirmRegen, setConfirmRegen] = React.useState(false);
  const [delTarget, setDelTarget] = React.useState<Passkey | null>(null);
  const [addOpen, setAddOpen] = React.useState(false);
  const [newName, setNewName] = React.useState("通行密钥");
  const [renameTarget, setRenameTarget] = React.useState<Passkey | null>(null);
  const [renameName, setRenameName] = React.useState("");

  const passkeys = useQuery<Passkey[]>({
    queryKey: ["passkeys"],
    queryFn: async () => (await api.get("/api/v1/account/passkeys")).data.passkeys ?? [],
  });

  const addPasskey = useMutation({
    mutationFn: (name: string) => registerPasskey(name),
    onSuccess: () => {
      toast("通行密钥已添加", "success");
      setAddOpen(false);
      qc.invalidateQueries({ queryKey: ["passkeys"] });
      refresh();
    },
    onError: (e) => toast(errorMessage(e) || "已取消", "error"),
  });

  const renamePasskey = useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) => api.patch(`/api/v1/account/passkeys/${id}`, { name }),
    onSuccess: () => {
      toast("已重命名", "success");
      setRenameTarget(null);
      qc.invalidateQueries({ queryKey: ["passkeys"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  const delPasskey = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/account/passkeys/${id}`),
    onSuccess: () => {
      setDelTarget(null);
      qc.invalidateQueries({ queryKey: ["passkeys"] });
      refresh();
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  const removeTotp = useMutation({
    mutationFn: () => api.delete("/api/v1/account/totp"),
    onSuccess: () => {
      setConfirmRemoveTotp(false);
      toast("已移除 TOTP", "success");
      refresh();
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  const regenRecovery = useMutation({
    mutationFn: async () => (await api.post("/api/v1/auth/recovery/generate")).data.codes as string[],
    onSuccess: (codes) => {
      setConfirmRegen(false);
      setRecovery(codes);
      refresh();
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <div>
      <PageHeader title="安全与多因素" description="修改密码,管理你的通行密钥、TOTP 与恢复码。" />
      <div className="grid gap-6">
        <ChangePasswordCard />

        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>通行密钥</CardTitle>
            <Button
              size="sm"
              onClick={() => {
                setNewName("通行密钥");
                setAddOpen(true);
              }}
              loading={addPasskey.isPending}
            >
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
                <div className="flex items-center gap-1">
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => {
                      setRenameTarget(pk);
                      setRenameName(pk.name);
                    }}
                    aria-label="重命名"
                  >
                    <Pencil className="h-4 w-4" />
                  </Button>
                  <Button size="icon" variant="ghost" onClick={() => setDelTarget(pk)} aria-label="删除">
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>动态口令 (TOTP)</CardTitle>
            {me?.mfa.totp ? (
              <Button size="sm" variant="outline" onClick={() => setConfirmRemoveTotp(true)}>
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
            <Button size="sm" variant="outline" onClick={() => setConfirmRegen(true)} loading={regenRecovery.isPending}>
              重新生成
            </Button>
          </CardHeader>
          <CardContent>
            {recovery ? (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-2 rounded-md border bg-muted/40 p-3 font-mono text-sm">
                  {recovery.map((c) => (
                    <span key={c}>{c}</span>
                  ))}
                </div>
                <CopyButton value={recovery.join("\n")} label="复制全部恢复码" />
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">剩余 {me?.mfa.recovery_codes ?? 0} 个未使用恢复码。重新生成将作废旧码。</p>
            )}
          </CardContent>
        </Card>
      </div>

      <Dialog
        open={addOpen}
        onClose={() => setAddOpen(false)}
        title="添加通行密钥"
        onSubmit={() => addPasskey.mutate(newName.trim() || "通行密钥")}
        footer={
          <>
            <Button variant="outline" type="button" onClick={() => setAddOpen(false)}>取消</Button>
            <Button type="submit" loading={addPasskey.isPending}>继续</Button>
          </>
        }
      >
        <Field label="名称" hint="给这个通行密钥起个好记的名字，例如「我的 iPhone」「公司笔记本」。">
          <Input value={newName} autoFocus onChange={(e) => setNewName(e.target.value)} maxLength={64} />
        </Field>
      </Dialog>

      <Dialog
        open={!!renameTarget}
        onClose={() => setRenameTarget(null)}
        title="重命名通行密钥"
        onSubmit={() => renameTarget && renamePasskey.mutate({ id: renameTarget.id, name: renameName.trim() || renameTarget.name })}
        footer={
          <>
            <Button variant="outline" type="button" onClick={() => setRenameTarget(null)}>取消</Button>
            <Button type="submit" loading={renamePasskey.isPending}>保存</Button>
          </>
        }
      >
        <Field label="名称">
          <Input value={renameName} autoFocus onChange={(e) => setRenameName(e.target.value)} maxLength={64} />
        </Field>
      </Dialog>

      <TOTPDialog open={totpOpen} onClose={() => setTotpOpen(false)} onDone={() => { setTotpOpen(false); refresh(); }} />

      <ConfirmDialog
        open={!!delTarget}
        onClose={() => setDelTarget(null)}
        onConfirm={() => delTarget && delPasskey.mutate(delTarget.id)}
        title={`删除通行密钥「${delTarget?.name}」?`}
        description="删除后将无法再用此通行密钥登录。"
        confirmLabel="删除"
        destructive
        loading={delPasskey.isPending}
      />
      <ConfirmDialog
        open={confirmRemoveTotp}
        onClose={() => setConfirmRemoveTotp(false)}
        onConfirm={() => removeTotp.mutate()}
        title="移除 TOTP?"
        description="移除后你将只能使用通行密钥或恢复码完成多因素验证。"
        confirmLabel="移除"
        destructive
        loading={removeTotp.isPending}
      />
      <ConfirmDialog
        open={confirmRegen}
        onClose={() => setConfirmRegen(false)}
        onConfirm={() => regenRecovery.mutate()}
        title="重新生成恢复码?"
        description="重新生成后,现有的所有恢复码将立即作废。"
        confirmLabel="重新生成"
        loading={regenRecovery.isPending}
      />
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
    <Dialog open={open} onClose={onClose} title="绑定 TOTP" onSubmit={confirm} footer={<Button type="submit" loading={loading}>确认</Button>}>
      <div className="space-y-3">
        {otpauth && (
          <div className="flex justify-center rounded-md border bg-white p-4">
            <QRCodeSVG value={otpauth} size={160} />
          </div>
        )}
        <Field label="验证码">
          <Input value={code} autoFocus onChange={(e) => setCode(e.target.value)} inputMode="numeric" />
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
            <PasswordInput value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" />
          </Field>
          <Field label="新密码" hint="至少 12 个字符">
            <PasswordInput value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" />
          </Field>
          <Field label="确认新密码">
            <PasswordInput value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
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
