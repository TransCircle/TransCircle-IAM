import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Pencil, Trash2 } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { api, errorMessage } from "@/lib/api";
import { registerPasskey } from "@/lib/webauthn";
import { useAuth } from "@/auth/AuthProvider";
import { Button, Card, CardContent, CardHeader, CardTitle, CopyButton, Field, Input, PageHeader, PasswordInput, Spinner } from "@/components/ui";
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
              <div key={pk.id} className="flex items-center justify-between gap-3 rounded-md border p-3 text-sm">
                <div className="min-w-0">
                  <div className="truncate font-medium">{pk.name}</div>
                  <div className="text-xs text-muted-foreground">
                    添加于 {formatDate(pk.created_at)} · 最近使用 {formatDate(pk.last_used_at)}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => {
                      setRenameTarget(pk);
                      setRenameName(pk.name ?? "");
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
        submitting={addPasskey.isPending}
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
        onSubmit={() => renameTarget && renamePasskey.mutate({ id: renameTarget.id, name: renameName.trim() || renameTarget.name || "通行密钥" })}
        submitting={renamePasskey.isPending}
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

// parseOtpauth pulls the human-meaningful pieces out of an otpauth:// URI so the
// dialog can show a copyable secret and the account/issuer it will be filed under.
function parseOtpauth(uri: string): { secret: string; account: string; issuer: string; digits: string; period: string; algorithm: string } {
  const empty = { secret: "", account: "", issuer: "", digits: "6", period: "30", algorithm: "SHA1" };
  if (!uri) return empty;
  try {
    const u = new URL(uri);
    const p = u.searchParams;
    // Label is /totp/{issuer}:{account} (issuer prefix optional). Split on the
    // FIRST colon only so an account value containing a colon is preserved.
    const label = decodeURIComponent(u.pathname.replace(/^\/+/, "").replace(/^totp\/?/i, ""));
    const ci = label.indexOf(":");
    const a = ci >= 0 ? label.slice(0, ci) : "";
    const b = ci >= 0 ? label.slice(ci + 1) : label;
    return {
      secret: p.get("secret") ?? "",
      issuer: p.get("issuer") ?? a ?? "",
      account: b ?? a ?? "",
      digits: p.get("digits") ?? "6",
      period: p.get("period") ?? "30",
      algorithm: p.get("algorithm") ?? "SHA1",
    };
  } catch {
    return empty;
  }
}

// groupSecret formats a base32 secret into space-separated quads for readability
// and easier manual entry / proofreading.
function groupSecret(s: string): string {
  return (s.match(/.{1,4}/g) ?? []).join(" ");
}

function TOTPDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const { toast } = useToast();
  const [otpauth, setOtpauth] = React.useState("");
  const [code, setCode] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [showManual, setShowManual] = React.useState(false);

  const began = React.useRef(false);
  React.useEffect(() => {
    // Ref-guarded so StrictMode's double effect doesn't enroll two tickets.
    if (open && !began.current) {
      began.current = true;
      api.post("/api/v1/auth/mfa/totp/enroll/begin").then((r) => setOtpauth(r.data.otpauth_url)).catch((e) => toast(errorMessage(e), "error"));
    }
    if (!open) {
      began.current = false;
      setOtpauth("");
      setCode("");
      setShowManual(false);
    }
  }, [open]); // eslint-disable-line

  const info = React.useMemo(() => parseOtpauth(otpauth), [otpauth]);
  const ready = code.length === 6 && !loading;

  async function confirm() {
    if (!ready) return;
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
    <Dialog
      open={open}
      onClose={onClose}
      title="绑定动态口令 (TOTP)"
      description="使用 Microsoft / Google Authenticator、1Password、Authy 等任意兼容应用扫码或手动添加，然后输入应用生成的 6 位验证码。"
      onSubmit={confirm}
      footer={
        <>
          <Button variant="outline" type="button" onClick={onClose}>取消</Button>
          <Button type="submit" loading={loading} disabled={!ready}>完成绑定</Button>
        </>
      }
    >
      <div className="space-y-5">
        {/* Step 1 — scan */}
        <section className="space-y-2.5">
          <div className="mono-label text-muted-foreground">第 1 步 · 扫描二维码</div>
          <div className="flex flex-col items-center gap-3 rounded-lg border bg-muted/30 p-4">
            <div className="rounded-lg border bg-white p-3 shadow-sm">
              {otpauth ? (
                <QRCodeSVG value={otpauth} size={168} />
              ) : (
                <div className="flex h-[168px] w-[168px] items-center justify-center text-muted-foreground">
                  <Spinner className="h-6 w-6" />
                </div>
              )}
            </div>
            {info.account && (
              <p className="text-center text-xs text-muted-foreground">
                将以 <span className="font-medium text-foreground">{info.issuer || "TransCircle"}</span>
                {" · "}
                <span className="font-medium text-foreground">{info.account}</span> 添加
              </p>
            )}
          </div>
        </section>

        {/* Step 2 — manual entry */}
        <section className="space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="mono-label text-muted-foreground">第 2 步 · 无法扫码？手动输入密钥</div>
            <button type="button" className="text-xs text-primary hover:underline" onClick={() => setShowManual((v) => !v)}>
              {showManual ? "收起" : "展开"}
            </button>
          </div>
          {showManual && (
            <div className="space-y-3 rounded-lg border bg-muted/30 p-3">
              <div className="space-y-1">
                <div className="text-xs text-muted-foreground">账户密钥（区分大小写）</div>
                <div className="flex items-center justify-between gap-2 rounded-md border bg-card p-2.5">
                  <code className="select-all break-all font-mono text-sm tracking-wider">{info.secret ? groupSecret(info.secret) : "—"}</code>
                  {info.secret && <CopyButton value={info.secret} />}
                </div>
              </div>
              <dl className="grid grid-cols-3 gap-2 text-center text-[11px] text-muted-foreground">
                <div className="rounded-md border bg-card py-1.5"><dt>类型</dt><dd className="font-medium text-foreground">基于时间</dd></div>
                <div className="rounded-md border bg-card py-1.5"><dt>位数</dt><dd className="font-medium text-foreground">{info.digits}</dd></div>
                <div className="rounded-md border bg-card py-1.5"><dt>周期</dt><dd className="font-medium text-foreground">{info.period}s</dd></div>
              </dl>
            </div>
          )}
        </section>

        {/* Step 3 — verify */}
        <section className="space-y-2.5">
          <div className="mono-label text-muted-foreground">第 3 步 · 输入验证码</div>
          <Input
            value={code}
            autoFocus
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="6 位数字"
            maxLength={6}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            className="text-center font-mono text-lg tracking-[0.5em]"
          />
        </section>
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
    if (change.isPending) return;
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
