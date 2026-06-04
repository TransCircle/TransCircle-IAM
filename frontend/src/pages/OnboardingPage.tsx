import * as React from "react";
import { useNavigate } from "react-router-dom";
import { QRCodeSVG } from "qrcode.react";
import { Fingerprint } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { registerPasskey } from "@/lib/webauthn";
import { useAuth } from "@/auth/AuthProvider";
import { Button, Card, CardContent, CardHeader, CardTitle, Field, Input } from "@/components/ui";
import { useToast } from "@/components/Toast";

export function OnboardingPage() {
  const { me, refresh } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();
  const action = me?.required_action ?? "none";

  React.useEffect(() => {
    if (action === "none") navigate("/account");
  }, [action, navigate]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/30 p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>账户初始化</CardTitle>
          <p className="text-sm text-muted-foreground">
            首次登录需要完成以下安全设置后方可使用系统。
          </p>
        </CardHeader>
        <CardContent>
          {action === "change_password" && <ChangePasswordStep onDone={refresh} toast={toast} />}
          {action === "enroll_mfa" && <EnrollMFAStep onDone={refresh} toast={toast} />}
        </CardContent>
      </Card>
    </div>
  );
}

function ChangePasswordStep({ onDone, toast }: { onDone: () => void; toast: (m: string, k?: "success" | "error") => void }) {
  const [current, setCurrent] = React.useState("");
  const [next, setNext] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [loading, setLoading] = React.useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (next !== confirm) {
      toast("两次输入的密码不一致", "error");
      return;
    }
    setLoading(true);
    try {
      await api.post("/api/v1/auth/password/change", { current_password: current, new_password: next });
      toast("密码已修改", "success");
      onDone();
    } catch (err) {
      toast(errorMessage(err), "error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <h3 className="font-medium">第一步：修改初始密码</h3>
      <Field label="当前（临时）密码">
        <Input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} />
      </Field>
      <Field label="新密码" hint="至少 12 个字符">
        <Input type="password" value={next} onChange={(e) => setNext(e.target.value)} />
      </Field>
      <Field label="确认新密码">
        <Input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
      </Field>
      <Button type="submit" className="w-full" loading={loading}>
        修改密码
      </Button>
    </form>
  );
}

function EnrollMFAStep({ onDone, toast }: { onDone: () => void; toast: (m: string, k?: "success" | "error") => void }) {
  const [tab, setTab] = React.useState<"passkey" | "totp">("passkey");
  const [otpauth, setOtpauth] = React.useState("");
  const [code, setCode] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [recovery, setRecovery] = React.useState<string[] | null>(null);

  async function addPasskey() {
    setLoading(true);
    try {
      await registerPasskey("通行密钥");
      await fetchRecovery();
    } catch (err) {
      toast(errorMessage(err) || "注册已取消", "error");
    } finally {
      setLoading(false);
    }
  }

  async function startTOTP() {
    setLoading(true);
    try {
      const { data } = await api.post("/api/v1/auth/mfa/totp/enroll/begin");
      setOtpauth(data.otpauth_url);
    } catch (err) {
      toast(errorMessage(err), "error");
    } finally {
      setLoading(false);
    }
  }

  async function confirmTOTP(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      await api.post("/api/v1/auth/mfa/totp/enroll/finish", { code });
      await fetchRecovery();
    } catch (err) {
      toast(errorMessage(err), "error");
    } finally {
      setLoading(false);
    }
  }

  async function fetchRecovery() {
    const { data } = await api.post("/api/v1/auth/recovery/generate");
    setRecovery(data.codes);
  }

  if (recovery) {
    return (
      <div className="space-y-4">
        <h3 className="font-medium">保存恢复码</h3>
        <p className="text-sm text-muted-foreground">请妥善保存以下一次性恢复码，丢失 MFA 设备时可用于登录。</p>
        <div className="grid grid-cols-2 gap-2 rounded-md border bg-muted/40 p-3 font-mono text-sm">
          {recovery.map((c) => (
            <span key={c}>{c}</span>
          ))}
        </div>
        <Button className="w-full" onClick={onDone}>
          我已保存，完成
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h3 className="font-medium">第二步：绑定多因素认证</h3>
      <div className="flex gap-2 rounded-md bg-muted p-1 text-sm">
        <button className={`flex-1 rounded px-3 py-1.5 ${tab === "passkey" ? "bg-card shadow" : ""}`} onClick={() => setTab("passkey")}>
          通行密钥
        </button>
        <button className={`flex-1 rounded px-3 py-1.5 ${tab === "totp" ? "bg-card shadow" : ""}`} onClick={() => setTab("totp")}>
          TOTP
        </button>
      </div>

      {tab === "passkey" && (
        <Button className="w-full" onClick={addPasskey} loading={loading}>
          <Fingerprint className="h-4 w-4" /> 注册通行密钥
        </Button>
      )}

      {tab === "totp" && (
        <div className="space-y-3">
          {!otpauth ? (
            <Button className="w-full" variant="outline" onClick={startTOTP} loading={loading}>
              生成 TOTP 二维码
            </Button>
          ) : (
            <form onSubmit={confirmTOTP} className="space-y-3">
              <div className="flex justify-center rounded-md border bg-white p-4">
                <QRCodeSVG value={otpauth} size={160} />
              </div>
              <p className="text-xs text-muted-foreground">使用认证器扫码后输入 6 位验证码确认绑定。</p>
              <Field label="验证码">
                <Input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" />
              </Field>
              <Button type="submit" className="w-full" loading={loading}>
                确认绑定
              </Button>
            </form>
          )}
        </div>
      )}
    </div>
  );
}
