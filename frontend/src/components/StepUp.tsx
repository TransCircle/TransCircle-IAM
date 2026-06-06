import * as React from "react";
import { Fingerprint, ShieldAlert } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { stepUpPasskey } from "@/lib/webauthn";
import { cancelStepUp, resolveStepUp, stepUpIsOpen, subscribeStepUp } from "@/lib/stepup";
import { Dialog } from "./Dialog";
import { Button, Field, Input } from "./ui";

export function StepUpHost() {
  const [open, setOpenState] = React.useState(stepUpIsOpen());
  const [factors, setFactors] = React.useState<{ totp: boolean; passkeys: number } | null>(null);
  const [code, setCode] = React.useState("");
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => subscribeStepUp((v) => setOpenState(v)), []);

  React.useEffect(() => {
    if (open) {
      setCode("");
      setError("");
      api
        .get("/api/v1/auth/step-up/factors")
        .then((r) => setFactors(r.data))
        .catch(() => setFactors({ totp: false, passkeys: 0 }));
    }
  }, [open]);

  async function verifyTOTP(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await api.post("/api/v1/auth/step-up/totp", { code });
      resolveStepUp();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  async function verifyPasskey() {
    setLoading(true);
    setError("");
    try {
      await stepUpPasskey();
      resolveStepUp();
    } catch (err) {
      setError(errorMessage(err) || "已取消");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Dialog open={open} onClose={cancelStepUp} title="二次验证" description="该操作较为敏感，请重新验证你的身份后继续。">
      <div className="space-y-4">
        <div className="flex items-start gap-3 rounded-lg bg-accent/60 p-3 text-sm text-accent-foreground">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <span>验证通过后，接下来几分钟内的敏感操作无需重复验证。</span>
        </div>
        {error && <div className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</div>}

        {factors?.passkeys ? (
          <Button variant="outline" className="w-full" onClick={verifyPasskey} loading={loading}>
            <Fingerprint className="h-4 w-4" /> 使用通行密钥验证
          </Button>
        ) : null}

        {factors?.totp && (
          <form onSubmit={verifyTOTP} className="space-y-3">
            <Field label="动态验证码 (TOTP)">
              <Input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoFocus placeholder="6 位验证码" />
            </Field>
            <Button type="submit" className="w-full" loading={loading}>
              验证并继续
            </Button>
          </form>
        )}

        {factors && !factors.totp && !factors.passkeys && (
          <p className="text-sm text-muted-foreground">你尚未绑定可用于二次验证的因子，请先在「个人中心 → 安全」绑定通行密钥或 TOTP。</p>
        )}
      </div>
    </Dialog>
  );
}
