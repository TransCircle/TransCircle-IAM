import * as React from "react";
import { useParams } from "react-router-dom";
import { ShieldCheck, Fingerprint, CheckCircle2, AlertTriangle } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { verifyPasskey } from "@/lib/webauthn";
import { Button, Input, Skeleton } from "@/components/ui";

interface VerifyInfo {
  status: "pending" | "verified";
  requested_by: string;
  allowed_factors: string[];
  require_label: string;
  mismatch: boolean;
  has_redirect: boolean;
  current_user: string;
  factors: { totp: boolean; passkeys: number };
}

// completeRedirect sends the browser back to the calling app with the result, or
// shows the in-page success state when no redirect was configured.
function completeRedirect(redirectURI: string, id: string): boolean {
  if (!redirectURI) return false;
  try {
    const u = new URL(redirectURI);
    u.searchParams.set("verification_id", id);
    u.searchParams.set("status", "verified");
    window.location.href = u.toString();
    return true;
  } catch {
    return false;
  }
}

export function VerifyPage() {
  const { id = "" } = useParams();
  const [info, setInfo] = React.useState<VerifyInfo | null>(null);
  const [loadErr, setLoadErr] = React.useState("");
  const [code, setCode] = React.useState("");
  const [busy, setBusy] = React.useState<null | "totp" | "passkey">(null);
  const [err, setErr] = React.useState("");
  const [done, setDone] = React.useState(false);
  const [redirecting, setRedirecting] = React.useState(false);

  React.useEffect(() => {
    api
      .get<VerifyInfo>(`/api/v1/verify/${encodeURIComponent(id)}`)
      .then((r) => {
        setInfo(r.data);
        if (r.data.status === "verified") setDone(true);
      })
      .catch((e) => setLoadErr(errorMessage(e)));
  }, [id]);

  const allow = (f: string) => !info?.allowed_factors?.length || info.allowed_factors.includes(f);
  const canTOTP = !!info && info.factors.totp && allow("totp");
  const canPasskey = !!info && info.factors.passkeys > 0 && allow("passkey");

  function onSuccess(redirectURI: string) {
    if (completeRedirect(redirectURI, id)) {
      setRedirecting(true);
    } else {
      setDone(true);
    }
  }

  async function submitTOTP(e: React.FormEvent) {
    e.preventDefault();
    if (busy || code.length !== 6) return;
    setBusy("totp");
    setErr("");
    try {
      const r = await api.post(`/api/v1/verify/${encodeURIComponent(id)}/totp`, { code });
      onSuccess(r.data?.redirect_uri ?? "");
    } catch (e2) {
      setErr(errorMessage(e2));
      setBusy(null);
    }
  }

  async function doPasskey() {
    if (busy) return;
    setBusy("passkey");
    setErr("");
    try {
      const r = await verifyPasskey(id);
      onSuccess(r.redirect_uri);
    } catch (e2) {
      setErr(errorMessage(e2) || "已取消");
      setBusy(null);
    }
  }

  return (
    <div className="bg-grid flex min-h-screen items-center justify-center p-4">
      <div className="bracket-frame w-full max-w-md rounded-lg border bg-card p-7 shadow-[0_2px_16px_hsl(var(--foreground)/0.05)]">
        <div className="stagger">
          <div className="mono-label mb-4 flex items-center gap-2 text-muted-foreground">
            <ShieldCheck className="h-3.5 w-3.5 text-primary" />
            two-factor verification · 两步验证
          </div>

          {loadErr ? (
            <div className="rounded-md border border-destructive/30 bg-destructive/8 px-3 py-3 text-sm text-destructive">{loadErr}</div>
          ) : !info ? (
            <div className="space-y-2">
              <Skeleton className="h-5 w-40" />
              <Skeleton className="h-4 w-56" />
              <Skeleton className="mt-4 h-10" />
            </div>
          ) : redirecting ? (
            <Success title="验证成功" desc="正在返回应用…" />
          ) : done ? (
            <Success title="验证成功" desc={info.has_redirect ? "你可以返回发起验证的应用了。" : "你已完成本次两步验证，请返回发起验证的应用。"} />
          ) : info.mismatch ? (
            <div className="space-y-3">
              <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 p-3 text-sm">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
                <div>
                  本次验证要求账号 <b className="font-mono">{info.require_label}</b>，但你当前登录的是
                  <b className="font-mono"> {info.current_user}</b>。请使用正确的账号登录后重试。
                </div>
              </div>
              <a href="/login" className="block text-center text-sm text-primary hover:underline">
                切换账号
              </a>
            </div>
          ) : (
            <>
              <p className="text-sm text-muted-foreground">
                <b className="text-foreground">{info.requested_by || "应用"}</b> 请求你完成一次两步验证，以
                <b className="font-mono text-foreground"> {info.current_user}</b> 的身份继续。
              </p>

              {err && <div className="mt-3 rounded-md border border-destructive/30 bg-destructive/8 px-3 py-2 text-sm text-destructive">{err}</div>}

              {!canTOTP && !canPasskey ? (
                <div className="mt-4 rounded-md border bg-muted/30 p-3 text-sm text-muted-foreground">
                  你的账号尚未绑定可用于本次验证的因素（通行密钥或动态口令）。请先在「安全与多因素」中绑定后重试。
                </div>
              ) : (
                <div className="mt-5 space-y-5">
                  {canPasskey && (
                    <div className="space-y-2">
                      <div className="mono-label text-muted-foreground">通行密钥</div>
                      <Button type="button" className="w-full" variant="outline" onClick={doPasskey} loading={busy === "passkey"} disabled={busy === "totp"}>
                        <Fingerprint className="h-4 w-4" /> 使用通行密钥验证
                      </Button>
                    </div>
                  )}

                  {canTOTP && canPasskey && (
                    <div className="flex items-center gap-3 text-[11px] uppercase tracking-wider text-muted-foreground">
                      <span className="h-px flex-1 bg-border" /> 或 <span className="h-px flex-1 bg-border" />
                    </div>
                  )}

                  {canTOTP && (
                    <form onSubmit={submitTOTP} className="space-y-2">
                      <div className="mono-label text-muted-foreground">动态口令 (TOTP)</div>
                      <Input
                        value={code}
                        autoFocus={!canPasskey}
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        placeholder="6 位数字"
                        maxLength={6}
                        onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                        className="text-center font-mono text-lg tracking-[0.5em]"
                      />
                      <Button type="submit" className="w-full" loading={busy === "totp"} disabled={code.length !== 6 || busy === "passkey"}>
                        验证
                      </Button>
                    </form>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function Success({ title, desc }: { title: string; desc: string }) {
  return (
    <div className="flex flex-col items-center gap-3 py-4 text-center">
      <CheckCircle2 className="h-12 w-12 text-success" />
      <div className="text-base font-semibold">{title}</div>
      <p className="text-sm text-muted-foreground">{desc}</p>
    </div>
  );
}
