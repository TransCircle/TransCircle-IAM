import * as React from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Fingerprint, ShieldCheck, KeyRound, Lock, Users } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { safeReturnPath } from "@/lib/utils";
import { loginPasskey } from "@/lib/webauthn";
import { useAuth } from "@/auth/AuthProvider";
import { Button, Field, Input } from "@/components/ui";
import { ThemeToggle } from "@/components/ThemeToggle";

type Stage = "credentials" | "mfa";

export function LoginPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { refresh } = useAuth();
  const [stage, setStage] = React.useState<Stage>("credentials");
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [ticket, setTicket] = React.useState("");
  const [methods, setMethods] = React.useState<string[]>([]);
  const [code, setCode] = React.useState("");
  const [recoveryMode, setRecoveryMode] = React.useState(false);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);

  function done(requiredAction: string) {
    refresh();
    if (requiredAction && requiredAction !== "none") {
      navigate("/onboarding");
      return;
    }
    const ret = safeReturnPath(params.get("return"));
    if (ret) window.location.href = ret;
    else navigate("/account");
  }

  async function submitCredentials(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const { data } = await api.post("/api/v1/auth/login", { username, password });
      if (data.status === "mfa_required") {
        setTicket(data.ticket);
        setMethods(data.methods || []);
        setStage("mfa");
      } else done(data.required_action);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  async function submitTOTP(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const endpoint = recoveryMode ? "/api/v1/auth/mfa/recovery" : "/api/v1/auth/mfa/totp";
      const { data } = await api.post(endpoint, { ticket, code });
      done(data.required_action);
    } catch (err) {
      setError(errorMessage(err));
      setCode("");
    } finally {
      setLoading(false);
    }
  }

  async function usePasskey() {
    setError("");
    setLoading(true);
    try {
      const data = await loginPasskey(ticket);
      done(data.required_action);
    } catch (err) {
      setError(errorMessage(err) || "通行密钥验证已取消");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      {/* Brand panel */}
      <div className="relative hidden overflow-hidden brand-gradient lg:flex lg:flex-col lg:justify-between lg:p-12 lg:text-white">
        <div className="pointer-events-none absolute -right-24 top-10 h-72 w-72 animate-float-slow rounded-full bg-white/15 blur-2xl" />
        <div className="pointer-events-none absolute -left-16 bottom-10 h-80 w-80 rounded-full bg-black/10 blur-3xl" />
        <div className="relative flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-white/20 backdrop-blur">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <span className="text-xl font-bold tracking-tight">TransCircle</span>
        </div>
        <div className="relative space-y-6">
          <h1 className="text-4xl font-bold leading-tight">
            一处登录,
            <br />
            畅行所有内部应用。
          </h1>
          <p className="max-w-md text-white/80">统一身份认证与细粒度权限中心,支持通行密钥与动态口令,企业级安全默认。</p>
          <div className="flex flex-wrap gap-3 text-sm">
            <span className="flex items-center gap-2 rounded-full bg-white/15 px-3 py-1.5 backdrop-blur">
              <Fingerprint className="h-4 w-4" /> 通行密钥
            </span>
            <span className="flex items-center gap-2 rounded-full bg-white/15 px-3 py-1.5 backdrop-blur">
              <Lock className="h-4 w-4" /> 多因素认证
            </span>
            <span className="flex items-center gap-2 rounded-full bg-white/15 px-3 py-1.5 backdrop-blur">
              <Users className="h-4 w-4" /> OAuth2 / OIDC
            </span>
          </div>
        </div>
        <div className="relative text-sm text-white/60">© TransCircle · 仅供内部成员使用</div>
      </div>

      {/* Form panel */}
      <div className="relative flex items-center justify-center p-6">
        <div className="absolute right-4 top-4">
          <ThemeToggle />
        </div>
        <div className="w-full max-w-sm">
          <div className="mb-8 flex flex-col items-center gap-2 lg:items-start">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl brand-gradient text-white shadow-lg shadow-primary/30 lg:hidden">
              <KeyRound className="h-6 w-6" />
            </div>
            <h2 className="text-2xl font-bold tracking-tight">{stage === "credentials" ? "登录账户" : "安全验证"}</h2>
            <p className="text-sm text-muted-foreground">
              {stage === "credentials" ? "输入用户名与密码以继续" : "请完成多因素验证"}
            </p>
          </div>

          {error && <div className="mb-4 rounded-lg bg-destructive/10 px-3 py-2.5 text-sm text-destructive">{error}</div>}

          {stage === "credentials" && (
            <form onSubmit={submitCredentials} className="space-y-4">
              <Field label="用户名">
                <Input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
              </Field>
              <Field label="密码">
                <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
              </Field>
              <Button type="submit" className="w-full" size="lg" loading={loading}>
                登录
              </Button>
            </form>
          )}

          {stage === "mfa" && (
            <div className="space-y-4">
              {methods.includes("webauthn") && (
                <Button variant="outline" className="w-full" size="lg" onClick={usePasskey} loading={loading}>
                  <Fingerprint className="h-4 w-4" /> 使用通行密钥
                </Button>
              )}
              {(methods.includes("totp") || recoveryMode) && (
                <form onSubmit={submitTOTP} className="space-y-3">
                  <Field label={recoveryMode ? "恢复码" : "动态验证码 (TOTP)"}>
                    <Input value={code} onChange={(e) => setCode(e.target.value)} autoFocus inputMode={recoveryMode ? "text" : "numeric"} />
                  </Field>
                  <Button type="submit" className="w-full" size="lg" loading={loading}>
                    验证
                  </Button>
                </form>
              )}
              <button
                type="button"
                className="w-full text-center text-xs text-muted-foreground transition-colors hover:text-foreground"
                onClick={() => setRecoveryMode((v) => !v)}
              >
                {recoveryMode ? "改用动态验证码" : "无法使用验证器?改用恢复码"}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
