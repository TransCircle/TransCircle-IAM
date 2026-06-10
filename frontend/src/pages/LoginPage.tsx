import * as React from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Fingerprint, ShieldCheck, Lock, Users, ArrowLeft } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { safeReturnPath } from "@/lib/utils";
import { loginPasskey } from "@/lib/webauthn";
import { useAuth } from "@/auth/AuthProvider";
import { Button, Field, Input, PasswordInput } from "@/components/ui";
import { ThemeToggle } from "@/components/ThemeToggle";

type Stage = "username" | "password" | "mfa";

export function LoginPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { me, loading: authLoading, refresh } = useAuth();
  const [stage, setStage] = React.useState<Stage>("username");
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [ticket, setTicket] = React.useState("");
  const [methods, setMethods] = React.useState<string[]>([]);
  const [code, setCode] = React.useState("");
  const [recoveryMode, setRecoveryMode] = React.useState(false);
  const [error, setError] = React.useState("");
  // Separate pending flags so starting a passkey ceremony doesn't lock the
  // TOTP form (and vice versa).
  const [submitting, setSubmitting] = React.useState(false);
  const [passkeyPending, setPasskeyPending] = React.useState(false);

  // Already signed in (e.g. user opened /login in a new tab) — skip the form.
  React.useEffect(() => {
    if (!authLoading && me && me.required_action === "none") {
      const ret = safeReturnPath(params.get("return"));
      if (ret) window.location.href = ret;
      else navigate("/account", { replace: true });
    }
  }, [authLoading, me, navigate, params]);

  async function done(requiredAction: string) {
    // Wait for /me to actually refetch before entering guarded routes,
    // otherwise RequireAuth still sees "not logged in" and bounces back here.
    await refresh();
    if (requiredAction && requiredAction !== "none") {
      navigate("/onboarding");
      return;
    }
    const ret = safeReturnPath(params.get("return"));
    if (ret) window.location.href = ret;
    else navigate("/account");
  }

  // Step 1: advance from username to password (no request yet) — pressing Enter
  // on the username field moves forward instead of attempting a login.
  function submitUsername(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (!username.trim()) {
      setError("请输入用户名");
      return;
    }
    setStage("password");
  }

  function backToUsername() {
    setError("");
    setPassword("");
    setStage("username");
  }

  // Step 2: submit credentials.
  async function submitCredentials(e: React.FormEvent) {
    e.preventDefault();
    if (submitting) return;
    setError("");
    if (!password) {
      setError("请输入密码");
      return;
    }
    setSubmitting(true);
    try {
      const { data } = await api.post("/api/v1/auth/login", { username, password });
      if (data.status === "mfa_required") {
        setTicket(data.ticket);
        setMethods(data.methods || []);
        setStage("mfa");
      } else await done(data.required_action);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  async function submitTOTP(e: React.FormEvent) {
    e.preventDefault();
    if (submitting) return;
    setError("");
    setSubmitting(true);
    try {
      const endpoint = recoveryMode ? "/api/v1/auth/mfa/recovery" : "/api/v1/auth/mfa/totp";
      const { data } = await api.post(endpoint, { ticket, code });
      await done(data.required_action);
    } catch (err) {
      setError(errorMessage(err));
      setCode("");
    } finally {
      setSubmitting(false);
    }
  }

  async function usePasskey() {
    if (passkeyPending) return;
    setError("");
    setPasskeyPending(true);
    try {
      const data = await loginPasskey(ticket);
      await done(data.required_action);
    } catch (err) {
      setError(errorMessage(err) || "通行密钥验证已取消");
    } finally {
      setPasskeyPending(false);
    }
  }

  const heading = stage === "mfa" ? "安全验证" : "登录账户";
  const subheading =
    stage === "username"
      ? "输入用户名以继续"
      : stage === "password"
        ? "输入密码完成登录"
        : "请完成多因素验证";
  const stageIndex = stage === "username" ? 1 : stage === "password" ? 2 : 3;

  return (
    <div className="grid min-h-screen lg:grid-cols-[5fr_6fr]">
      {/* Ink brand panel */}
      <div className="bg-grid-chrome relative hidden overflow-hidden bg-chrome text-chrome-foreground lg:flex lg:flex-col lg:justify-between lg:p-12">
        <div className="pointer-events-none absolute inset-x-12 top-1/2 h-px -translate-y-1/2 bg-chrome-border" />
        <div className="relative flex items-center gap-3">
          <div className="bracket-frame flex h-11 w-11 items-center justify-center rounded-md brand-gradient text-white [--tick:hsl(var(--chrome-accent)/0.9)] [--tick-len:9px]">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div className="leading-tight">
            <span className="font-mono text-lg font-semibold tracking-tight">
              TRANS<span className="text-chrome-accent">CIRCLE</span>
            </span>
            <div className="mono-label text-[10px] text-chrome-muted">identity · access · management</div>
          </div>
        </div>

        <div className="relative space-y-7">
          <p className="mono-label text-chrome-accent">single sign-on</p>
          <h1 className="text-[2.6rem] font-bold leading-[1.18] tracking-tight">
            一处登录，
            <br />
            畅行所有内部应用。
          </h1>
          <p className="max-w-md text-[15px] leading-relaxed text-chrome-muted">
            统一身份认证与细粒度权限中心，支持通行密钥与动态口令，企业级安全默认开启。
          </p>
          <div className="flex flex-wrap gap-2.5">
            {[
              { icon: Fingerprint, label: "PASSKEY · 通行密钥" },
              { icon: Lock, label: "MFA · 多因素" },
              { icon: Users, label: "OAUTH2 / OIDC" },
            ].map((f) => (
              <span
                key={f.label}
                className="flex items-center gap-2 rounded-sm border border-chrome-border bg-white/[0.03] px-3 py-1.5 font-mono text-xs text-chrome-muted"
              >
                <f.icon className="h-3.5 w-3.5 text-chrome-accent" /> {f.label}
              </span>
            ))}
          </div>
        </div>

        <div className="mono-label relative text-[10px] text-chrome-muted/70">© transcircle · internal use only</div>
      </div>

      {/* Form panel */}
      <div className="bg-grid relative flex flex-col items-center justify-center p-5 pt-16 sm:p-6 sm:pt-16 lg:pt-6">
        <div className="absolute right-4 top-4">
          <ThemeToggle />
        </div>
        {/* The ink brand panel is hidden below lg — phones still need the brand. */}
        <div className="mb-6 flex items-center gap-2.5 lg:hidden">
          <div className="bracket-frame flex h-10 w-10 items-center justify-center rounded-md brand-gradient text-white [--tick:hsl(var(--primary)/0.7)] [--tick-len:8px]">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div className="leading-tight">
            <div className="font-mono text-[15px] font-semibold tracking-tight">
              TRANS<span className="text-primary">CIRCLE</span>
            </div>
            <div className="mono-label text-[10px] text-muted-foreground">identity · 统一身份</div>
          </div>
        </div>
        <div className="bracket-frame w-full max-w-md rounded-lg border bg-card p-6 shadow-[0_2px_16px_hsl(var(--foreground)/0.05)] sm:p-10">
          <div className="stagger">
            <div className="mb-8">
              <div className="mono-label mb-3 flex items-center gap-2 text-muted-foreground">
                <span className="text-primary">{String(stageIndex).padStart(2, "0")}</span>
                <span className="h-px w-6 bg-border" />
                <span>step {stageIndex} / 3</span>
              </div>
              <h2 className="text-2xl font-bold tracking-tight">{heading}</h2>
              <p className="mt-1.5 text-sm text-muted-foreground">{subheading}</p>
            </div>

            {error && (
              <div className="mb-4 rounded-md border border-destructive/30 bg-destructive/8 px-3 py-2.5 text-sm text-destructive">
                {error}
              </div>
            )}

            {stage === "username" && (
              <form onSubmit={submitUsername} className="space-y-4">
                <Field label="用户名">
                  <Input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
                </Field>
                <Button type="submit" className="w-full" size="lg">
                  下一步
                </Button>
              </form>
            )}

            {stage === "password" && (
              <form onSubmit={submitCredentials} className="space-y-4">
                <button
                  type="button"
                  onClick={backToUsername}
                  className="flex items-center gap-1.5 font-mono text-sm text-muted-foreground transition-colors hover:text-foreground"
                >
                  <ArrowLeft className="h-4 w-4" /> {username}
                </button>
                <Field label="密码">
                  <PasswordInput
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoFocus
                    autoComplete="current-password"
                  />
                </Field>
                <Button type="submit" className="w-full" size="lg" loading={submitting}>
                  登录
                </Button>
              </form>
            )}

            {stage === "mfa" && (
              <div className="space-y-4">
                {methods.includes("webauthn") && (
                  <Button variant="outline" className="w-full" size="lg" onClick={usePasskey} loading={passkeyPending}>
                    <Fingerprint className="h-4 w-4" /> 使用通行密钥
                  </Button>
                )}
                {(methods.includes("totp") || recoveryMode) && (
                  <form onSubmit={submitTOTP} className="space-y-3">
                    <Field label={recoveryMode ? "恢复码" : "动态验证码 (TOTP)"}>
                      <Input
                        value={code}
                        onChange={(e) => setCode(e.target.value)}
                        autoFocus
                        inputMode={recoveryMode ? "text" : "numeric"}
                        className="font-mono tracking-widest"
                      />
                    </Field>
                    <Button type="submit" className="w-full" size="lg" loading={submitting}>
                      验证
                    </Button>
                  </form>
                )}
                <button
                  type="button"
                  className="w-full text-center text-xs text-muted-foreground transition-colors hover:text-foreground"
                  onClick={() => setRecoveryMode((v) => !v)}
                >
                  {recoveryMode ? "改用动态验证码" : "无法使用验证器？改用恢复码"}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
