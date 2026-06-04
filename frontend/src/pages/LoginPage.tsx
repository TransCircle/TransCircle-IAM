import * as React from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Fingerprint, KeyRound } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { safeReturnPath } from "@/lib/utils";
import { loginPasskey } from "@/lib/webauthn";
import { useAuth } from "@/auth/AuthProvider";
import { Button, Card, CardContent, CardHeader, CardTitle, Field, Input } from "@/components/ui";
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
    if (ret) {
      window.location.href = ret;
    } else {
      navigate("/account");
    }
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
      } else {
        done(data.required_action);
      }
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
    <div className="flex min-h-screen items-center justify-center bg-muted/30 p-4">
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>
      <Card className="w-full max-w-sm">
        <CardHeader className="text-center">
          <div className="mx-auto mb-2 flex h-11 w-11 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <KeyRound className="h-5 w-5" />
          </div>
          <CardTitle>登录 TransCircle</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</div>}

          {stage === "credentials" && (
            <form onSubmit={submitCredentials} className="space-y-4">
              <Field label="用户名">
                <Input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
              </Field>
              <Field label="密码">
                <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
              </Field>
              <Button type="submit" className="w-full" loading={loading}>
                登录
              </Button>
            </form>
          )}

          {stage === "mfa" && (
            <div className="space-y-4">
              {methods.includes("webauthn") && (
                <Button variant="outline" className="w-full" onClick={usePasskey} loading={loading}>
                  <Fingerprint className="h-4 w-4" /> 使用通行密钥
                </Button>
              )}
              {(methods.includes("totp") || recoveryMode) && (
                <form onSubmit={submitTOTP} className="space-y-3">
                  <Field label={recoveryMode ? "恢复码" : "动态验证码 (TOTP)"}>
                    <Input value={code} onChange={(e) => setCode(e.target.value)} autoFocus inputMode={recoveryMode ? "text" : "numeric"} />
                  </Field>
                  <Button type="submit" className="w-full" loading={loading}>
                    验证
                  </Button>
                </form>
              )}
              <button
                type="button"
                className="w-full text-center text-xs text-muted-foreground hover:text-foreground"
                onClick={() => setRecoveryMode((v) => !v)}
              >
                {recoveryMode ? "使用动态验证码" : "使用恢复码"}
              </button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
