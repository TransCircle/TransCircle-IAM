import * as React from "react";
import { useSearchParams } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { safeReturnPath } from "@/lib/utils";
import { useAuth } from "@/auth/AuthProvider";
import { Button, Skeleton } from "@/components/ui";

interface ConsentInfo {
  client_name: string;
  app_name?: string;
  app_description?: string;
  scopes: { name: string; display_name: string; description: string }[];
}

export function ConsentPage() {
  const [params] = useSearchParams();
  const { me } = useAuth();
  const clientID = params.get("client_id") || "";
  const scope = params.get("scope") || "";
  const ret = params.get("return") || "";
  const [info, setInfo] = React.useState<ConsentInfo | null>(null);
  const [error, setError] = React.useState("");
  const [deciding, setDeciding] = React.useState<"approve" | "deny" | null>(null);

  React.useEffect(() => {
    api
      .get<ConsentInfo>(`/api/v1/oauth/consent-info?client_id=${encodeURIComponent(clientID)}&scope=${encodeURIComponent(scope)}`)
      .then((r) => setInfo(r.data))
      .catch((e) => setError(errorMessage(e)));
  }, [clientID, scope]);

  async function decide(approve: boolean) {
    if (deciding) return;
    setDeciding(approve ? "approve" : "deny");
    try {
      const resp = await api.post<{ consent_token?: string }>("/api/v1/oauth/consent", {
        client_id: clientID,
        scopes: scope.split(" ").filter(Boolean),
        approve,
      });
      const safe = safeReturnPath(ret);
      const token = resp.data?.consent_token;
      if (safe && token) {
        // Both approval AND denial go back through the authorize endpoint, so
        // the relying party gets a definite answer (code or access_denied)
        // instead of a hanging login flow.
        const sep = safe.includes("?") ? "&" : "?";
        window.location.href = `${safe}${sep}consent_token=${encodeURIComponent(token)}`;
      } else {
        window.location.href = "/account";
      }
    } catch (e) {
      setError(errorMessage(e));
      setDeciding(null);
    }
  }

  const appName = info?.app_name || info?.client_name || clientID;

  return (
    <div className="bg-grid flex min-h-screen items-center justify-center p-4">
      <div className="bracket-frame w-full max-w-md rounded-lg border bg-card p-7 shadow-[0_2px_16px_hsl(var(--foreground)/0.05)]">
        <div className="stagger">
          <div className="mono-label mb-4 flex items-center gap-2 text-muted-foreground">
            <ShieldCheck className="h-3.5 w-3.5 text-primary" />
            authorization request · 授权请求
          </div>

          <div className="flex items-start gap-3">
            <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-md brand-gradient font-mono text-lg font-semibold text-white">
              {appName ? appName.slice(0, 1).toUpperCase() : "?"}
            </span>
            <div className="min-w-0">
              {info ? (
                <>
                  <div className="truncate text-base font-semibold">{appName}</div>
                  {info.app_description && <div className="mt-0.5 text-xs text-muted-foreground">{info.app_description}</div>}
                  {info.app_name && info.client_name && info.app_name !== info.client_name && (
                    <div className="mt-0.5 font-mono text-xs text-muted-foreground">client: {info.client_name}</div>
                  )}
                </>
              ) : (
                <div className="space-y-1.5 pt-0.5">
                  <Skeleton className="h-4 w-36" />
                  <Skeleton className="h-3 w-48" />
                </div>
              )}
            </div>
          </div>

          <p className="mt-4 text-sm text-muted-foreground">
            请求以 <b className="font-mono text-foreground">{me?.user.username}</b> 的身份访问以下信息：
          </p>

          {error && (
            <div className="mt-3 rounded-md border border-destructive/30 bg-destructive/8 px-3 py-2 text-sm text-destructive">{error}</div>
          )}

          <ul className="mt-3 space-y-2">
            {info
              ? info.scopes.map((s) => (
                  <li key={s.name} className="rounded-md border bg-background/40 p-3">
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="text-sm font-medium">{s.display_name}</span>
                      <span className="shrink-0 font-mono text-[11px] text-muted-foreground/70">{s.name}</span>
                    </div>
                    {s.description && <div className="mt-0.5 text-xs text-muted-foreground">{s.description}</div>}
                  </li>
                ))
              : [0, 1].map((i) => <Skeleton key={i} className="h-14" />)}
          </ul>

          <div className="mt-6 flex gap-2">
            <Button
              variant="outline"
              className="flex-1"
              onClick={() => decide(false)}
              disabled={!info || deciding === "approve"}
              loading={deciding === "deny"}
            >
              拒绝
            </Button>
            <Button
              className="flex-1"
              onClick={() => decide(true)}
              disabled={!info || deciding === "deny"}
              loading={deciding === "approve"}
            >
              同意授权
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
