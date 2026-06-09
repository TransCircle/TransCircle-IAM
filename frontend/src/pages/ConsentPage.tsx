import * as React from "react";
import { useSearchParams } from "react-router-dom";
import { api, errorMessage } from "@/lib/api";
import { safeReturnPath } from "@/lib/utils";
import { useAuth } from "@/auth/AuthProvider";
import { Button, Card, CardContent, CardHeader, CardTitle } from "@/components/ui";

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
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    api
      .get<ConsentInfo>(`/api/v1/oauth/consent-info?client_id=${encodeURIComponent(clientID)}&scope=${encodeURIComponent(scope)}`)
      .then((r) => setInfo(r.data))
      .catch((e) => setError(errorMessage(e)));
  }, [clientID, scope]);

  async function decide(approve: boolean) {
    setLoading(true);
    try {
      const resp = await api.post<{ consent_token?: string }>("/api/v1/oauth/consent", {
        client_id: clientID,
        scopes: scope.split(" ").filter(Boolean),
        approve,
      });
      const safe = safeReturnPath(ret);
      if (approve && safe) {
        // Carry the one-time consent ticket back to the authorize endpoint so it
        // completes exactly this request (a fresh authorization re-prompts).
        const token = resp.data?.consent_token;
        const sep = safe.includes("?") ? "&" : "?";
        window.location.href = token ? `${safe}${sep}consent_token=${encodeURIComponent(token)}` : safe;
      } else {
        window.location.href = "/account";
      }
    } catch (e) {
      setError(errorMessage(e));
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/30 p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>授权请求</CardTitle>
          {(() => {
            const appName = info?.app_name || info?.client_name || clientID;
            return (
              <div className="flex items-start gap-3 pt-1">
                <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl brand-gradient text-lg font-semibold text-white">
                  {appName.slice(0, 1).toUpperCase()}
                </span>
                <div className="min-w-0">
                  <div className="truncate text-base font-semibold">{appName}</div>
                  {info?.app_description && <div className="text-xs text-muted-foreground">{info.app_description}</div>}
                  {info?.app_name && info.client_name && info.app_name !== info.client_name && (
                    <div className="mt-0.5 text-xs text-muted-foreground">客户端：{info.client_name}</div>
                  )}
                </div>
              </div>
            );
          })()}
          <p className="pt-2 text-sm text-muted-foreground">
            请求以 <b>{me?.user.username}</b> 的身份访问以下信息：
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</div>}
          <ul className="space-y-2">
            {info?.scopes.map((s) => (
              <li key={s.name} className="rounded-md border p-3">
                <div className="text-sm font-medium">{s.display_name}</div>
                {s.description && <div className="text-xs text-muted-foreground">{s.description}</div>}
              </li>
            ))}
          </ul>
          <div className="flex gap-2">
            <Button variant="outline" className="flex-1" onClick={() => decide(false)} disabled={loading}>
              拒绝
            </Button>
            <Button className="flex-1" onClick={() => decide(true)} loading={loading}>
              同意授权
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
