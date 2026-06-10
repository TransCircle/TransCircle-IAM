import { useQuery } from "@tanstack/react-query";
import { Users, AppWindow, Boxes, UsersRound, KeyRound, RotateCw } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Button, Card, PageHeader, Skeleton } from "@/components/ui";

export function DashboardPage() {
  const { data, isLoading, isError, error, refetch } = useQuery<{ stats: Record<string, number> }>({
    queryKey: ["stats"],
    queryFn: async () => (await api.get("/api/v1/admin/stats")).data,
  });
  const stats = data?.stats ?? {};
  const cards = [
    { key: "users", label: "用户", en: "users", value: stats.users, icon: Users },
    { key: "applications", label: "应用", en: "applications", value: stats.applications, icon: AppWindow },
    { key: "clients", label: "OIDC 客户端", en: "oidc clients", value: stats.clients, icon: Boxes },
    { key: "groups", label: "身份组", en: "groups", value: stats.groups, icon: UsersRound },
    { key: "sessions", label: "活跃会话", en: "active sessions", value: stats.sessions, icon: KeyRound, live: true },
  ];
  return (
    <div className="stagger">
      <PageHeader title="概览" description="系统关键指标。" />
      {isError ? (
        <div className="bracket-frame rounded-lg border border-dashed bg-card/50 p-10 text-center">
          <p className="text-sm text-muted-foreground">指标加载失败：{errorMessage(error)}</p>
          <Button variant="outline" size="sm" className="mt-3" onClick={() => refetch()}>
            <RotateCw className="h-3.5 w-3.5" /> 重试
          </Button>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {cards.map((c) => (
            <Card key={c.key} className="bracket-frame group relative overflow-hidden p-5 transition-colors hover:border-primary/40">
              <div className="flex items-start justify-between">
                <div className="min-w-0">
                  <div className="mono-label flex items-center gap-1.5 text-muted-foreground">
                    {c.live && <span className="status-dot" aria-hidden />}
                    {c.en}
                  </div>
                  <div className="mt-0.5 text-[13px] text-muted-foreground">{c.label}</div>
                </div>
                <c.icon className="h-5 w-5 text-primary/50 transition-colors group-hover:text-primary" />
              </div>
              {isLoading ? (
                <Skeleton className="mt-3 h-9 w-20" />
              ) : (
                <div className="mt-2 font-mono text-4xl font-semibold tracking-tight">{c.value ?? "—"}</div>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
