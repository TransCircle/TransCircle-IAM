import { useQuery } from "@tanstack/react-query";
import { Users, AppWindow, Boxes, UsersRound, KeyRound } from "lucide-react";
import { api } from "@/lib/api";
import { Card, CardContent, PageHeader } from "@/components/ui";

export function DashboardPage() {
  const { data } = useQuery<{ stats: Record<string, number> }>({
    queryKey: ["stats"],
    queryFn: async () => (await api.get("/api/v1/admin/stats")).data,
  });
  const stats = data?.stats ?? {};
  const cards = [
    { label: "用户", value: stats.users, icon: Users },
    { label: "应用", value: stats.applications, icon: AppWindow },
    { label: "OIDC 客户端", value: stats.clients, icon: Boxes },
    { label: "身份组", value: stats.groups, icon: UsersRound },
    { label: "活跃会话", value: stats.sessions, icon: KeyRound },
  ];
  return (
    <div>
      <PageHeader title="概览" description="系统关键指标。" />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {cards.map((c) => (
          <Card key={c.label}>
            <CardContent className="flex items-center justify-between p-6">
              <div>
                <div className="text-sm text-muted-foreground">{c.label}</div>
                <div className="mt-1 text-3xl font-semibold">{c.value ?? "—"}</div>
              </div>
              <c.icon className="h-8 w-8 text-primary/70" />
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
