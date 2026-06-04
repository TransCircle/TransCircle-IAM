import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge, Button, PageHeader } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import type { Session } from "@/lib/types";
import { formatDate } from "@/lib/utils";
import { useToast } from "@/components/Toast";

export function MySessionsPage() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const { data, isLoading } = useQuery<{ sessions: Session[]; current: string }>({
    queryKey: ["my-sessions"],
    queryFn: async () => (await api.get("/api/v1/account/sessions")).data,
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/account/sessions/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["my-sessions"] }),
  });
  const revokeOthers = useMutation({
    mutationFn: () => api.post("/api/v1/account/sessions/revoke-others"),
    onSuccess: () => {
      toast("已下线其他会话", "success");
      qc.invalidateQueries({ queryKey: ["my-sessions"] });
    },
  });

  return (
    <div>
      <PageHeader
        title="我的会话"
        description="查看并管理所有登录设备。"
        action={<Button variant="outline" onClick={() => revokeOthers.mutate()}>下线其他会话</Button>}
      />
      <DataTable<Session>
        loading={isLoading}
        rows={data?.sessions}
        rowKey={(s) => s.id}
        columns={[
          {
            header: "设备 / IP",
            cell: (s) => (
              <div>
                <div className="max-w-xs truncate">{s.user_agent || "未知设备"}</div>
                <div className="text-xs text-muted-foreground">{s.ip}</div>
              </div>
            ),
          },
          { header: "认证方式", cell: (s) => (s.amr || []).join(", ") },
          { header: "最近活动", cell: (s) => formatDate(s.last_seen_at) },
          {
            header: "",
            className: "text-right",
            cell: (s) =>
              s.id === data?.current ? (
                <Badge variant="success">当前会话</Badge>
              ) : (
                <Button size="sm" variant="ghost" onClick={() => revoke.mutate(s.id)}>
                  下线
                </Button>
              ),
          },
        ]}
      />
    </div>
  );
}
