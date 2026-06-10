import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, PageHeader, RelativeTime } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { ConfirmDialog } from "@/components/Dialog";
import type { Session } from "@/lib/types";
import { useToast } from "@/components/Toast";

const amrLabels: Record<string, string> = {
  pwd: "密码",
  otp: "动态口令",
  totp: "动态口令",
  webauthn: "通行密钥",
  recovery: "恢复码",
};

export function MySessionsPage() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [confirmOthers, setConfirmOthers] = React.useState(false);
  const { data, isLoading, isError, error, refetch } = useQuery<{ sessions: Session[]; current: string }>({
    queryKey: ["my-sessions"],
    queryFn: async () => (await api.get("/api/v1/account/sessions")).data,
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/account/sessions/${id}`),
    onSuccess: () => {
      toast("会话已下线", "success");
      qc.invalidateQueries({ queryKey: ["my-sessions"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const revokeOthers = useMutation({
    mutationFn: () => api.post("/api/v1/account/sessions/revoke-others"),
    onSuccess: () => {
      setConfirmOthers(false);
      toast("已下线其他会话", "success");
      qc.invalidateQueries({ queryKey: ["my-sessions"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <div className="stagger">
      <PageHeader
        title="我的会话"
        description="查看并管理所有登录设备。"
        action={
          <Button variant="outline" onClick={() => setConfirmOthers(true)}>
            下线其他会话
          </Button>
        }
      />
      <DataTable<Session>
        loading={isLoading}
        error={isError ? error : undefined}
        onRetry={() => refetch()}
        rows={data?.sessions}
        rowKey={(s) => s.id}
        columns={[
          {
            header: "设备 / IP",
            cell: (s) => (
              <div>
                <div className="max-w-xs truncate">{s.user_agent || "未知设备"}</div>
                <div className="font-mono text-xs text-muted-foreground">{s.ip}</div>
              </div>
            ),
          },
          {
            header: "认证方式",
            cell: (s) => (s.amr || []).map((m) => amrLabels[m] || m).join(" + ") || "—",
          },
          { header: "最近活动", className: "text-muted-foreground", cell: (s) => <RelativeTime value={s.last_seen_at} /> },
          {
            header: "",
            className: "text-right",
            cell: (s) =>
              s.id === data?.current ? (
                <Badge variant="success">
                  <span className="status-dot" aria-hidden /> 当前会话
                </Badge>
              ) : (
                <Button
                  size="sm"
                  variant="ghost"
                  loading={revoke.isPending && revoke.variables === s.id}
                  onClick={() => revoke.mutate(s.id)}
                >
                  下线
                </Button>
              ),
          },
        ]}
      />
      <ConfirmDialog
        open={confirmOthers}
        onClose={() => setConfirmOthers(false)}
        onConfirm={() => revokeOthers.mutate()}
        loading={revokeOthers.isPending}
        title="下线其他会话"
        description="除当前设备外，所有已登录设备都将被立即登出。"
        confirmLabel="全部下线"
        destructive
      />
    </div>
  );
}
