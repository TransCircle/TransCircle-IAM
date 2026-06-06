import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge, Input, PageHeader, RelativeTime, Select } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import type { AuditEntry } from "@/lib/types";


export function AuditPage() {
  const [action, setAction] = React.useState("");
  const [result, setResult] = React.useState("");

  const { data, isLoading } = useQuery<{ entries: AuditEntry[] }>({
    queryKey: ["audit", action, result],
    queryFn: async () =>
      (await api.get(`/api/v1/admin/audit?action=${encodeURIComponent(action)}&result=${encodeURIComponent(result)}&limit=100`)).data,
  });

  return (
    <div>
      <PageHeader title="审计日志" description="所有管理与安全操作的不可篡改记录。" />
      <div className="mb-4 flex flex-wrap gap-3">
        <Input className="max-w-xs" placeholder="按操作过滤，如 iam.user" value={action} onChange={(e) => setAction(e.target.value)} />
        <Select
          className="w-40"
          value={result}
          onValueChange={setResult}
          options={[
            { value: "", label: "全部结果" },
            { value: "success", label: "成功" },
            { value: "failure", label: "失败" },
            { value: "denied", label: "拒绝" },
          ]}
        />
      </div>
      <DataTable<AuditEntry>
        loading={isLoading}
        rows={data?.entries}
        rowKey={(e) => e.id}
        columns={[
          { header: "时间", cell: (e) => <RelativeTime value={e.occurred_at} /> },
          { header: "操作者", cell: (e) => e.actor_label || "—" },
          { header: "动作", cell: (e) => <code className="text-xs">{e.action}</code> },
          { header: "对象", cell: (e) => (e.target_type ? `${e.target_type}:${e.target_id.slice(0, 8)}` : "—") },
          {
            header: "结果",
            cell: (e) =>
              e.result === "success" ? <Badge variant="success">成功</Badge> :
              e.result === "denied" ? <Badge variant="destructive">拒绝</Badge> :
              <Badge variant="muted">失败</Badge>,
          },
          { header: "IP", cell: (e) => e.ip || "—" },
        ]}
      />
    </div>
  );
}
