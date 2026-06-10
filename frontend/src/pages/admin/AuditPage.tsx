import * as React from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge, Input, PageHeader, Pager, RelativeTime, Select, useDebounced } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { auditActionLabel, auditTargetText } from "@/lib/audit";
import type { AuditEntry } from "@/lib/types";


export function AuditPage() {
  const [action, setAction] = React.useState("");
  const [result, setResult] = React.useState("");
  const [offset, setOffset] = React.useState(0);

  const limit = 50;
  const debouncedAction = useDebounced(action);
  React.useEffect(() => setOffset(0), [debouncedAction, result]);

  const { data, isLoading } = useQuery<{ entries: AuditEntry[] }>({
    queryKey: ["audit", debouncedAction, result, offset],
    queryFn: async () =>
      (
        await api.get(
          `/api/v1/admin/audit?action=${encodeURIComponent(debouncedAction)}&result=${encodeURIComponent(result)}&limit=${limit}&offset=${offset}`
        )
      ).data,
    placeholderData: keepPreviousData,
  });

  return (
    <div>
      <PageHeader title="审计日志" description="所有管理与安全操作的不可篡改记录。" />
      <div className="mb-4 flex flex-wrap gap-3">
        <Input className="max-w-xs" placeholder="按动作关键字过滤，如 iam.user / login / mfa" value={action} onChange={(e) => setAction(e.target.value)} />
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
          { header: "时间", className: "whitespace-nowrap text-muted-foreground", cell: (e) => <RelativeTime value={e.occurred_at} /> },
          { header: "操作者", className: "whitespace-nowrap", cell: (e) => e.actor_label || "—" },
          { header: "动作", className: "whitespace-nowrap font-medium", cell: (e) => <span title={e.action}>{auditActionLabel(e.action)}</span> },
          { header: "对象", cell: (e) => <span title={e.target_id}>{auditTargetText(e)}</span> },
          {
            header: "结果",
            className: "whitespace-nowrap",
            cell: (e) =>
              e.result === "success" ? <Badge variant="success">成功</Badge> :
              e.result === "denied" ? <Badge variant="destructive">拒绝</Badge> :
              <Badge variant="muted">失败</Badge>,
          },
          { header: "IP", className: "whitespace-nowrap font-mono text-[13px]", cell: (e) => e.ip || "—" },
        ]}
      />
      <Pager
        offset={offset}
        limit={limit}
        count={data?.entries.length ?? 0}
        hasMore={(data?.entries.length ?? 0) === limit}
        onOffsetChange={setOffset}
      />
    </div>
  );
}
