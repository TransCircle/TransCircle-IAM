import * as React from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { RotateCcw } from "lucide-react";
import { api } from "@/lib/api";
import { Badge, Button, Input, Label, PageHeader, Pager, RelativeTime, Select, useDebounced } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { auditActionLabel, auditTargetText } from "@/lib/audit";
import type { AuditEntry } from "@/lib/types";

// Action categories map a friendly label to the substring the backend matches
// (ILIKE %action%), so admins can narrow by area without memorising action keys.
const CATEGORIES: { value: string; label: string }[] = [
  { value: "", label: "全部分类" },
  { value: "login", label: "登录" },
  { value: "logout", label: "退出登录" },
  { value: "auth.stepup", label: "二次验证" },
  { value: "mfa.", label: "多因素 (MFA)" },
  { value: "mfa.verify", label: "两步验证接口" },
  { value: "impersonate", label: "代登" },
  { value: "oauth", label: "OAuth / 登录授权" },
  { value: "iam.user", label: "用户管理" },
  { value: "iam.group", label: "身份组管理" },
  { value: "iam.role", label: "角色管理" },
  { value: "iam.permission", label: "权限管理" },
  { value: "iam.application", label: "应用管理" },
  { value: "iam.client", label: "OIDC 客户端" },
  { value: "iam.apptoken", label: "API 令牌" },
  { value: "iam.session", label: "会话管理" },
  { value: "iam.settings", label: "系统设置" },
  { value: "iam.security", label: "密钥与安全" },
];

// toRFC3339 converts a <input type=datetime-local> value (local, no tz) to the
// RFC3339 instant the backend's since/until filters expect.
function toRFC3339(local: string): string {
  if (!local) return "";
  const d = new Date(local);
  return isNaN(d.getTime()) ? "" : d.toISOString();
}

export function AuditPage() {
  const [category, setCategory] = React.useState("");
  const [action, setAction] = React.useState("");
  const [actor, setActor] = React.useState("");
  const [result, setResult] = React.useState("");
  const [since, setSince] = React.useState("");
  const [until, setUntil] = React.useState("");
  const [offset, setOffset] = React.useState(0);

  const limit = 50;
  // The effective action filter prefers an explicitly typed keyword, falling
  // back to the chosen category.
  const effectiveAction = action.trim() || category;
  const debouncedAction = useDebounced(effectiveAction);
  const debouncedActor = useDebounced(actor);
  const sinceISO = toRFC3339(since);
  const untilISO = toRFC3339(until);

  React.useEffect(() => setOffset(0), [debouncedAction, debouncedActor, result, sinceISO, untilISO]);

  const { data, isLoading, isError, error, refetch } = useQuery<{ entries: AuditEntry[] }>({
    queryKey: ["audit", debouncedAction, debouncedActor, result, sinceISO, untilISO, offset],
    queryFn: async () => {
      const q = new URLSearchParams({
        action: debouncedAction,
        actor: debouncedActor,
        result,
        limit: String(limit),
        offset: String(offset),
      });
      if (sinceISO) q.set("since", sinceISO);
      if (untilISO) q.set("until", untilISO);
      return (await api.get(`/api/v1/admin/audit?${q.toString()}`)).data;
    },
    placeholderData: keepPreviousData,
  });

  const hasFilters = !!(category || action || actor || result || since || until);
  function reset() {
    setCategory("");
    setAction("");
    setActor("");
    setResult("");
    setSince("");
    setUntil("");
  }

  return (
    <div>
      <PageHeader title="审计日志" description="所有管理与安全操作的不可篡改记录。" />

      <div className="mb-4 grid gap-3 rounded-lg border bg-card/50 p-4 sm:grid-cols-2 lg:grid-cols-3">
        <div className="space-y-1.5">
          <Label>分类</Label>
          <Select value={category} onValueChange={setCategory} options={CATEGORIES} />
        </div>
        <div className="space-y-1.5">
          <Label>动作关键字</Label>
          <Input placeholder="如 iam.user.delete / login.success" value={action} onChange={(e) => setAction(e.target.value)} />
        </div>
        <div className="space-y-1.5">
          <Label>操作者</Label>
          <Input placeholder="用户名 / 令牌名" value={actor} onChange={(e) => setActor(e.target.value)} />
        </div>
        <div className="space-y-1.5">
          <Label>结果</Label>
          <Select
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
        <div className="space-y-1.5">
          <Label>起始时间</Label>
          <Input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} />
        </div>
        <div className="space-y-1.5">
          <Label>截止时间</Label>
          <Input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} />
        </div>
        {hasFilters && (
          <div className="flex items-end sm:col-span-2 lg:col-span-3">
            <Button variant="ghost" size="sm" onClick={reset}>
              <RotateCcw className="h-3.5 w-3.5" /> 清除筛选
            </Button>
          </div>
        )}
      </div>

      <DataTable<AuditEntry>
        loading={isLoading}
        error={isError ? error : undefined}
        onRetry={() => refetch()}
        rows={data?.entries}
        rowKey={(e) => e.id}
        columns={[
          { header: "时间", className: "whitespace-nowrap text-muted-foreground", cell: (e) => <RelativeTime value={e.occurred_at} /> },
          {
            header: "操作者",
            className: "whitespace-nowrap",
            cell: (e) => (
              <span className="flex items-center gap-1.5">
                {e.actor_label || "—"}
                {e.impersonator_user_id && (
                  <Badge variant="warning" title={`代登：操作由管理员 ${e.impersonator_user_id} 以该用户身份发起`}>
                    代登
                  </Badge>
                )}
              </span>
            ),
          },
          { header: "动作", className: "whitespace-nowrap font-medium", cell: (e) => <span title={e.action}>{auditActionLabel(e.action)}</span> },
          { header: "对象", cell: (e) => <span title={e.target_id}>{auditTargetText(e)}</span> },
          {
            header: "结果",
            className: "whitespace-nowrap",
            cell: (e) =>
              e.result === "success" ? <Badge variant="success">成功</Badge> : e.result === "denied" ? <Badge variant="destructive">拒绝</Badge> : <Badge variant="muted">失败</Badge>,
          },
          { header: "IP", className: "whitespace-nowrap font-mono text-[13px]", cell: (e) => e.ip || "—" },
        ]}
      />
      <Pager offset={offset} limit={limit} count={data?.entries?.length ?? 0} hasMore={(data?.entries?.length ?? 0) === limit} onOffsetChange={setOffset} />
    </div>
  );
}
