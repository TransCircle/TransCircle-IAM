import * as React from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, Field, Input, PageHeader, Textarea } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { Dialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { Application } from "@/lib/types";

export function ApplicationsPage() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.applications.write");
  const [open, setOpen] = React.useState(false);
  const [form, setForm] = React.useState({ key: "", display_name: "", description: "" });

  const apps = useQuery<Application[]>({
    queryKey: ["applications"],
    queryFn: async () => (await api.get("/api/v1/admin/applications")).data.applications ?? [],
  });

  const create = useMutation({
    mutationFn: () => api.post("/api/v1/admin/applications", { ...form, is_active: true }),
    onSuccess: () => {
      setOpen(false);
      setForm({ key: "", display_name: "", description: "" });
      qc.invalidateQueries({ queryKey: ["applications"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const del = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/admin/applications/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["applications"] }),
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <div>
      <PageHeader
        title="应用"
        description="每个应用是一个独立的权限作用域。"
        action={canWrite && <Button onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> 新建应用</Button>}
      />
      <DataTable<Application>
        loading={apps.isLoading}
        rows={apps.data}
        rowKey={(a) => a.id}
        columns={[
          {
            header: "名称",
            cell: (a) => (
              <Link to={`/admin/applications/${a.id}`} className="font-medium text-primary hover:underline">
                {a.display_name}
              </Link>
            ),
          },
          { header: "标识", cell: (a) => <Badge variant="muted">{a.key}</Badge> },
          { header: "类型", cell: (a) => (a.is_system ? <Badge>系统内置</Badge> : "应用") },
          { header: "状态", cell: (a) => (a.is_active ? <Badge variant="success">启用</Badge> : <Badge variant="muted">停用</Badge>) },
          {
            header: "",
            className: "text-right",
            cell: (a) =>
              canWrite && !a.is_system && (
                <Button size="icon" variant="ghost" onClick={() => del.mutate(a.id)}><Trash2 className="h-4 w-4" /></Button>
              ),
          },
        ]}
      />

      <Dialog open={open} onClose={() => setOpen(false)} title="新建应用"
        footer={<><Button variant="outline" onClick={() => setOpen(false)}>取消</Button><Button onClick={() => create.mutate()} loading={create.isPending}>创建</Button></>}>
        <div className="space-y-4">
          <Field label="标识 (key)" hint="唯一英文标识，如 wiki、grafana" help="创建后作为 OIDC 客户端绑定与权限查询 API 的应用标识，建议用小写字母/数字。">
            <Input value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} />
          </Field>
          <Field label="名称"><Input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
          <Field label="描述"><Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        </div>
      </Dialog>
    </div>
  );
}
