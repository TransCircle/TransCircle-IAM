import * as React from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, Field, Input, PageHeader, Textarea } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { Dialog, ConfirmDialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { Group } from "@/lib/types";

export function GroupsPage() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const canWrite = hasPermission("iam.groups.write");
  const [open, setOpen] = React.useState(false);
  const [confirm, setConfirm] = React.useState<Group | null>(null);
  const [form, setForm] = React.useState({ key: "", display_name: "", description: "" });

  // Reset the draft on close so a cancelled form doesn't reappear next time.
  React.useEffect(() => {
    if (!open) setForm({ key: "", display_name: "", description: "" });
  }, [open]);

  const groups = useQuery<Group[]>({
    queryKey: ["groups"],
    queryFn: async () => (await api.get("/api/v1/admin/groups")).data.groups ?? [],
  });

  const create = useMutation({
    mutationFn: () => api.post("/api/v1/admin/groups", form),
    onSuccess: () => {
      setOpen(false);
      setForm({ key: "", display_name: "", description: "" });
      qc.invalidateQueries({ queryKey: ["groups"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });
  const del = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/admin/groups/${id}`),
    onSuccess: () => {
      setConfirm(null);
      qc.invalidateQueries({ queryKey: ["groups"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  function submitCreate() {
    if (!form.key.trim() || !form.display_name.trim()) {
      toast("Key 与名称必填", "error");
      return;
    }
    create.mutate();
  }

  return (
    <div>
      <PageHeader
        title="身份组"
        description="身份组将一组角色批量授予其成员。点击任一身份组进入详情可编辑并管理其角色。"
        action={canWrite && <Button onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> 新建身份组</Button>}
      />
      <DataTable<Group>
        loading={groups.isLoading}
        error={groups.isError ? groups.error : undefined}
        onRetry={() => groups.refetch()}
        rows={groups.data}
        rowKey={(g) => g.id}
        onRowClick={(g) => navigate(`/admin/groups/${g.id}`)}
        columns={[
          { header: "名称", cell: (g) => <span className="font-medium">{g.display_name}</span> },
          { header: "标识", cell: (g) => <Badge variant="muted">{g.key}</Badge> },
          { header: "描述", cell: (g) => g.description || "—" },
          {
            header: "",
            className: "text-right",
            cell: (g) =>
              canWrite && !g.is_system ? (
                <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                  <Button size="icon" variant="ghost" title="删除" onClick={() => setConfirm(g)}><Trash2 className="h-4 w-4" /></Button>
                </div>
              ) : null,
          },
        ]}
      />

      <Dialog open={open} onClose={() => setOpen(false)} title="新建身份组" onSubmit={submitCreate} submitting={create.isPending}
        footer={<><Button variant="outline" type="button" onClick={() => setOpen(false)}>取消</Button><Button type="submit" loading={create.isPending}>创建</Button></>}>
        <div className="space-y-4">
          <Field label="Key"><Input value={form.key} autoFocus onChange={(e) => setForm({ ...form, key: e.target.value })} /></Field>
          <Field label="名称"><Input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
          <Field label="描述"><Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        </div>
      </Dialog>

      <ConfirmDialog
        open={!!confirm}
        onClose={() => setConfirm(null)}
        onConfirm={() => confirm && del.mutate(confirm.id)}
        title={`删除身份组「${confirm?.display_name}」?`}
        description="删除后组成员将失去该组授予的角色。"
        confirmLabel="删除"
        destructive
        loading={del.isPending}
      />
    </div>
  );
}
