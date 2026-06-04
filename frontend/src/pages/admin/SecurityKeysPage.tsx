import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, PageHeader } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { SigningKeyInfo } from "@/lib/types";
import { formatDate } from "@/lib/utils";

export function SecurityKeysPage() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canRotate = hasPermission("iam.security.rotate");

  const { data, isLoading } = useQuery<{ signing_keys: SigningKeyInfo[]; active_dek_version: number }>({
    queryKey: ["security-keys"],
    queryFn: async () => (await api.get("/api/v1/admin/security/keys")).data,
  });

  const rotate = useMutation({
    mutationFn: () => api.post("/api/v1/admin/security/keys/rotate"),
    onSuccess: () => {
      toast("签名密钥已轮换", "success");
      qc.invalidateQueries({ queryKey: ["security-keys"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <div>
      <PageHeader
        title="安全密钥"
        description="OIDC 签名密钥与数据加密密钥 (DEK) 状态。"
        action={canRotate && <Button onClick={() => rotate.mutate()} loading={rotate.isPending}>轮换签名密钥</Button>}
      />
      <Card className="mb-4">
        <CardHeader><CardTitle>数据加密密钥 (DEK)</CardTitle></CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          当前活跃 DEK 版本：<b className="text-foreground">v{data?.active_dek_version ?? "—"}</b>。所有入库秘密均以 AES-256-GCM 加密保存。
        </CardContent>
      </Card>
      <DataTable<SigningKeyInfo>
        loading={isLoading}
        rows={data?.signing_keys}
        rowKey={(k) => k.kid}
        columns={[
          { header: "KID", cell: (k) => <code className="text-xs">{k.kid}</code> },
          { header: "算法", cell: (k) => k.algorithm },
          {
            header: "状态",
            cell: (k) =>
              k.status === "active" ? <Badge variant="success">活跃</Badge> :
              k.status === "previous" ? <Badge>上一版</Badge> :
              <Badge variant="muted">已退役</Badge>,
          },
          { header: "创建时间", cell: (k) => formatDate(k.created_at) },
        ]}
      />
    </div>
  );
}
