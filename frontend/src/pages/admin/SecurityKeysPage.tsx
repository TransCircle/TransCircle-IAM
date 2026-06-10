import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage } from "@/lib/api";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, PageHeader, RelativeTime } from "@/components/ui";
import { DataTable } from "@/components/DataTable";
import { ConfirmDialog } from "@/components/Dialog";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";
import type { SigningKeyInfo } from "@/lib/types";


export function SecurityKeysPage() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canRotate = hasPermission("iam.security.rotate");
  const [confirmRotate, setConfirmRotate] = React.useState(false);

  const { data, isLoading } = useQuery<{ signing_keys: SigningKeyInfo[]; active_dek_version: number }>({
    queryKey: ["security-keys"],
    queryFn: async () => (await api.get("/api/v1/admin/security/keys")).data,
  });

  const rotate = useMutation({
    mutationFn: () => api.post("/api/v1/admin/security/keys/rotate"),
    onSuccess: () => {
      setConfirmRotate(false);
      toast("签名密钥已轮换", "success");
      qc.invalidateQueries({ queryKey: ["security-keys"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  return (
    <div className="stagger">
      <PageHeader
        title="安全密钥"
        description="OIDC 签名密钥与数据加密密钥 (DEK) 状态。"
        action={canRotate && <Button onClick={() => setConfirmRotate(true)}>轮换签名密钥</Button>}
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
          { header: "KID", cell: (k) => <code className="font-mono text-xs">{k.kid}</code> },
          { header: "算法", className: "font-mono text-[13px]", cell: (k) => k.algorithm },
          {
            header: "状态",
            cell: (k) =>
              k.status === "active" ? <Badge variant="success">活跃</Badge> :
              k.status === "previous" ? <Badge>上一版</Badge> :
              <Badge variant="muted">已退役</Badge>,
          },
          { header: "创建时间", cell: (k) => <RelativeTime value={k.created_at} /> },
        ]}
      />
      <ConfirmDialog
        open={confirmRotate}
        onClose={() => setConfirmRotate(false)}
        onConfirm={() => rotate.mutate()}
        loading={rotate.isPending}
        title="轮换 OIDC 签名密钥？"
        description="将生成新的活跃签名密钥；旧密钥进入「上一版」继续用于验签，已签发令牌不受影响。"
        confirmLabel="轮换"
      />
    </div>
  );
}
