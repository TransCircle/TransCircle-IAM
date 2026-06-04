import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage } from "@/lib/api";
import { Button, Card, CardContent, CardHeader, CardTitle, Field, Input, PageHeader, Select } from "@/components/ui";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/auth/AuthProvider";

interface WebAuthnRP {
  rp_id: string;
  rp_display_name: string;
  origins: string[];
  attestation: string;
  user_verification: string;
}

export function SettingsPage() {
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const canWrite = hasPermission("iam.settings.write");

  const rp = useQuery<WebAuthnRP>({
    queryKey: ["webauthn-rp"],
    queryFn: async () => (await api.get("/api/v1/admin/settings/webauthn")).data,
  });
  const [form, setForm] = React.useState<WebAuthnRP | null>(null);
  React.useEffect(() => {
    if (rp.data) setForm(rp.data);
  }, [rp.data]);

  const save = useMutation({
    mutationFn: () => api.put("/api/v1/admin/settings/webauthn", { ...form, origins: form?.origins ?? [] }),
    onSuccess: () => {
      toast("已保存 WebAuthn 配置", "success");
      qc.invalidateQueries({ queryKey: ["webauthn-rp"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  if (!form) return null;

  return (
    <div>
      <PageHeader title="系统设置" description="WebAuthn 依赖方配置与安全策略。" />
      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle>WebAuthn (Passkey) 配置</CardTitle>
          <p className="text-sm text-muted-foreground">修改 RP ID 会使现有通行密钥失效，请谨慎操作。修改后即时生效。</p>
        </CardHeader>
        <CardContent className="space-y-4">
          <Field label="RP ID" hint="通常是 IAM 的域名，如 iam.transcircle.internal">
            <Input value={form.rp_id} onChange={(e) => setForm({ ...form, rp_id: e.target.value })} disabled={!canWrite} />
          </Field>
          <Field label="显示名称">
            <Input value={form.rp_display_name} onChange={(e) => setForm({ ...form, rp_display_name: e.target.value })} disabled={!canWrite} />
          </Field>
          <Field label="允许的来源 (Origins，每行一个)">
            <textarea
              className="flex min-h-[72px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={form.origins.join("\n")}
              onChange={(e) => setForm({ ...form, origins: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean) })}
              disabled={!canWrite}
            />
          </Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Attestation">
              <Select value={form.attestation} onChange={(e) => setForm({ ...form, attestation: e.target.value })} disabled={!canWrite}>
                <option value="none">none</option>
                <option value="indirect">indirect</option>
                <option value="direct">direct</option>
              </Select>
            </Field>
            <Field label="User Verification">
              <Select value={form.user_verification} onChange={(e) => setForm({ ...form, user_verification: e.target.value })} disabled={!canWrite}>
                <option value="required">required</option>
                <option value="preferred">preferred</option>
                <option value="discouraged">discouraged</option>
              </Select>
            </Field>
          </div>
          {canWrite && (
            <Button onClick={() => save.mutate()} loading={save.isPending}>保存</Button>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
