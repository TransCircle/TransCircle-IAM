import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, errorMessage } from "@/lib/api";
import { Button, Card, CardContent, CardHeader, CardTitle, Field, Input, PageHeader, Select, Skeleton, Switch, Textarea } from "@/components/ui";
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
  const { hasPermission, isSuperAdmin } = useAuth();
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

  const policy = useQuery<Record<string, unknown>>({
    queryKey: ["security-policy"],
    queryFn: async () => (await api.get("/api/v1/admin/settings/policy")).data ?? {},
  });
  const emailLock = !!policy.data?.disable_self_email_change;
  const savePolicy = useMutation({
    // Merge into the stored policy object so future policy keys survive the toggle.
    mutationFn: (next: boolean) =>
      api.put("/api/v1/admin/settings/policy", { ...(policy.data ?? {}), disable_self_email_change: next }),
    onSuccess: () => {
      toast("账户策略已更新", "success");
      qc.invalidateQueries({ queryKey: ["security-policy"] });
      qc.invalidateQueries({ queryKey: ["me"] });
    },
    onError: (e) => toast(errorMessage(e), "error"),
  });

  if (rp.isError) {
    return (
      <div>
        <PageHeader title="系统设置" description="WebAuthn 依赖方配置与安全策略。" />
        <div className="bracket-frame rounded-lg border border-dashed bg-card/50 p-10 text-center">
          <p className="text-sm text-muted-foreground">配置加载失败：{errorMessage(rp.error)}</p>
          <Button variant="outline" size="sm" className="mt-3" onClick={() => rp.refetch()}>
            重试
          </Button>
        </div>
      </div>
    );
  }
  if (!form) {
    return (
      <div>
        <PageHeader title="系统设置" description="WebAuthn 依赖方配置与安全策略。" />
        <div className="max-w-2xl space-y-3">
          <Skeleton className="h-10" />
          <Skeleton className="h-10 opacity-80" />
          <Skeleton className="h-24 opacity-60" />
        </div>
      </div>
    );
  }

  return (
    <div className="stagger">
      <PageHeader title="系统设置" description="WebAuthn 依赖方配置与安全策略。" />
      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle>WebAuthn (Passkey) 配置</CardTitle>
          <p className="text-sm text-muted-foreground">修改 RP ID 会使现有通行密钥失效，请谨慎操作。修改后即时生效。</p>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!save.isPending) save.mutate();
            }}
            className="space-y-4"
          >
          <Field label="RP ID" hint="通常是 IAM 的域名，如 iam.transcircle.internal">
            <Input value={form.rp_id} onChange={(e) => setForm({ ...form, rp_id: e.target.value })} disabled={!canWrite} />
          </Field>
          <Field label="显示名称">
            <Input value={form.rp_display_name} onChange={(e) => setForm({ ...form, rp_display_name: e.target.value })} disabled={!canWrite} />
          </Field>
          <Field label="允许的来源 (Origins，每行一个)">
            <Textarea
              value={(form.origins ?? []).join("\n")}
              spellCheck={false}
              onChange={(e) => setForm({ ...form, origins: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean) })}
              disabled={!canWrite}
            />
          </Field>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label="证明方式 (Attestation)" help="一般保持 none 即可，除非需要校验认证器厂商证书。">
              <Select
                value={form.attestation}
                onValueChange={(v) => setForm({ ...form, attestation: v })}
                disabled={!canWrite}
                options={[
                  { value: "none", label: "none（推荐）" },
                  { value: "indirect", label: "indirect" },
                  { value: "direct", label: "direct" },
                ]}
              />
            </Field>
            <Field label="用户验证 (User Verification)" help="required 要求指纹/PIN 等本人验证，安全性最高。">
              <Select
                value={form.user_verification}
                onValueChange={(v) => setForm({ ...form, user_verification: v })}
                disabled={!canWrite}
                options={[
                  { value: "required", label: "required（推荐）" },
                  { value: "preferred", label: "preferred" },
                  { value: "discouraged", label: "discouraged" },
                ]}
              />
            </Field>
          </div>
          {canWrite && (
            <Button type="submit" loading={save.isPending}>保存</Button>
          )}
          </form>
        </CardContent>
      </Card>

      <Card className="mt-6 max-w-2xl">
        <CardHeader>
          <CardTitle>账户策略</CardTitle>
          <p className="text-sm text-muted-foreground">控制全体用户的自助账户行为，仅超级管理员可更改。</p>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between gap-3 rounded-lg border p-3 text-sm">
            <div>
              <div className="font-medium">禁止用户自行修改邮箱</div>
              <p className="mt-0.5 text-xs text-muted-foreground">开启后，邮箱仅能由超级管理员在用户管理中修改，其他人（含管理员）一律只读。</p>
            </div>
            <Switch
              checked={emailLock}
              disabled={!isSuperAdmin || policy.isLoading || policy.isError || savePolicy.isPending}
              onCheckedChange={(v) => savePolicy.mutate(v)}
            />
          </div>
          {policy.isError && <p className="mt-2 text-xs text-muted-foreground">策略加载失败：{errorMessage(policy.error)}</p>}
          {!isSuperAdmin && !policy.isError && <p className="mt-2 text-xs text-muted-foreground">仅超级管理员可更改此策略。</p>}
        </CardContent>
      </Card>
    </div>
  );
}
