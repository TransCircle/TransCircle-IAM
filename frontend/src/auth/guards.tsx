import * as React from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./AuthProvider";
import { Spinner } from "@/components/ui";

function FullScreenSpinner() {
  return (
    <div className="flex h-screen items-center justify-center">
      <Spinner className="h-6 w-6 text-primary" />
    </div>
  );
}

export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { me, loading } = useAuth();
  const location = useLocation();
  if (loading) return <FullScreenSpinner />;
  if (!me) {
    const ret = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?return=${ret}`} replace />;
  }
  return <>{children}</>;
}

export function RequireOnboarded({ children }: { children: React.ReactNode }) {
  const { me, loading } = useAuth();
  if (loading) return <FullScreenSpinner />;
  if (!me) return <Navigate to="/login" replace />;
  if (me.required_action !== "none") return <Navigate to="/onboarding" replace />;
  return <>{children}</>;
}

export function RequirePermission({ perm, children }: { perm: string; children: React.ReactNode }) {
  const { hasPermission, loading } = useAuth();
  if (loading) return <FullScreenSpinner />;
  if (!hasPermission(perm)) {
    return (
      <div className="rounded-lg border border-dashed p-10 text-center text-sm text-muted-foreground">
        你没有访问该页面的权限（缺少 {perm}）。
      </div>
    );
  }
  return <>{children}</>;
}
