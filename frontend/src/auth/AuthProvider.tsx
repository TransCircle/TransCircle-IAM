import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, onAuthExpired } from "@/lib/api";
import type { Me } from "@/lib/types";

interface AuthState {
  me: Me | null;
  loading: boolean;
  error: unknown;
  // refresh resolves once /me has actually been refetched — await it before
  // navigating into a guarded route right after login/logout.
  refresh: () => Promise<unknown>;
  hasPermission: (perm: string) => boolean;
  isSuperAdmin: boolean;
}

const Ctx = React.createContext<AuthState>({
  me: null,
  loading: true,
  error: null,
  refresh: async () => {},
  hasPermission: () => false,
  isSuperAdmin: false,
});

export function useAuth() {
  return React.useContext(Ctx);
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const qc = useQueryClient();
  const { data, isLoading, isFetching, error } = useQuery<Me>({
    queryKey: ["me"],
    queryFn: async () => (await api.get<Me>("/api/v1/me")).data,
    retry: false,
    refetchOnWindowFocus: false,
  });

  React.useEffect(
    () =>
      onAuthExpired(() => {
        void qc.cancelQueries({ queryKey: ["me"] });
        qc.removeQueries({ queryKey: ["me"] });
        window.location.assign("/login?reason=session_expired");
      }),
    [qc],
  );

  const value: AuthState = {
    me: data ?? null,
    // A refetch after a 401 (post-login) has isLoading=false but no data yet;
    // treat it as loading so guards don't bounce the user back to /login.
    loading: isLoading || (isFetching && !data),
    error,
    refresh: () => qc.refetchQueries({ queryKey: ["me"] }),
    hasPermission: (perm: string) => !!data?.permissions?.includes(perm),
    isSuperAdmin: !!data?.is_super_admin,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
