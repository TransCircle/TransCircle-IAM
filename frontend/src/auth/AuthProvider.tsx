import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Me } from "@/lib/types";

interface AuthState {
  me: Me | null;
  loading: boolean;
  error: unknown;
  refresh: () => void;
  hasPermission: (perm: string) => boolean;
  isSuperAdmin: boolean;
}

const Ctx = React.createContext<AuthState>({
  me: null,
  loading: true,
  error: null,
  refresh: () => {},
  hasPermission: () => false,
  isSuperAdmin: false,
});

export function useAuth() {
  return React.useContext(Ctx);
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery<Me>({
    queryKey: ["me"],
    queryFn: async () => (await api.get<Me>("/api/v1/me")).data,
    retry: false,
    refetchOnWindowFocus: false,
  });

  const value: AuthState = {
    me: data ?? null,
    loading: isLoading,
    error,
    refresh: () => qc.invalidateQueries({ queryKey: ["me"] }),
    hasPermission: (perm: string) => !!data?.permissions?.includes(perm),
    isSuperAdmin: !!data?.is_super_admin,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
