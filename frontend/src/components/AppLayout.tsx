import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  LayoutDashboard, Users, UsersRound, AppWindow, KeyRound, ScrollText,
  Settings, ShieldCheck, UserCircle, LogOut, Boxes, Cpu,
} from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Button } from "./ui";
import { ThemeToggle } from "./ThemeToggle";

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  perm?: string;
}

const accountNav: NavItem[] = [
  { to: "/account", label: "个人资料", icon: UserCircle },
  { to: "/account/security", label: "安全与 MFA", icon: ShieldCheck },
  { to: "/account/sessions", label: "我的会话", icon: KeyRound },
];

const adminNav: NavItem[] = [
  { to: "/admin/dashboard", label: "概览", icon: LayoutDashboard, perm: "iam.users.read" },
  { to: "/admin/users", label: "用户", icon: Users, perm: "iam.users.read" },
  { to: "/admin/groups", label: "身份组", icon: UsersRound, perm: "iam.groups.read" },
  { to: "/admin/applications", label: "应用", icon: AppWindow, perm: "iam.applications.read" },
  { to: "/admin/clients", label: "OIDC 客户端", icon: Boxes, perm: "iam.clients.read" },
  { to: "/admin/audit", label: "审计日志", icon: ScrollText, perm: "iam.audit.read" },
  { to: "/admin/api-tokens", label: "API 令牌", icon: Cpu, perm: "iam.apptokens.read" },
  { to: "/admin/security", label: "安全密钥", icon: KeyRound, perm: "iam.security.read" },
  { to: "/admin/settings", label: "系统设置", icon: Settings, perm: "iam.settings.read" },
];

function NavSection({ title, items }: { title: string; items: NavItem[] }) {
  return (
    <div className="space-y-1">
      <p className="px-3 pb-1 pt-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">{title}</p>
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.to === "/account"}
          className={({ isActive }) =>
            cn(
              "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
              isActive ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent hover:text-foreground"
            )
          }
        >
          <item.icon className="h-4 w-4" />
          {item.label}
        </NavLink>
      ))}
    </div>
  );
}

export function AppLayout() {
  const { me, hasPermission, refresh } = useAuth();
  const navigate = useNavigate();
  const visibleAdmin = adminNav.filter((i) => !i.perm || hasPermission(i.perm));

  async function logout() {
    await api.post("/api/v1/auth/logout");
    refresh();
    navigate("/login");
  }

  async function stopImpersonation() {
    await api.post("/api/v1/admin/impersonation/stop");
    refresh();
    navigate("/account");
    window.location.reload();
  }

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-64 shrink-0 border-r bg-card/40 p-3 md:block">
        <div className="px-3 py-3">
          <div className="text-lg font-bold tracking-tight">TransCircle</div>
          <div className="text-xs text-muted-foreground">统一身份</div>
        </div>
        <NavSection title="账户" items={accountNav} />
        {visibleAdmin.length > 0 && <NavSection title="管理" items={visibleAdmin} />}
      </aside>

      <div className="flex flex-1 flex-col">
        {me?.impersonator && (
          <div className="flex items-center justify-between bg-amber-500/15 px-4 py-2 text-sm text-amber-700 dark:text-amber-400">
            <span>
              你正以 <b>{me.user.username}</b> 的身份操作（由 {me.impersonator.username} 代登）
            </span>
            <Button size="sm" variant="outline" onClick={stopImpersonation}>
              结束代登
            </Button>
          </div>
        )}
        <header className="flex h-14 items-center justify-between border-b px-6">
          <div className="text-sm text-muted-foreground">{me?.user.display_name || me?.user.username}</div>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <Button variant="ghost" size="sm" onClick={logout}>
              <LogOut className="mr-1 h-4 w-4" /> 退出
            </Button>
          </div>
        </header>
        <main className="flex-1 p-6">
          <div className="mx-auto max-w-6xl">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
