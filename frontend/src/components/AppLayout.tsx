import * as React from "react";
import { NavLink, Outlet, useNavigate, useLocation } from "react-router-dom";
import {
  LayoutDashboard, Users, UsersRound, AppWindow, KeyRound, ScrollText,
  Settings, ShieldCheck, UserCircle, LogOut, Boxes, Cpu, BookOpen, Menu, X,
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
  end?: boolean;
}

const accountNav: NavItem[] = [
  { to: "/account", label: "个人资料", icon: UserCircle, end: true },
  { to: "/account/security", label: "安全与多因素", icon: ShieldCheck },
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

const docsNav: NavItem[] = [{ to: "/api-docs", label: "对接文档", icon: BookOpen }];

function NavSection({ title, items, onNavigate }: { title: string; items: NavItem[]; onNavigate?: () => void }) {
  if (items.length === 0) return null;
  return (
    <div className="space-y-0.5">
      <p className="px-3 pb-1 pt-4 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/70">{title}</p>
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
              isActive
                ? "bg-primary/10 text-primary"
                : "text-muted-foreground hover:bg-accent hover:text-foreground"
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

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const { hasPermission } = useAuth();
  const visibleAdmin = adminNav.filter((i) => !i.perm || hasPermission(i.perm));
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 px-4 py-4">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <div className="text-sm font-bold leading-tight tracking-tight">TransCircle</div>
          <div className="text-[11px] text-muted-foreground">统一身份</div>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto px-3 pb-4">
        <NavSection title="账户" items={accountNav} onNavigate={onNavigate} />
        <NavSection title="管理" items={visibleAdmin} onNavigate={onNavigate} />
        <NavSection title="文档" items={docsNav} onNavigate={onNavigate} />
      </nav>
    </div>
  );
}

export function AppLayout() {
  const { me, refresh } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [drawer, setDrawer] = React.useState(false);

  React.useEffect(() => {
    setDrawer(false);
  }, [location.pathname]);

  async function logout() {
    await api.post("/api/v1/auth/logout");
    refresh();
    navigate("/login");
  }

  async function stopImpersonation() {
    await api.post("/api/v1/admin/impersonation/stop");
    refresh();
    window.location.href = "/account";
  }

  return (
    <div className="min-h-screen">
      {/* Desktop fixed sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 border-r bg-card/60 backdrop-blur md:block">
        <SidebarContent />
      </aside>

      {/* Mobile drawer */}
      {drawer && (
        <div className="fixed inset-0 z-50 md:hidden">
          <div className="absolute inset-0 animate-fade-in bg-slate-900/40 backdrop-blur-sm" onClick={() => setDrawer(false)} />
          <aside className="absolute inset-y-0 left-0 w-64 animate-slide-in-left border-r bg-card shadow-2xl">
            <button
              onClick={() => setDrawer(false)}
              className="absolute right-3 top-4 rounded-md p-1 text-muted-foreground hover:bg-accent"
              aria-label="关闭菜单"
            >
              <X className="h-5 w-5" />
            </button>
            <SidebarContent onNavigate={() => setDrawer(false)} />
          </aside>
        </div>
      )}

      <div className="flex min-h-screen flex-col md:pl-64">
        {me?.impersonator && (
          <div className="flex flex-wrap items-center justify-between gap-2 bg-amber-500/15 px-4 py-2 text-sm text-amber-700 dark:text-amber-400">
            <span>
              你正以 <b>{me.user.username}</b> 的身份操作（由 {me.impersonator.username} 代登）
            </span>
            <Button size="sm" variant="outline" onClick={stopImpersonation}>
              结束代登
            </Button>
          </div>
        )}
        <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b bg-background/80 px-4 backdrop-blur md:px-6">
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="icon" className="md:hidden" onClick={() => setDrawer(true)} aria-label="菜单">
              <Menu className="h-5 w-5" />
            </Button>
            <span className="text-sm text-muted-foreground">{me?.user.display_name || me?.user.username}</span>
          </div>
          <div className="flex items-center gap-1">
            <ThemeToggle />
            <Button variant="ghost" size="sm" onClick={logout}>
              <LogOut className="mr-1 h-4 w-4" /> 退出
            </Button>
          </div>
        </header>
        <main className="flex-1 px-4 py-6 md:px-8">
          <div className="mx-auto max-w-6xl">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
