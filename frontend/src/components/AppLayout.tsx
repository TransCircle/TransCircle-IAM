import * as React from "react";
import { NavLink, Outlet, useNavigate, useLocation, Link } from "react-router-dom";
import {
  LayoutDashboard, Users, UsersRound, AppWindow, KeyRound, ScrollText,
  Settings, ShieldCheck, UserCircle, LogOut, Boxes, Cpu, BookOpen, Menu, X, ChevronDown,
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
      <p className="px-3 pb-1 pt-5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/60">{title}</p>
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              "group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
              isActive ? "bg-accent/70 text-accent-foreground" : "text-muted-foreground hover:bg-accent/40 hover:text-foreground"
            )
          }
        >
          {({ isActive }) => (
            <>
              <span
                className={cn(
                  "absolute left-0 top-1.5 h-[calc(100%-12px)] w-1 rounded-r-full brand-gradient transition-opacity",
                  isActive ? "opacity-100" : "opacity-0"
                )}
              />
              <item.icon className="h-[18px] w-[18px]" />
              {item.label}
            </>
          )}
        </NavLink>
      ))}
    </div>
  );
}

function Brand() {
  return (
    <Link to="/account" className="flex items-center gap-2.5 px-4 py-4">
      <div className="flex h-9 w-9 items-center justify-center rounded-xl brand-gradient text-white shadow-md shadow-primary/30">
        <ShieldCheck className="h-5 w-5" />
      </div>
      <div className="leading-tight">
        <div className="text-sm font-bold tracking-tight">
          Trans<span className="brand-text">Circle</span>
        </div>
        <div className="text-[11px] text-muted-foreground">统一身份</div>
      </div>
    </Link>
  );
}

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const { hasPermission } = useAuth();
  const visibleAdmin = adminNav.filter((i) => !i.perm || hasPermission(i.perm));
  return (
    <div className="flex h-full flex-col">
      <Brand />
      <nav className="flex-1 overflow-y-auto px-3 pb-6">
        <NavSection title="账户" items={accountNav} onNavigate={onNavigate} />
        <NavSection title="管理" items={visibleAdmin} onNavigate={onNavigate} />
        <NavSection title="文档" items={docsNav} onNavigate={onNavigate} />
      </nav>
    </div>
  );
}

function UserMenu() {
  const { me, isSuperAdmin } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  async function logout() {
    await api.post("/api/v1/auth/logout");
    navigate("/login");
    window.location.reload();
  }

  const name = me?.user.display_name || me?.user.username || "";
  const initial = name.slice(0, 1).toUpperCase();

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-full border bg-card py-1 pl-1 pr-2.5 text-sm transition-colors hover:bg-accent/50"
      >
        <span className="flex h-7 w-7 items-center justify-center rounded-full brand-gradient text-xs font-semibold text-white">
          {initial}
        </span>
        <span className="hidden max-w-[10rem] truncate sm:block">{name}</span>
        <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
      </button>
      {open && (
        <div className="absolute right-0 z-50 mt-2 w-56 animate-pop-in overflow-hidden rounded-xl border bg-card p-1 shadow-xl">
          <div className="px-3 py-2.5">
            <div className="truncate text-sm font-medium">{name}</div>
            <div className="truncate text-xs text-muted-foreground">
              @{me?.user.username}
              {isSuperAdmin && <span className="ml-1.5 rounded bg-accent px-1 py-0.5 text-[10px] text-accent-foreground">超级管理员</span>}
            </div>
          </div>
          <div className="my-1 h-px bg-border" />
          <Link to="/account" onClick={() => setOpen(false)} className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm hover:bg-accent">
            <UserCircle className="h-4 w-4" /> 个人中心
          </Link>
          <Link to="/account/security" onClick={() => setOpen(false)} className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm hover:bg-accent">
            <ShieldCheck className="h-4 w-4" /> 安全与多因素
          </Link>
          <div className="my-1 h-px bg-border" />
          <button onClick={logout} className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm text-destructive hover:bg-destructive/10">
            <LogOut className="h-4 w-4" /> 退出登录
          </button>
        </div>
      )}
    </div>
  );
}

export function AppLayout() {
  const { me, refresh } = useAuth();
  const location = useLocation();
  const [drawer, setDrawer] = React.useState(false);

  React.useEffect(() => {
    setDrawer(false);
  }, [location.pathname]);

  async function stopImpersonation() {
    await api.post("/api/v1/admin/impersonation/stop");
    refresh();
    window.location.href = "/account";
  }

  return (
    <div className="relative min-h-screen">
      {/* Ambient brand glow */}
      <div className="pointer-events-none fixed -left-40 -top-40 -z-10 h-96 w-96 rounded-full brand-gradient opacity-[0.12] blur-3xl" />

      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 border-r glass md:block">
        <SidebarContent />
      </aside>

      {drawer && (
        <div className="fixed inset-0 z-50 md:hidden">
          <div className="absolute inset-0 animate-fade-in bg-slate-900/40 backdrop-blur-sm" onClick={() => setDrawer(false)} />
          <aside className="absolute inset-y-0 left-0 w-72 animate-slide-in-left border-r bg-card shadow-2xl">
            <button onClick={() => setDrawer(false)} className="absolute right-3 top-4 rounded-md p-1 text-muted-foreground hover:bg-accent" aria-label="关闭菜单">
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
        <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b glass px-4 md:px-8">
          <Button variant="ghost" size="icon" className="md:hidden" onClick={() => setDrawer(true)} aria-label="菜单">
            <Menu className="h-5 w-5" />
          </Button>
          <div className="ml-auto flex items-center gap-1.5">
            <ThemeToggle />
            <UserMenu />
          </div>
        </header>
        <main className="flex-1 px-4 py-7 md:px-8">
          <div className="mx-auto max-w-5xl">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
