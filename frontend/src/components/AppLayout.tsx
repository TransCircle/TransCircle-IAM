import * as React from "react";
import { NavLink, Outlet, useLocation, Link } from "react-router-dom";
import {
  LayoutDashboard, Users, UsersRound, AppWindow, KeyRound, ScrollText,
  Settings, ShieldCheck, UserCircle, LogOut, Boxes, Cpu, BookOpen, Menu, X, ChevronDown,
} from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { api, errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useToast } from "./Toast";
import { Avatar, Button } from "./ui";
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
    <div className="space-y-px">
      <p className="mono-label px-3 pb-1.5 pt-6 text-chrome-muted/80">{title}</p>
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              "group relative flex items-center gap-3 rounded-md px-3 py-2 text-[13.5px] font-medium transition-colors",
              isActive
                ? "bg-white/[0.07] text-chrome-foreground"
                : "text-chrome-muted hover:bg-white/[0.04] hover:text-chrome-foreground"
            )
          }
        >
          {({ isActive }) => (
            <>
              <span
                className={cn(
                  "absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-r-full bg-chrome-accent transition-opacity",
                  isActive ? "opacity-100" : "opacity-0"
                )}
              />
              <item.icon className={cn("h-[17px] w-[17px] transition-colors", isActive && "text-chrome-accent")} />
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
    <Link to="/account" className="flex items-center gap-2.5 border-b border-chrome-border px-4 py-[18px]">
      <div className="bracket-frame flex h-9 w-9 items-center justify-center rounded-md brand-gradient text-white [--tick:hsl(var(--chrome-accent)/0.9)] [--tick-len:8px]">
        <ShieldCheck className="h-5 w-5" />
      </div>
      <div className="leading-tight">
        <div className="font-mono text-[13px] font-semibold tracking-tight text-chrome-foreground">
          TRANS<span className="text-chrome-accent">CIRCLE</span>
        </div>
        <div className="mono-label mt-0.5 text-[10px] text-chrome-muted">identity · 统一身份</div>
      </div>
    </Link>
  );
}

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const { hasPermission } = useAuth();
  const visibleAdmin = adminNav.filter((i) => !i.perm || hasPermission(i.perm));
  return (
    <div className="bg-grid-chrome flex h-full flex-col bg-chrome">
      <Brand />
      <nav className="flex-1 overflow-y-auto px-3 pb-6">
        <NavSection title="account · 账户" items={accountNav} onNavigate={onNavigate} />
        <NavSection title="admin · 管理" items={visibleAdmin} onNavigate={onNavigate} />
        <NavSection title="docs · 文档" items={docsNav} onNavigate={onNavigate} />
      </nav>
      <div className="border-t border-chrome-border px-4 py-3">
        <p className="mono-label text-[10px] text-chrome-muted/60">transcircle iam</p>
      </div>
    </div>
  );
}

function UserMenu() {
  const { me, isSuperAdmin } = useAuth();
  const { toast } = useToast();
  const [open, setOpen] = React.useState(false);
  const [loggingOut, setLoggingOut] = React.useState(false);
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  async function logout() {
    if (loggingOut) return;
    setLoggingOut(true);
    try {
      await api.post("/api/v1/auth/logout");
      // Full reload so all client caches (react-query, in-memory state) reset.
      window.location.href = "/login";
    } catch (err) {
      setLoggingOut(false);
      toast(errorMessage(err), "error");
    }
  }

  const name = me?.user.display_name || me?.user.username || "";

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="flex items-center gap-2 rounded-md border bg-card py-1 pl-1 pr-2.5 text-sm transition-colors hover:border-primary/40"
      >
        <Avatar src={me?.user.avatar_url} name={name} size="sm" />
        <span className="hidden max-w-[10rem] truncate sm:block">{name}</span>
        <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
      </button>
      {open && (
        <div className="absolute right-0 z-50 mt-2 w-60 animate-pop-in overflow-hidden rounded-md border bg-popover p-1 shadow-xl shadow-black/10">
          <div className="px-3 py-2.5">
            <div className="truncate text-sm font-medium">{name}</div>
            <div className="mt-0.5 flex items-center gap-1.5 truncate font-mono text-xs text-muted-foreground">
              @{me?.user.username}
              {isSuperAdmin && (
                <span className="rounded-sm border border-warning/40 bg-warning/10 px-1 py-px text-[10px] text-warning">
                  超级管理员
                </span>
              )}
            </div>
          </div>
          <div className="my-1 h-px bg-border" />
          <Link to="/account" onClick={() => setOpen(false)} className="flex items-center gap-2 rounded-sm px-3 py-2 text-sm hover:bg-accent">
            <UserCircle className="h-4 w-4" /> 个人中心
          </Link>
          <Link to="/account/security" onClick={() => setOpen(false)} className="flex items-center gap-2 rounded-sm px-3 py-2 text-sm hover:bg-accent">
            <ShieldCheck className="h-4 w-4" /> 安全与多因素
          </Link>
          <div className="my-1 h-px bg-border" />
          <button
            onClick={logout}
            disabled={loggingOut}
            className="flex w-full items-center gap-2 rounded-sm px-3 py-2 text-sm text-destructive hover:bg-destructive/10 disabled:opacity-60"
          >
            <LogOut className="h-4 w-4" /> {loggingOut ? "正在退出…" : "退出登录"}
          </button>
        </div>
      )}
    </div>
  );
}

export function AppLayout() {
  const { me, refresh } = useAuth();
  const { toast } = useToast();
  const location = useLocation();
  const [drawer, setDrawer] = React.useState(false);

  React.useEffect(() => {
    setDrawer(false);
  }, [location.pathname]);

  async function stopImpersonation() {
    try {
      await api.post("/api/v1/admin/impersonation/stop");
      await refresh();
      window.location.href = "/account";
    } catch (err) {
      toast(errorMessage(err), "error");
    }
  }

  return (
    <div className="relative min-h-screen">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 border-r border-chrome-border md:block">
        <SidebarContent />
      </aside>

      {drawer && (
        <div className="fixed inset-0 z-50 md:hidden">
          <div className="absolute inset-0 animate-fade-in bg-black/50" onClick={() => setDrawer(false)} />
          <aside className="absolute inset-y-0 left-0 w-72 animate-slide-in-left shadow-2xl">
            <button
              onClick={() => setDrawer(false)}
              className="absolute right-3 top-4 z-10 rounded-md p-1 text-chrome-muted hover:bg-white/10 hover:text-chrome-foreground"
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
          <div
            className="flex flex-wrap items-center justify-between gap-2 border-b border-warning/30 bg-warning/10 px-4 py-2 text-sm
              [background-image:repeating-linear-gradient(135deg,transparent,transparent_14px,hsl(var(--warning)/0.08)_14px,hsl(var(--warning)/0.08)_28px)]"
          >
            <span className="text-warning">
              ⚠ 你正以 <b className="font-mono">{me.user.username}</b> 的身份操作（由 {me.impersonator.username} 代登）
            </span>
            <Button size="sm" variant="outline" onClick={stopImpersonation}>
              结束代登
            </Button>
          </div>
        )}
        <header className="glass sticky top-0 z-20 flex h-14 items-center justify-between border-b px-4 md:px-8">
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
