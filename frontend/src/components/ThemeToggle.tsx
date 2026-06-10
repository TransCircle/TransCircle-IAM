import * as React from "react";
import { Moon, Sun } from "lucide-react";
import { Button } from "./ui";

// Theme state lives at module level so every ThemeToggle instance (header,
// login page, …) stays in sync. main.tsx applies the initial class before
// paint; unset preference follows the OS.
type Theme = "light" | "dark";

function readInitial(): Theme {
  const stored = localStorage.getItem("theme");
  if (stored === "dark" || stored === "light") return stored;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

let current: Theme = readInitial();
const listeners = new Set<() => void>();

function applyTheme(t: Theme) {
  current = t;
  localStorage.setItem("theme", t);
  document.documentElement.classList.toggle("dark", t === "dark");
  listeners.forEach((l) => l());
}

export function useTheme() {
  const dark = React.useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => current === "dark"
  );
  return { dark, toggle: () => applyTheme(dark ? "light" : "dark") };
}

export function ThemeToggle({ chrome }: { chrome?: boolean }) {
  const { dark, toggle } = useTheme();
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={toggle}
      title="切换主题"
      aria-label="切换主题"
      className={chrome ? "text-chrome-muted hover:bg-white/10 hover:text-chrome-foreground" : undefined}
    >
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </Button>
  );
}
