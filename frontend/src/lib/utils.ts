import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getCookie(name: string): string {
  const match = document.cookie.match(new RegExp("(?:^|; )" + name.replace(/([.$?*|{}()[\]\\/+^])/g, "\\$1") + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : "";
}

// safeReturnPath validates a post-login `return` target, allowing only
// same-origin absolute paths (defends against open-redirect / phishing).
export function safeReturnPath(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let v: string;
  try {
    v = decodeURIComponent(raw);
  } catch {
    return null;
  }
  // Must be an absolute same-origin path; reject //, /\, and any scheme.
  if (!v.startsWith("/") || v.startsWith("//") || v.startsWith("/\\")) return null;
  return v;
}

export function formatDate(value?: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  return d.toLocaleString("zh-CN", { hour12: false });
}
