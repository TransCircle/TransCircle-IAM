import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getCookie(name: string): string {
  const match = document.cookie.match(new RegExp("(?:^|; )" + name.replace(/([.$?*|{}()[\]\\/+^])/g, "\\$1") + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : "";
}

// hasControlChar reports whether s contains an ASCII control character. The
// WHATWG URL parser silently strips tab/newline/CR before parsing, so a value
// like "/<tab>/evil.com" would otherwise collapse to "//evil.com" — a
// protocol-relative redirect to a foreign origin.
function hasControlChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
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
  if (hasControlChar(v)) return null;
  if (!v.startsWith("/")) return null;
  // Resolve against our own origin and require it to stay same-origin. This
  // catches "//host", "/\\host", and any scheme that slipped through.
  try {
    const u = new URL(v, window.location.origin);
    if (u.origin !== window.location.origin) return null;
    return u.pathname + u.search + u.hash;
  } catch {
    return null;
  }
}

export function formatDate(value?: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString("zh-CN", { hour12: false });
}

// copyText writes to the clipboard and reports whether it actually worked.
// navigator.clipboard is undefined on non-HTTPS origins, so fall back to the
// legacy execCommand path; never report success for a silent failure.
export async function copyText(value: string): Promise<boolean> {
  if (navigator.clipboard) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch {
      /* fall through to legacy path */
    }
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = value;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}
