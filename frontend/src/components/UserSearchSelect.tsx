import * as React from "react";
import { createPortal } from "react-dom";
import { Check, Search } from "lucide-react";
import { cn } from "@/lib/utils";
import { Avatar, Spinner } from "./ui";

export interface UserOption {
  id: string;
  label: string;
  sublabel?: string;
  avatar_url?: string | null;
}

// UserSearchSelect is a hand-written, theme-matching searchable multi-select. It
// debounces an async search, renders results in a body portal (never clipped),
// and shows a checkmark for already-selected ids. Clicking a row adds it (or
// removes it via onRemove when already selected); the menu stays open for batch
// selection. Keyboard: ArrowUp/Down move, Enter toggles, Escape closes.
export function UserSearchSelect({
  placeholder = "搜索用户名或显示名…",
  selectedIds,
  fetchOptions,
  onAdd,
  onRemove,
  disabled,
  emptyText = "无匹配用户",
}: {
  placeholder?: string;
  selectedIds: Set<string>;
  fetchOptions: (search: string) => Promise<UserOption[]>;
  onAdd: (opt: UserOption) => void;
  onRemove?: (opt: UserOption) => void;
  disabled?: boolean;
  emptyText?: string;
}) {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const [options, setOptions] = React.useState<UserOption[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [active, setActive] = React.useState(0);
  const wrapRef = React.useRef<HTMLDivElement>(null);
  const menuRef = React.useRef<HTMLDivElement>(null);
  const [box, setBox] = React.useState<{ left: number; top: number; width: number; maxH: number } | null>(null);
  // Keep the latest fetchOptions without making it an effect dependency (callers
  // pass an inline closure each render).
  const fetchRef = React.useRef(fetchOptions);
  React.useEffect(() => {
    fetchRef.current = fetchOptions;
  });
  // Monotonic request id so out-of-order responses are discarded.
  const seq = React.useRef(0);

  const reposition = React.useCallback(() => {
    const el = wrapRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    setBox({ left: r.left, top: r.bottom + 6, width: r.width, maxH: Math.min(288, window.innerHeight - r.bottom - 16) });
  }, []);

  React.useLayoutEffect(() => {
    if (!open) return;
    reposition();
    const onScroll = () => reposition();
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", reposition);
    function onDoc(e: MouseEvent) {
      const t = e.target as Node;
      if (wrapRef.current?.contains(t) || menuRef.current?.contains(t)) return;
      setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    return () => {
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", reposition);
      document.removeEventListener("mousedown", onDoc);
    };
  }, [open, reposition]);

  // Debounced async search whenever the query changes while open.
  React.useEffect(() => {
    if (!open) return;
    const my = ++seq.current;
    setLoading(true);
    const t = setTimeout(async () => {
      try {
        const res = await fetchRef.current(query);
        if (seq.current === my) {
          setOptions(res);
          setActive(0);
        }
      } catch {
        if (seq.current === my) setOptions([]);
      } finally {
        if (seq.current === my) setLoading(false);
      }
    }, 220);
    return () => clearTimeout(t);
  }, [query, open]);

  function toggle(opt: UserOption) {
    if (selectedIds.has(opt.id)) onRemove?.(opt);
    else onAdd(opt);
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      setOpen(false);
      return;
    }
    if (!open && (e.key === "ArrowDown" || e.key === "Enter")) {
      setOpen(true);
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(options.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (options[active]) toggle(options[active]);
    }
  }

  return (
    <div ref={wrapRef} className="relative">
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <input
          value={query}
          disabled={disabled}
          placeholder={placeholder}
          onFocus={() => setOpen(true)}
          onClick={() => setOpen(true)}
          onChange={(e) => {
            setQuery(e.target.value);
            setOpen(true);
          }}
          onKeyDown={onKeyDown}
          className="flex h-10 w-full rounded-lg border border-input bg-card pl-9 pr-3 text-sm shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
        />
      </div>
      {open && box &&
        createPortal(
          <div
            ref={menuRef}
            style={{ position: "fixed", left: box.left, top: box.top, width: box.width, maxHeight: box.maxH }}
            className="z-[70] animate-pop-in overflow-auto rounded-lg border bg-card p-1 shadow-lg"
          >
            {loading && (
              <div className="flex items-center justify-center gap-2 px-3 py-3 text-sm text-muted-foreground">
                <Spinner className="h-4 w-4" /> 搜索中…
              </div>
            )}
            {!loading && options.length === 0 && <div className="px-3 py-3 text-sm text-muted-foreground">{emptyText}</div>}
            {!loading &&
              options.map((o, i) => {
                const isSel = selectedIds.has(o.id);
                return (
                  <button
                    key={o.id}
                    ref={i === active ? (el) => el?.scrollIntoView({ block: "nearest" }) : undefined}
                    type="button"
                    onMouseEnter={() => setActive(i)}
                    onClick={() => toggle(o)}
                    className={cn(
                      "flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-left text-sm transition-colors",
                      i === active && "bg-accent"
                    )}
                  >
                    <Avatar src={o.avatar_url} name={o.label} size="sm" />
                    <span className="flex min-w-0 flex-1 flex-col">
                      <span className="truncate font-medium">{o.label}</span>
                      {o.sublabel && <span className="truncate text-xs text-muted-foreground">@{o.sublabel}</span>}
                    </span>
                    {isSel && <Check className="h-4 w-4 shrink-0 text-primary" />}
                  </button>
                );
              })}
          </div>,
          document.body
        )}
    </div>
  );
}
