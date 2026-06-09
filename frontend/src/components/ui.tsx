import * as React from "react";
import { createPortal } from "react-dom";
import { cva, type VariantProps } from "class-variance-authority";
import { Check, ChevronDown, HelpCircle, Copy, Eye, EyeOff } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { zhCN } from "date-fns/locale";
import { cn } from "@/lib/utils";

/* ----------------------------- Button ----------------------------- */

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 rounded-lg text-sm font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50 active:scale-[0.98]",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm",
        secondary: "bg-secondary text-secondary-foreground hover:bg-secondary/70",
        outline: "border border-input bg-card hover:bg-accent hover:text-accent-foreground",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        destructive: "bg-destructive text-destructive-foreground hover:bg-destructive/90 shadow-sm",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-4 py-2",
        sm: "h-8 px-3 text-xs",
        lg: "h-10 px-6",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  loading?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, loading, children, disabled, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(buttonVariants({ variant, size }), className)}
      disabled={disabled || loading}
      {...props}
    >
      {loading && <Spinner className="h-4 w-4" />}
      {children}
    </button>
  )
);
Button.displayName = "Button";

/* ----------------------------- Inputs ----------------------------- */

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "flex h-10 w-full rounded-lg border border-input bg-card px-3 py-1 text-sm shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50",
        className
      )}
      {...props}
    />
  )
);
Input.displayName = "Input";

/* A password input with a show/hide toggle. */
export const PasswordInput = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => {
    const [show, setShow] = React.useState(false);
    return (
      <div className="relative">
        <Input ref={ref} type={show ? "text" : "password"} className={cn("pr-10", className)} {...props} />
        <button
          type="button"
          tabIndex={-1}
          onClick={() => setShow((v) => !v)}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-1 text-muted-foreground transition-colors hover:text-foreground"
          aria-label={show ? "隐藏密码" : "显示密码"}
        >
          {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>
    );
  }
);
PasswordInput.displayName = "PasswordInput";

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        "flex min-h-[80px] w-full rounded-lg border border-input bg-card px-3 py-2 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        className
      )}
      {...props}
    />
  )
);
Textarea.displayName = "Textarea";

export function Label({ className, children, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return (
    <label className={cn("text-sm font-medium leading-none text-foreground", className)} {...props}>
      {children}
    </label>
  );
}

export function Field({
  label,
  children,
  hint,
  help,
}: {
  label: string;
  children: React.ReactNode;
  hint?: string;
  help?: string;
}) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-1.5">
        <Label>{label}</Label>
        {help && <Help text={help} />}
      </div>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

/* ----------------------------- Card ----------------------------- */

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-xl border bg-card text-card-foreground shadow-sm", className)} {...props} />;
}
export function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("flex flex-col space-y-1.5 p-6", className)} {...props} />;
}
export function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={cn("text-base font-semibold leading-none tracking-tight", className)} {...props} />;
}
export function CardDescription({ className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn("text-sm text-muted-foreground", className)} {...props} />;
}
export function CardContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-6 pt-0", className)} {...props} />;
}

/* ----------------------------- Badge ----------------------------- */

export function Badge({
  className,
  variant = "default",
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { variant?: "default" | "success" | "muted" | "destructive" | "warning" }) {
  const variants: Record<string, string> = {
    default: "bg-primary/10 text-primary",
    success: "bg-emerald-500/12 text-emerald-600 dark:text-emerald-400",
    warning: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
    muted: "bg-muted text-muted-foreground",
    destructive: "bg-destructive/12 text-destructive",
  };
  return (
    <span
      className={cn("inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium", variants[variant], className)}
      {...props}
    />
  );
}

export function Spinner({ className }: { className?: string }) {
  return (
    <svg className={cn("animate-spin text-current", className)} viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
    </svg>
  );
}

/* ----------------------------- Select (custom) ----------------------------- */

export interface SelectOption {
  value: string;
  label: string;
}

// useDropdownPosition tracks a trigger element and computes a fixed-position menu
// box (flipping above when there isn't room below). The menu is rendered in a
// body portal so it is never clipped by an ancestor's overflow (cards, tables).
type MenuBox = { left: number; width: number; top?: number; bottom?: number; maxH: number };

export function Select({
  value,
  onValueChange,
  options,
  placeholder = "请选择",
  disabled,
  className,
}: {
  value: string;
  onValueChange: (value: string) => void;
  options: SelectOption[];
  placeholder?: string;
  disabled?: boolean;
  className?: string;
}) {
  const [open, setOpen] = React.useState(false);
  const [active, setActive] = React.useState(-1);
  const triggerRef = React.useRef<HTMLButtonElement>(null);
  const menuRef = React.useRef<HTMLDivElement>(null);
  const selected = options.find((o) => o.value === value);
  const [box, setBox] = React.useState<MenuBox | null>(null);

  const reposition = React.useCallback(() => {
    const el = triggerRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const below = window.innerHeight - r.bottom;
    const above = r.top;
    const flip = below < 240 && above > below;
    setBox({
      left: r.left,
      width: r.width,
      top: flip ? undefined : r.bottom + 6,
      bottom: flip ? window.innerHeight - r.top + 6 : undefined,
      maxH: Math.min(256, (flip ? above : below) - 16),
    });
  }, []);

  React.useLayoutEffect(() => {
    if (!open) return;
    reposition();
    const onScroll = () => reposition();
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", reposition);
    return () => {
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", reposition);
    };
  }, [open, reposition]);

  React.useEffect(() => {
    if (!open) return;
    setActive(Math.max(0, options.findIndex((o) => o.value === value)));
    // Close on a click outside BOTH the trigger and the (portalled) menu.
    function onDoc(e: MouseEvent) {
      const t = e.target as Node;
      if (triggerRef.current?.contains(t) || menuRef.current?.contains(t)) return;
      setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open, options, value]);

  function choose(v: string) {
    onValueChange(v);
    setOpen(false);
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      setOpen(false);
      return;
    }
    if (!open) {
      if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        setOpen(true);
      }
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(options.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      if (active >= 0 && options[active]) choose(options[active].value);
    }
  }

  return (
    <div className={cn("relative", className)}>
      <button
        ref={triggerRef}
        type="button"
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        onKeyDown={onKeyDown}
        className="flex h-10 w-full items-center justify-between rounded-lg border border-input bg-card px-3 text-sm shadow-sm transition-colors hover:bg-accent/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
      >
        <span className={cn("truncate", !selected && "text-muted-foreground")}>
          {selected ? selected.label : placeholder}
        </span>
        <ChevronDown className={cn("h-4 w-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")} />
      </button>
      {open && box &&
        createPortal(
          <div
            ref={menuRef}
            role="listbox"
            style={{ position: "fixed", left: box.left, width: box.width, top: box.top, bottom: box.bottom, maxHeight: box.maxH }}
            className="z-[70] animate-pop-in overflow-auto rounded-lg border bg-card p-1 shadow-lg"
          >
            {options.length === 0 && <div className="px-3 py-2 text-sm text-muted-foreground">无选项</div>}
            {options.map((o, i) => (
              <button
                key={o.value}
                ref={i === active ? (el) => el?.scrollIntoView({ block: "nearest" }) : undefined}
                type="button"
                role="option"
                aria-selected={o.value === value}
                onMouseEnter={() => setActive(i)}
                onClick={() => choose(o.value)}
                className={cn(
                  "flex w-full items-center justify-between rounded-md px-3 py-2 text-left text-sm transition-colors",
                  i === active && "bg-accent",
                  o.value === value && "font-medium text-accent-foreground"
                )}
              >
                <span className="truncate">{o.label}</span>
                {o.value === value && <Check className="h-4 w-4 text-primary" />}
              </button>
            ))}
          </div>,
          document.body
        )}
    </div>
  );
}

/* ----------------------------- Checkbox (custom) ----------------------------- */

export function Checkbox({
  checked,
  onCheckedChange,
  disabled,
  className,
}: {
  checked: boolean;
  onCheckedChange?: (checked: boolean) => void;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onCheckedChange?.(!checked)}
      className={cn(
        "flex h-5 w-5 shrink-0 items-center justify-center rounded-md border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50",
        checked ? "border-primary bg-primary text-primary-foreground" : "border-input bg-card hover:border-primary/60",
        className
      )}
    >
      {checked && <Check className="h-3.5 w-3.5" strokeWidth={3} />}
    </button>
  );
}

/* ----------------------------- Avatar ----------------------------- */

const avatarSizes = {
  sm: "h-7 w-7 text-xs",
  md: "h-10 w-10 text-sm",
  lg: "h-16 w-16 text-xl",
};

// Avatar shows the user's uploaded image, or a brand-gradient circle with the
// first letter of their name as a fallback (also used while an image 404s).
export function Avatar({
  src,
  name,
  size = "md",
  className,
}: {
  src?: string | null;
  name?: string;
  size?: keyof typeof avatarSizes;
  className?: string;
}) {
  const [errored, setErrored] = React.useState(false);
  React.useEffect(() => setErrored(false), [src]);
  const initial = (name || "").trim().slice(0, 1).toUpperCase() || "?";
  const showImg = !!src && !errored;
  return (
    <span
      className={cn(
        "inline-flex shrink-0 select-none items-center justify-center overflow-hidden rounded-full brand-gradient font-semibold text-white",
        avatarSizes[size],
        className
      )}
    >
      {showImg ? (
        <img src={src!} alt={name || "头像"} className="h-full w-full object-cover" onError={() => setErrored(true)} />
      ) : (
        initial
      )}
    </span>
  );
}

/* ----------------------------- CheckRow (whole-row checkmark toggle) ----------------------------- */

// CheckRow is a full-width, single-click selectable row with a leading checkmark
// box. The ENTIRE row is the click target (fixes the old <label><Checkbox/>
// double-dispatch), and callers drive `checked` optimistically for instant feedback.
export function CheckRow({
  checked,
  onToggle,
  disabled,
  locked,
  lockedHint,
  className,
  children,
}: {
  checked: boolean;
  onToggle: (next: boolean) => void;
  disabled?: boolean;
  locked?: boolean;
  lockedHint?: string;
  className?: string;
  children: React.ReactNode;
}) {
  const inert = disabled || locked;
  return (
    <div className={cn("relative", className)}>
      <button
        type="button"
        role="checkbox"
        aria-checked={checked}
        disabled={inert}
        onClick={() => onToggle(!checked)}
        className={cn(
          "flex w-full items-center gap-2.5 rounded-lg border p-2.5 text-left text-sm transition-colors",
          locked && lockedHint && "pr-9",
          inert ? "cursor-not-allowed opacity-60" : "hover:bg-accent/40",
          checked && !inert ? "border-primary/50 bg-primary/5" : "border-input"
        )}
      >
        <span
          className={cn(
            "flex h-5 w-5 shrink-0 items-center justify-center rounded-md border transition-colors",
            checked ? "border-primary bg-primary text-primary-foreground" : "border-input bg-card"
          )}
        >
          {checked && <Check className="h-3.5 w-3.5" strokeWidth={3} />}
        </span>
        <span className="flex min-w-0 flex-1 items-center gap-2">{children}</span>
      </button>
      {locked && lockedHint && (
        <span className="absolute right-2.5 top-1/2 -translate-y-1/2">
          <Help text={lockedHint} />
        </span>
      )}
    </div>
  );
}

/* ----------------------------- Switch (custom) ----------------------------- */

export function Switch({
  checked,
  onCheckedChange,
  disabled,
}: {
  checked: boolean;
  onCheckedChange?: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onCheckedChange?.(!checked)}
      className={cn(
        "relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50",
        checked ? "bg-primary" : "bg-input"
      )}
    >
      <span
        className={cn(
          "inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform",
          checked ? "translate-x-5" : "translate-x-0.5"
        )}
      />
    </button>
  );
}

/* ----------------------------- Help tooltip ----------------------------- */

export function Help({ text, className }: { text: string; className?: string }) {
  const [open, setOpen] = React.useState(false);
  return (
    <span
      className={cn("relative inline-flex", className)}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="text-muted-foreground/70 transition-colors hover:text-primary"
        aria-label="帮助"
      >
        <HelpCircle className="h-3.5 w-3.5" />
      </button>
      {open && (
        <span className="absolute bottom-full left-1/2 z-50 mb-1.5 w-56 -translate-x-1/2 animate-fade-in rounded-lg border bg-card px-3 py-2 text-xs font-normal leading-relaxed text-muted-foreground shadow-lg">
          {text}
        </span>
      )}
    </span>
  );
}

/* ----------------------------- Tabs ----------------------------- */

export function Tabs({
  tabs,
  value,
  onValueChange,
  className,
}: {
  tabs: { value: string; label: React.ReactNode }[];
  value: string;
  onValueChange: (v: string) => void;
  className?: string;
}) {
  return (
    <div className={cn("inline-flex gap-1 rounded-xl bg-muted p-1", className)}>
      {tabs.map((t) => (
        <button
          key={t.value}
          type="button"
          onClick={() => onValueChange(t.value)}
          className={cn(
            "rounded-lg px-4 py-1.5 text-sm font-medium transition-all",
            value === t.value ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
          )}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

/* ----------------------------- Skeleton ----------------------------- */

export function Skeleton({ className }: { className?: string }) {
  return (
    <div className={cn("relative overflow-hidden rounded-md bg-muted", className)}>
      <div className="absolute inset-0 -translate-x-full animate-[shimmer_1.4s_infinite] bg-gradient-to-r from-transparent via-foreground/5 to-transparent" />
    </div>
  );
}

/* ----------------------------- CopyButton ----------------------------- */

export function CopyButton({ value, className, label }: { value: string; className?: string; label?: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard?.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground",
        className
      )}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-[hsl(var(--success))]" /> : <Copy className="h-3.5 w-3.5" />}
      {label ?? (copied ? "已复制" : "复制")}
    </button>
  );
}

/* ----------------------------- RelativeTime ----------------------------- */

export function RelativeTime({ value }: { value?: string | null }) {
  if (!value) return <span className="text-muted-foreground">—</span>;
  const d = new Date(value);
  let rel = "";
  try {
    rel = formatDistanceToNow(d, { addSuffix: true, locale: zhCN });
  } catch {
    rel = d.toLocaleString("zh-CN", { hour12: false });
  }
  return <span title={d.toLocaleString("zh-CN", { hour12: false })}>{rel}</span>;
}

/* ----------------------------- Layout helpers ----------------------------- */

export function PageHeader({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-dashed p-10 text-center text-sm text-muted-foreground">{message}</div>
  );
}
