import * as React from "react";
import { X, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "./ui";

export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  className,
  onSubmit,
  submitting,
  lockClose,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  className?: string;
  // When provided, the body + footer are wrapped in a <form>, so pressing Enter
  // in any field submits (footer's primary button must be type="submit").
  onSubmit?: () => void;
  // While true, repeated form submits (double Enter) are ignored.
  submitting?: boolean;
  // One-time secrets: disable Escape / backdrop / X close so a stray click
  // can't discard the only copy — closing must go through an explicit button.
  lockClose?: boolean;
}) {
  const [render, setRender] = React.useState(open);
  const [show, setShow] = React.useState(false);
  const panelRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (open) {
      setRender(true);
      const id = requestAnimationFrame(() => setShow(true));
      return () => cancelAnimationFrame(id);
    }
    setShow(false);
    const t = setTimeout(() => setRender(false), 180);
    return () => clearTimeout(t);
  }, [open]);

  React.useEffect(() => {
    if (!open) return;
    // Focus the first focusable control inside the panel so keyboard users
    // land in the dialog (and Escape works without clicking first).
    const t = setTimeout(() => {
      const el = panelRef.current?.querySelector<HTMLElement>(
        'input, select, textarea, button:not([aria-label="关闭"])'
      );
      (el ?? panelRef.current)?.focus();
    }, 50);
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape" && !lockClose) onClose();
    }
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      clearTimeout(t);
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose, lockClose]);

  if (!render) return null;
  return (
    // Mobile: bottom sheet (full width, slides up, thumb-reachable buttons).
    // ≥sm: centered modal. dvh keeps it visible above the soft keyboard / URL bar.
    <div className="fixed inset-0 z-50 flex items-end justify-center sm:items-center sm:p-4">
      <div
        className={cn(
          "absolute inset-0 bg-[hsl(192_30%_6%/0.55)] transition-opacity duration-200",
          show ? "opacity-100" : "opacity-0"
        )}
        onClick={lockClose ? undefined : onClose}
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        className={cn(
          "bracket-frame relative z-10 max-h-[88vh] w-full max-w-lg overflow-y-auto border bg-card shadow-2xl shadow-black/25 outline-none transition-all duration-200 supports-[height:100dvh]:max-h-[calc(100dvh-2.5rem)] sm:supports-[height:100dvh]:max-h-[88dvh]",
          "rounded-t-lg border-b-0 p-5 pb-6 sm:rounded-lg sm:border-b sm:p-6",
          show ? "translate-y-0 scale-100 opacity-100" : "translate-y-6 opacity-0 sm:translate-y-3 sm:scale-[0.98]",
          className
        )}
      >
        {!lockClose && (
          <button
            onClick={onClose}
            className="absolute right-4 top-4 rounded-md p-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
            aria-label="关闭"
          >
            <X className="h-4 w-4" />
          </button>
        )}
        <h2 className="pr-6 text-base font-semibold tracking-tight">{title}</h2>
        {description && <p className="mt-1 text-[13px] text-muted-foreground">{description}</p>}
        {onSubmit ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!submitting) onSubmit();
            }}
          >
            <div className="mt-4">{children}</div>
            {footer && (
              <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end [&>button]:w-full sm:[&>button]:w-auto">
                {footer}
              </div>
            )}
          </form>
        ) : (
          <>
            <div className="mt-4">{children}</div>
            {footer && (
              <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end [&>button]:w-full sm:[&>button]:w-auto">
                {footer}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

/* A confirmation dialog for destructive / sensitive actions. */
export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel = "确认",
  destructive,
  loading,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  description?: string;
  confirmLabel?: string;
  destructive?: boolean;
  loading?: boolean;
}) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      description={description}
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            取消
          </Button>
          <Button variant={destructive ? "destructive" : "default"} onClick={onConfirm} loading={loading}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      {destructive && (
        <div className="flex items-start gap-3 rounded-md border border-destructive/30 bg-destructive/8 p-3 text-sm text-destructive">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>此操作不可撤销，请确认后继续。</span>
        </div>
      )}
    </Dialog>
  );
}
