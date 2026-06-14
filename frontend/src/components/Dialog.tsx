import * as React from "react";
import { createPortal } from "react-dom";
import { X, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "./ui";

// A module-level stack of every currently-open dialog, shared across all
// instances. Stacked modals are real here — e.g. a step-up challenge (StepUp.tsx)
// opens over an edit form. The stack lets us (1) keep the body scroll-locked
// until the LAST dialog closes (a per-instance save/restore would unlock the
// body as soon as the first of two dialogs closed), and (2) route Escape only
// to the top-most dialog instead of closing every open one at once.
const dialogStack: symbol[] = [];
let savedBodyOverflow = "";

function pushDialog(id: symbol) {
  if (dialogStack.length === 0) {
    savedBodyOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
  }
  dialogStack.push(id);
}

function popDialog(id: symbol) {
  const i = dialogStack.lastIndexOf(id);
  if (i !== -1) dialogStack.splice(i, 1);
  if (dialogStack.length === 0) document.body.style.overflow = savedBodyOverflow;
}

function isTopDialog(id: symbol) {
  return dialogStack[dialogStack.length - 1] === id;
}

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
  // Stable per-instance token used to identify this dialog in the shared stack.
  const idRef = React.useRef<symbol>(undefined as unknown as symbol);
  if (idRef.current === undefined) idRef.current = Symbol("dialog");
  // Callers pass inline arrows for onClose, so its identity changes on every
  // parent render (i.e. every keystroke in a controlled form). Effects below
  // must NOT depend on it, or they re-run and steal focus mid-typing — read
  // the latest value through a ref instead.
  const onCloseRef = React.useRef(onClose);
  React.useEffect(() => {
    onCloseRef.current = onClose;
  });

  React.useEffect(() => {
    if (open) {
      setRender(true);
      const id = requestAnimationFrame(() => setShow(true));
      return () => cancelAnimationFrame(id);
    }
    setShow(false);
    // Matches the panel's `duration-200` exit transition so it isn't cut short.
    const t = setTimeout(() => setRender(false), 200);
    return () => clearTimeout(t);
  }, [open]);

  // Runs exactly once per open: focus the first focusable control so keyboard
  // users land in the dialog, and join the shared stack (which locks body
  // scroll while any dialog is open).
  React.useEffect(() => {
    if (!open) return;
    const id = idRef.current;
    const t = setTimeout(() => {
      // Skip disabled controls so focus lands in the first *editable* field
      // (e.g. edit dialogs lead with a disabled, read-only `key` input).
      const el = panelRef.current?.querySelector<HTMLElement>(
        'input:not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]):not([aria-label="关闭"])'
      );
      (el ?? panelRef.current)?.focus();
    }, 50);
    pushDialog(id);
    return () => {
      clearTimeout(t);
      popDialog(id);
    };
  }, [open]);

  React.useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      // Only the top-most dialog reacts, so Escape closes one layer at a time
      // instead of dismissing every stacked dialog at once.
      if (e.key === "Escape" && !lockClose && isTopDialog(idRef.current)) onCloseRef.current();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, lockClose]);

  if (!render) return null;
  // Portal to <body> so the dialog escapes any ancestor that establishes a
  // containing block for fixed-position descendants (e.g. the page-load
  // `.stagger` reveal animation touches `transform`). Without this, `fixed`
  // resolves relative to that ancestor and the modal + overlay render down the
  // page instead of over the viewport. Matches the dropdown/tooltip in ui.tsx.
  return createPortal(
    // Always a centered modal — anchoring to the bottom on narrow viewports
    // pushed dialogs off-screen at higher browser zoom levels. dvh keeps it
    // visible above the soft keyboard / URL bar.
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
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
          "bracket-frame relative z-10 max-h-[88vh] w-full max-w-lg overflow-y-auto border bg-card shadow-2xl shadow-black/25 outline-none transition-all duration-200 supports-[height:100dvh]:max-h-[calc(100dvh-2rem)] sm:supports-[height:100dvh]:max-h-[88dvh]",
          "rounded-lg p-5 sm:p-6",
          show ? "translate-y-0 scale-100 opacity-100" : "translate-y-3 scale-[0.98] opacity-0",
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
    </div>,
    document.body
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
