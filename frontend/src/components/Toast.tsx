import * as React from "react";
import { CheckCircle2, XCircle, Info, X } from "lucide-react";
import { cn } from "@/lib/utils";

type ToastKind = "success" | "error" | "info";
interface ToastItem {
  id: number;
  message: string;
  kind: ToastKind;
}

interface ToastCtx {
  toast: (message: string, kind?: ToastKind) => void;
}

function dismissLabel(): string {
  return document.documentElement.lang.toLowerCase().startsWith("zh-tw")
    ? "關閉通知"
    : "关闭通知";
}

const Ctx = React.createContext<ToastCtx>({ toast: () => {} });

export function useToast() {
  return React.useContext(Ctx);
}

let counter = 0;

const icons: Record<ToastKind, React.ComponentType<{ className?: string }>> = {
  success: CheckCircle2,
  error: XCircle,
  info: Info,
};

const accents: Record<ToastKind, string> = {
  success: "before:bg-success [&_svg]:text-success",
  error: "before:bg-destructive [&_svg]:text-destructive",
  info: "before:bg-info [&_svg]:text-info",
};

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = React.useState<ToastItem[]>([]);

  const toast = React.useCallback((message: string, kind: ToastKind = "info") => {
    const id = ++counter;
    setItems((prev) => [...prev, { id, message, kind }]);
    // Errors stay longer — users need time to read what went wrong.
    const ttl = kind === "error" ? 6500 : 4000;
    setTimeout(() => setItems((prev) => prev.filter((t) => t.id !== id)), ttl);
  }, []);

  return (
    <Ctx.Provider value={{ toast }}>
      {children}
      <div className="pointer-events-none fixed inset-x-4 bottom-4 z-[80] flex flex-col gap-2 sm:inset-x-auto sm:right-4 sm:w-[22rem]">
        {items.map((t) => {
          const Icon = icons[t.kind];
          return (
            <div
              key={t.id}
              role={t.kind === "error" ? "alert" : "status"}
              aria-live={t.kind === "error" ? "assertive" : "polite"}
              className={cn(
                "pointer-events-auto relative flex animate-slide-in-right items-start gap-3 overflow-hidden rounded-md border bg-popover py-3 pl-5 pr-2 text-sm shadow-xl shadow-black/10",
                "before:absolute before:inset-y-0 before:left-0 before:w-1",
                accents[t.kind]
              )}
            >
              <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <span className="min-w-0 flex-1 leading-relaxed">{t.message}</span>
              <button
                type="button"
                className="rounded-sm p-1 text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                aria-label={dismissLabel()}
                onClick={() => setItems((prev) => prev.filter((x) => x.id !== t.id))}
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
          );
        })}
      </div>
    </Ctx.Provider>
  );
}
