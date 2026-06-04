import * as React from "react";
import { CheckCircle2, XCircle, Info } from "lucide-react";
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

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = React.useState<ToastItem[]>([]);

  const toast = React.useCallback((message: string, kind: ToastKind = "info") => {
    const id = ++counter;
    setItems((prev) => [...prev, { id, message, kind }]);
    setTimeout(() => setItems((prev) => prev.filter((t) => t.id !== id)), 4000);
  }, []);

  return (
    <Ctx.Provider value={{ toast }}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(90vw,22rem)] flex-col gap-2">
        {items.map((t) => {
          const Icon = icons[t.kind];
          return (
            <div
              key={t.id}
              className={cn(
                "pointer-events-auto flex animate-slide-in-right items-start gap-3 rounded-lg border bg-card px-4 py-3 text-sm shadow-lg",
                t.kind === "success" && "border-emerald-500/40",
                t.kind === "error" && "border-destructive/40",
                t.kind === "info" && "border-border"
              )}
            >
              <Icon
                className={cn(
                  "mt-0.5 h-4 w-4 shrink-0",
                  t.kind === "success" && "text-emerald-500",
                  t.kind === "error" && "text-destructive",
                  t.kind === "info" && "text-primary"
                )}
              />
              <span className="leading-relaxed">{t.message}</span>
            </div>
          );
        })}
      </div>
    </Ctx.Provider>
  );
}
