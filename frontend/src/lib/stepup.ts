// Dependency-free step-up controller, so the axios layer (lib/api.ts) and the
// React host (components/StepUp.tsx) can share it without an import cycle.

type Pending = { resolve: () => void; reject: (e?: unknown) => void };

const listeners = new Set<(open: boolean) => void>();
let queue: Pending[] = [];
let isOpen = false;

function emit(v: boolean) {
  isOpen = v;
  listeners.forEach((l) => l(v));
}

// requestStepUp opens the step-up dialog and resolves once the user re-verifies.
export function requestStepUp(): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    queue.push({ resolve, reject });
    if (!isOpen) emit(true);
  });
}

export function resolveStepUp() {
  const q = queue;
  queue = [];
  emit(false);
  q.forEach((p) => p.resolve());
}

export function cancelStepUp() {
  const q = queue;
  queue = [];
  emit(false);
  q.forEach((p) => p.reject(new Error("step-up cancelled")));
}

export function subscribeStepUp(l: (open: boolean) => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function stepUpIsOpen() {
  return isOpen;
}
